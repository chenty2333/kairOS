/**
 * kernel/fs/ipc/pipe.c - Pipe Implementation
 */

#include <kairos/mm.h>
#include <kairos/pollwait.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/poll.h>
#include <kairos/signal.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/string.h>
#include <kairos/pipe.h>
#include <kairos/vfs.h>

#define PIPE_SIZE 4096
#define PIPE_BUF 4096

struct pipe {
    uint8_t *data;
    size_t head;
    size_t tail;
    size_t count;
    int readers;
    int writers;
    struct poll_wait_source rd_src;
    struct poll_wait_source wr_src;
    struct poll_wait_head pollers;
    struct mutex lock;
};

static uint32_t pipe_poll_events_locked(struct pipe *p) {
    uint32_t revents = 0;
    if (p->count > 0 || p->writers == 0)
        revents |= POLLIN;
    if (p->readers == 0)
        revents |= POLLERR;
    else if (p->count < PIPE_SIZE)
        revents |= POLLOUT;
    if (p->writers == 0)
        revents |= POLLHUP;
    return revents;
}

static ssize_t pipe_read_internal(struct pipe *p, void *buf, size_t len, bool nonblock) {
    size_t read = 0;

    mutex_lock(&p->lock);
    while (read < len) {
        while (p->count == 0) {
            if (p->writers == 0) {
                mutex_unlock(&p->lock);
                return read;
            }
            if (nonblock) {
                mutex_unlock(&p->lock);
                return read ? (ssize_t)read : -EAGAIN;
            }
            int rc =
                poll_wait_source_block(&p->rd_src, 0, &p->rd_src, &p->lock);
            if (rc == -EINTR) {
                return read ? (ssize_t)read : -EINTR;
            }
        }

        size_t want = len - read;
        size_t can = (p->count < want) ? p->count : want;
        size_t tail_space = PIPE_SIZE - p->tail;
        size_t n1 = (can < tail_space) ? can : tail_space;
        memcpy((uint8_t *)buf + read, p->data + p->tail, n1);
        p->tail = (p->tail + n1) % PIPE_SIZE;
        p->count -= n1;
        read += n1;

        size_t n2 = can - n1;
        if (n2) {
            memcpy((uint8_t *)buf + read, p->data + p->tail, n2);
            p->tail = (p->tail + n2) % PIPE_SIZE;
            p->count -= n2;
            read += n2;
        }

        poll_wait_source_wake_one(&p->wr_src, 0);
        uint32_t revents = pipe_poll_events_locked(p);
        mutex_unlock(&p->lock);
        poll_wait_wake(&p->pollers, revents);
        mutex_lock(&p->lock);
        if (nonblock || read > 0)
            break;
    }
    mutex_unlock(&p->lock);
    return read;
}

static ssize_t pipe_write_internal(struct pipe *p, const void *buf, size_t len, bool nonblock) {
    size_t written = 0;
    struct process *curr = proc_current();

    mutex_lock(&p->lock);
    while (written < len) {
        if (p->readers == 0) {
            mutex_unlock(&p->lock);
            if (curr)
                signal_send(curr->pid, SIGPIPE);
            return written ? (ssize_t)written : -EPIPE;
        }

        size_t space = PIPE_SIZE - p->count;
        if (len <= PIPE_BUF) {
            while (space < len) {
                if (p->readers == 0) {
                    mutex_unlock(&p->lock);
                    if (curr)
                        signal_send(curr->pid, SIGPIPE);
                    return written ? (ssize_t)written : -EPIPE;
                }
                if (nonblock) {
                    mutex_unlock(&p->lock);
                    return written ? (ssize_t)written : -EAGAIN;
                }
                int rc =
                    poll_wait_source_block(&p->wr_src, 0, &p->wr_src, &p->lock);
                if (rc == -EINTR) {
                    mutex_unlock(&p->lock);
                    return written ? (ssize_t)written : -EINTR;
                }
                space = PIPE_SIZE - p->count;
            }
        } else if (space == 0) {
            if (nonblock) {
                mutex_unlock(&p->lock);
                return written ? (ssize_t)written : -EAGAIN;
            }
            int rc =
                poll_wait_source_block(&p->wr_src, 0, &p->wr_src, &p->lock);
            if (rc == -EINTR) {
                mutex_unlock(&p->lock);
                return written ? (ssize_t)written : -EINTR;
            }
            continue;
        }

        size_t want = len - written;
        size_t can = (PIPE_SIZE - p->count < want) ? (PIPE_SIZE - p->count) : want;
        size_t head_space = PIPE_SIZE - p->head;
        size_t n1 = (can < head_space) ? can : head_space;
        memcpy(p->data + p->head, (const uint8_t *)buf + written, n1);
        p->head = (p->head + n1) % PIPE_SIZE;
        p->count += n1;
        written += n1;

        size_t n2 = can - n1;
        if (n2) {
            memcpy(p->data + p->head, (const uint8_t *)buf + written, n2);
            p->head = (p->head + n2) % PIPE_SIZE;
            p->count += n2;
            written += n2;
        }

        poll_wait_source_wake_one(&p->rd_src, 0);
        uint32_t revents = pipe_poll_events_locked(p);
        mutex_unlock(&p->lock);
        poll_wait_wake(&p->pollers, revents);
        mutex_lock(&p->lock);
        if (len <= PIPE_BUF || nonblock)
            break;
    }
    mutex_unlock(&p->lock);
    return written;
}

static ssize_t pipe_read(struct vnode *vn, void *buf, size_t len, off_t off,
                         uint32_t flags) {
    (void)off;
    return pipe_read_internal(vn->fs_data, buf, len, (flags & O_NONBLOCK) != 0);
}

static ssize_t pipe_write(struct vnode *vn, const void *buf, size_t len, off_t off,
                          uint32_t flags) {
    (void)off;
    return pipe_write_internal(vn->fs_data, buf, len, (flags & O_NONBLOCK) != 0);
}

static int pipe_close(struct vnode *vn) {
    struct pipe *p = vn->fs_data;
    if (!p)
        return 0;
    kfree(p->data);
    kfree(p);
    kfree(vn);
    return 0;
}

static struct file_ops pipe_ops = {
    .read = pipe_read,
    .write = pipe_write,
    .close = pipe_close,
    .poll = NULL,
};

int pipe_create(struct file **read_pipe, struct file **write_pipe) {
    struct pipe *p = kzalloc(sizeof(*p));
    if (!p) return -ENOMEM;
    
    p->data = kmalloc(PIPE_SIZE);
    if (!p->data) {
        kfree(p);
        return -ENOMEM;
    }
    
    p->head = 0;
    p->tail = 0;
    p->count = 0;
    p->readers = 1;
    p->writers = 1;
    poll_wait_source_init(&p->rd_src, NULL);
    poll_wait_source_init(&p->wr_src, NULL);
    poll_wait_head_init(&p->pollers);
    mutex_init(&p->lock, "pipe_lock");
    
    struct vnode *vn = kzalloc(sizeof(*vn));
    if (!vn) {
        kfree(p->data);
        kfree(p);
        return -ENOMEM;
    }
    
    vn->type = VNODE_PIPE;
    vn->mode = S_IFIFO | 0600;
    vn->nlink = 1;
    vn->ops = &pipe_ops;
    vn->fs_data = p;
    atomic_init(&vn->refcount, 2); /* One for reader, one for writer */
    vn->kobj = NULL;
    atomic_init(&vn->kobj_state, 0);
    vn->parent = NULL;
    vn->name[0] = '\0';
    rwlock_init(&vn->lock, "pipe_vnode");
    poll_wait_head_init(&vn->pollers);
    
    *read_pipe = vfs_file_alloc();
    *write_pipe = vfs_file_alloc();
    
    if (!*read_pipe || !*write_pipe) {
        if (*read_pipe) vfs_file_free(*read_pipe);
        if (*write_pipe) vfs_file_free(*write_pipe);
        kfree(vn);
        kfree(p->data);
        kfree(p);
        return -ENOMEM;
    }
    
    (*read_pipe)->vnode = vn;
    (*read_pipe)->flags = O_RDONLY;
    
    (*write_pipe)->vnode = vn;
    (*write_pipe)->flags = O_WRONLY;
    
    return 0;
}

void pipe_close_end(struct file *file) {
    struct pipe *p = file->vnode->fs_data;
    uint32_t flags = file->flags;
    int readers, writers;
    bool dec_reader = false;
    bool dec_writer = false;
    if (!p)
        return;
    mutex_lock(&p->lock);
    if ((flags & O_RDWR) == O_RDWR) {
        dec_reader = true;
        dec_writer = true;
    } else if (flags & O_WRONLY) {
        dec_writer = true;
    } else {
        dec_reader = true;
    }
    if (dec_reader)
        p->readers--;
    if (dec_writer)
        p->writers--;
    readers = p->readers;
    writers = p->writers;
    mutex_unlock(&p->lock);

    if (dec_reader && writers == 0)
        poll_wait_source_wake_all(&p->rd_src, 0);
    if (dec_writer && readers == 0)
        poll_wait_source_wake_all(&p->wr_src, 0);
    poll_wait_wake(&p->pollers, POLLIN | POLLOUT | POLLHUP | POLLERR);
}

ssize_t pipe_read_file(struct file *file, void *buf, size_t len) {
    if (!file || !file->vnode)
        return -EINVAL;
    return pipe_read_internal(file->vnode->fs_data, buf, len,
                              (file->flags & O_NONBLOCK) != 0);
}

ssize_t pipe_write_file(struct file *file, const void *buf, size_t len) {
    if (!file || !file->vnode)
        return -EINVAL;
    return pipe_write_internal(file->vnode->fs_data, buf, len,
                               (file->flags & O_NONBLOCK) != 0);
}

int pipe_poll_file(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;
    struct pipe *p = file->vnode->fs_data;
    uint32_t revents;

    mutex_lock(&p->lock);
    revents = pipe_poll_events_locked(p) & events;
    mutex_unlock(&p->lock);

    return (int)revents;
}

void pipe_poll_register_file(struct file *file, struct poll_waiter *waiter,
                             uint32_t events) {
    (void)events;
    if (!file || !file->vnode || !waiter)
        return;
    struct pipe *p = file->vnode->fs_data;
    waiter->entry.proc = proc_current();
    poll_wait_add(&p->pollers, waiter);
}

void pipe_poll_watch_vnode(struct vnode *vn, struct poll_watch *watch,
                           uint32_t events) {
    if (!vn || vn->type != VNODE_PIPE || !watch)
        return;
    struct pipe *p = vn->fs_data;
    watch->events = events;
    poll_watch_add(&p->pollers, watch);
}

void pipe_poll_wake_vnode(struct vnode *vn, uint32_t events) {
    if (!vn || vn->type != VNODE_PIPE)
        return;
    struct pipe *p = vn->fs_data;
    if (!p)
        return;
    poll_wait_wake(&p->pollers, events);
}
