/**
 * kernel/fs/vfs/pipe.c - Pipe Implementation using Semaphores
 */

#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

#define PIPE_SIZE 4096

struct pipe {
    uint8_t *data;
    size_t head;
    size_t tail;
    struct semaphore sem_full;  /* Items available to read */
    struct semaphore sem_empty; /* Space available to write */
    struct mutex lock;
    bool closed;
};

static ssize_t pipe_read(struct vnode *vn, void *buf, size_t len, off_t off) {
    (void)off;
    struct pipe *p = vn->fs_data;
    size_t read = 0;

    for (size_t i = 0; i < len; i++) {
        /* Wait for data if pipe is empty */
        sem_wait(&p->sem_full);
        
        mutex_lock(&p->lock);
        if (p->closed && p->head == p->tail) {
            mutex_unlock(&p->lock);
            break;
        }
        
        ((uint8_t *)buf)[i] = p->data[p->tail];
        p->tail = (p->tail + 1) % PIPE_SIZE;
        read++;
        mutex_unlock(&p->lock);
        
        /* Signal that space is now available */
        sem_post(&p->sem_empty);
    }
    
    return read;
}

static ssize_t pipe_write(struct vnode *vn, const void *buf, size_t len, off_t off) {
    (void)off;
    struct pipe *p = vn->fs_data;
    size_t written = 0;

    for (size_t i = 0; i < len; i++) {
        /* Wait for space if pipe is full */
        sem_wait(&p->sem_empty);
        
        mutex_lock(&p->lock);
        if (p->closed) {
            mutex_unlock(&p->lock);
            break;
        }
        
        p->data[p->head] = ((const uint8_t *)buf)[i];
        p->head = (p->head + 1) % PIPE_SIZE;
        written++;
        mutex_unlock(&p->lock);
        
        /* Signal that data is now available */
        sem_post(&p->sem_full);
    }
    
    return written;
}

static int pipe_close(struct vnode *vn) {
    struct pipe *p = vn->fs_data;
    mutex_lock(&p->lock);
    /* For a real pipe, we'd need reference counting for readers/writers */
    /* This is a simplified version */
    p->closed = true;
    mutex_unlock(&p->lock);
    
    /* Wake up any waiters */
    sem_post(&p->sem_full);
    sem_post(&p->sem_empty);
    
    /* If it's the last reference, free the pipe */
    /* (This part depends on VFS refcounting logic) */
    return 0;
}

static struct file_ops pipe_ops = {
    .read = pipe_read,
    .write = pipe_write,
    .close = pipe_close,
};

int pipe_create(struct file **read_pipe, struct file **write_pipe) {
    struct pipe *p = kzalloc(sizeof(*p));
    if (!p) return -ENOMEM;
    
    p->data = kmalloc(PIPE_SIZE);
    if (!p->data) {
        kfree(p);
        return -ENOMEM;
    }
    
    sem_init(&p->sem_full, 0, "pipe_full");
    sem_init(&p->sem_empty, PIPE_SIZE, "pipe_empty");
    mutex_init(&p->lock, "pipe_lock");
    
    struct vnode *vn = kzalloc(sizeof(*vn));
    if (!vn) {
        kfree(p->data);
        kfree(p);
        return -ENOMEM;
    }
    
    vn->type = VNODE_PIPE;
    vn->ops = &pipe_ops;
    vn->fs_data = p;
    vn->refcount = 2; /* One for reader, one for writer */
    mutex_init(&vn->lock, "pipe_vnode");
    
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
