/**
 * kernel/fs/poll/epoll.c - epoll implementation
 */

#include <kairos/epoll_internal.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/pollwait.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/vfs.h>

struct epoll_item {
    int fd;
    uint32_t events;
    uint64_t data;
    uint32_t revents;
    struct epoll_instance *ep;
    struct file *file;
    struct vnode *vn;
    struct poll_watch watch;
    atomic_t refcount;
    bool ready;
    bool dispatching;
    bool deleted;
    struct list_head list;
    struct list_head ready_node;
    struct wait_queue detach_wait;
};

struct epoll_instance {
    struct mutex lock;
    struct list_head items;
    struct list_head ready;
    struct poll_wait_head waiters;
    bool closing;
};

static struct epoll_instance *epoll_from_fd(int epfd, struct file **filep) {
    struct file *file = fd_get(proc_current(), epfd);
    if (!file || !file->vnode || file->vnode->type != VNODE_EPOLL) {
        if (file) file_put(file);
        return NULL;
    }
    struct epoll_instance *ep = (struct epoll_instance *)file->vnode->fs_data;
    *filep = file;
    return ep;
}

static struct epoll_item *epoll_find(struct epoll_instance *ep, int fd) {
    struct epoll_item *item;
    list_for_each_entry(item, &ep->items, list) {
        if (item->fd == fd)
            return item;
    }
    return NULL;
}

static inline void epoll_item_get(struct epoll_item *item) {
    atomic_inc(&item->refcount);
}

static inline uint32_t epoll_item_refs(struct epoll_item *item) {
    return atomic_read(&item->refcount);
}

static void epoll_item_put(struct epoll_item *item) {
    if (!item)
        return;
    uint32_t old = atomic_fetch_sub(&item->refcount, 1);
    if (old == 2) {
        /* Last external ref dropped — wake detach waiter */
        wait_queue_wakeup_all(&item->detach_wait);
    }
    if (old == 1) {
        file_put(item->file);
        kfree(item);
    }
}

static void epoll_item_prepare(struct poll_watch *watch) {
    struct epoll_item *item = (struct epoll_item *)watch->data;
    epoll_item_get(item);
}

static void epoll_mark_ready(struct epoll_item *item, uint32_t revents) {
    struct epoll_instance *ep = item->ep;
    if (!ep)
        return;

    mutex_lock(&ep->lock);
    if (!ep->closing && !item->deleted) {
        item->revents = revents;
        if (!item->ready && !item->dispatching) {
            item->ready = true;
            list_add_tail(&item->ready_node, &ep->ready);
        }
    }
    mutex_unlock(&ep->lock);

    poll_wait_wake(&ep->waiters, revents);
}

static void epoll_item_notify(struct poll_watch *watch, uint32_t events) {
    struct epoll_item *item = (struct epoll_item *)watch->data;
    if (!item || item->deleted) {
        epoll_item_put(item);
        return;
    }
    uint32_t mask = events ? (events & item->events) : item->events;
    if (!mask) {
        epoll_item_put(item);
        return;
    }
    uint32_t revents = (uint32_t)vfs_poll(item->file, mask);
    if (revents)
        epoll_mark_ready(item, revents);
    epoll_item_put(item);
}

static void epoll_item_detach(struct epoll_item *item) {
    vfs_poll_unwatch(&item->watch);
    while (epoll_item_refs(item) > 1) {
        proc_sleep_on(&item->detach_wait, item, false);
    }
}

static int epoll_close(struct vnode *vn) {
    if (!vn)
        return 0;
    struct epoll_instance *ep = (struct epoll_instance *)vn->fs_data;
    if (ep) {
        LIST_HEAD(local);
        mutex_lock(&ep->lock);
        ep->closing = true;
        while (!list_empty(&ep->items)) {
            struct epoll_item *item =
                list_first_entry(&ep->items, struct epoll_item, list);
            list_del(&item->list);
            if (item->ready && !item->dispatching) {
                list_del(&item->ready_node);
            }
            item->ready = false;
            list_add_tail(&item->list, &local);
        }
        mutex_unlock(&ep->lock);

        struct epoll_item *item, *tmp;
        list_for_each_entry_safe(item, tmp, &local, list) {
            list_del(&item->list);
            item->deleted = true;
            item->ep = NULL;
            epoll_item_detach(item);
            epoll_item_put(item);
        }
        kfree(ep);
    }
    kfree(vn);
    return 0;
}

static struct file_ops epoll_ops = {
    .close = epoll_close,
};

int epoll_create_file(struct file **out) {
    if (!out)
        return -EINVAL;

    struct epoll_instance *ep = kzalloc(sizeof(*ep));
    struct vnode *vn = kzalloc(sizeof(*vn));
    struct file *file = vfs_file_alloc();
    if (!ep || !vn || !file) {
        kfree(ep);
        kfree(vn);
        if (file)
            vfs_file_free(file);
        return -ENOMEM;
    }

    mutex_init(&ep->lock, "epoll");
    INIT_LIST_HEAD(&ep->items);
    INIT_LIST_HEAD(&ep->ready);
    poll_wait_head_init(&ep->waiters);
    ep->closing = false;

    vn->type = VNODE_EPOLL;
    vn->ops = &epoll_ops;
    vn->fs_data = ep;
    atomic_init(&vn->refcount, 1);
    vn->parent = NULL;
    vn->name[0] = '\0';
    rwlock_init(&vn->lock, "epoll_vnode");
    poll_wait_head_init(&vn->pollers);

    file->vnode = vn;
    file->flags = O_RDONLY;

    *out = file;
    return 0;
}

int epoll_ctl_fd(int epfd, int op, int fd, const struct epoll_event *ev) {
    if (epfd == fd)
        return -EINVAL;

    struct file *ep_file = NULL;
    struct epoll_instance *ep = epoll_from_fd(epfd, &ep_file);
    if (!ep)
        return -EBADF;

    struct file *target = fd_get(proc_current(), fd);
    if (!target) {
        file_put(ep_file);
        return -EBADF;
    }
    if (!target->vnode || target->vnode->type == VNODE_EPOLL) {
        file_put(target);
        file_put(ep_file);
        return -EINVAL;
    }

    uint32_t events = ev ? ev->events : 0;
    uint64_t data = ev ? ev->data : 0;

    mutex_lock(&ep->lock);
    struct epoll_item *item = epoll_find(ep, fd);

    switch (op) {
    case EPOLL_CTL_ADD:
        if (item) {
            mutex_unlock(&ep->lock);
            file_put(target);
            file_put(ep_file);
            return -EEXIST;
        }
        item = kzalloc(sizeof(*item));
        if (!item) {
            mutex_unlock(&ep->lock);
            file_put(target);
            file_put(ep_file);
            return -ENOMEM;
        }
        item->fd = fd;
        item->events = events;
        item->data = data;
        item->revents = 0;
        item->ep = ep;
        item->file = target;
        item->vn = target->vnode;
        atomic_init(&item->refcount, 1);
        item->ready = false;
        item->dispatching = false;
        item->deleted = false;
        item->watch.head = NULL;
        item->watch.prepare = epoll_item_prepare;
        item->watch.notify = epoll_item_notify;
        item->watch.events = events;
        item->watch.data = item;
        INIT_LIST_HEAD(&item->list);
        INIT_LIST_HEAD(&item->ready_node);
        wait_queue_init(&item->detach_wait);
        list_add_tail(&item->list, &ep->items);
        break;
    case EPOLL_CTL_MOD:
        if (!item) {
            mutex_unlock(&ep->lock);
            file_put(target);
            file_put(ep_file);
            return -ENOENT;
        }
        item->events = events;
        item->data = data;
        __atomic_store_n(&item->watch.events, events, __ATOMIC_RELEASE);
        break;
    case EPOLL_CTL_DEL:
        if (!item) {
            mutex_unlock(&ep->lock);
            file_put(target);
            file_put(ep_file);
            return -ENOENT;
        }
        list_del(&item->list);
        if (item->ready && !item->dispatching) {
            list_del(&item->ready_node);
        }
        item->ready = false;
        item->deleted = true;
        break;
    default:
        mutex_unlock(&ep->lock);
        file_put(target);
        file_put(ep_file);
        return -EINVAL;
    }

    mutex_unlock(&ep->lock);

    if (op == EPOLL_CTL_ADD) {
        file_get(item->file);
        vfs_poll_watch(item->vn, &item->watch, item->events);
        uint32_t revents = (uint32_t)vfs_poll(item->file, item->events);
        if (revents)
            epoll_mark_ready(item, revents);
        file_put(target);
        file_put(ep_file);
        return 0;
    }

    if (op == EPOLL_CTL_MOD) {
        uint32_t revents = (uint32_t)vfs_poll(item->file, item->events);
        if (revents)
            epoll_mark_ready(item, revents);
        file_put(target);
        file_put(ep_file);
        return 0;
    }

    if (op == EPOLL_CTL_DEL) {
        epoll_item_detach(item);
        epoll_item_put(item);
    }
    file_put(target);
    file_put(ep_file);
    return 0;
}

ssize_t epoll_snapshot(int epfd, struct epoll_snapshot_item *items, size_t max) {
    if (!items || max == 0)
        return -EINVAL;

    struct file *ep_file = NULL;
    struct epoll_instance *ep = epoll_from_fd(epfd, &ep_file);
    if (!ep)
        return -EBADF;

    mutex_lock(&ep->lock);
    size_t count = 0;
    struct epoll_item *item;
    list_for_each_entry(item, &ep->items, list) {
        if (count >= max)
            break;
        items[count].fd = item->fd;
        items[count].events = item->events;
        items[count].data = item->data;
        count++;
    }
    mutex_unlock(&ep->lock);
    file_put(ep_file);
    return (ssize_t)count;
}

static int epoll_collect_ready(struct epoll_instance *ep,
                               struct epoll_event *events, size_t maxevents) {
    if (!ep || !events || maxevents == 0)
        return -EINVAL;

    LIST_HEAD(local_ready);
    mutex_lock(&ep->lock);
    size_t pulled = 0;
    while (!list_empty(&ep->ready) && pulled < maxevents) {
        struct epoll_item *item =
            list_first_entry(&ep->ready, struct epoll_item, ready_node);
        list_del(&item->ready_node);
        /* Keep ready=true while dispatching to block concurrent requeue. */
        item->dispatching = true;
        item->ready = true;
        epoll_item_get(item);
        list_add_tail(&item->ready_node, &local_ready);
        pulled++;
    }
    mutex_unlock(&ep->lock);

    int out = 0;
    struct epoll_item *item, *tmp;
    list_for_each_entry_safe(item, tmp, &local_ready, ready_node) {
        list_del(&item->ready_node);
        uint32_t revents = 0;
        if (!item->deleted && item->ep)
            revents = (uint32_t)vfs_poll(item->file, item->events);

        if (revents && out < (int)maxevents) {
            events[out].events = revents;
            events[out].data = item->data;
            out++;
        }

        bool can_requeue = (revents != 0);
        mutex_lock(&ep->lock);
        item->dispatching = false;
        if (ep->closing || item->deleted || !item->ep)
            can_requeue = false;
        if (can_requeue)
            list_add_tail(&item->ready_node, &ep->ready);
        item->ready = can_requeue;
        mutex_unlock(&ep->lock);
        epoll_item_put(item);
    }
    return out;
}

/*
 * Fallback rescan for vnodes that do not actively wake pollers yet.
 * We take references under the epoll lock, then poll outside it.
 */
static void epoll_rescan(struct epoll_instance *ep) {
    for (;;) {
        size_t count = 0;
        struct epoll_item *item;

        mutex_lock(&ep->lock);
        list_for_each_entry(item, &ep->items, list) {
            if (ep->closing || item->deleted || item->ready ||
                item->dispatching)
                continue;
            count++;
        }
        mutex_unlock(&ep->lock);

        if (count == 0)
            return;

        struct epoll_item **items = kmalloc(count * sizeof(*items));
        if (!items)
            return;

        bool overflow = false;
        size_t idx = 0;
        mutex_lock(&ep->lock);
        list_for_each_entry(item, &ep->items, list) {
            if (ep->closing || item->deleted || item->ready ||
                item->dispatching)
                continue;
            if (idx >= count) {
                overflow = true;
                break;
            }
            epoll_item_get(item);
            items[idx++] = item;
        }
        mutex_unlock(&ep->lock);

        if (overflow) {
            for (size_t i = 0; i < idx; i++)
                epoll_item_put(items[i]);
            kfree(items);
            continue;
        }

        for (size_t i = 0; i < idx; i++) {
            item = items[i];
            if (!item->deleted && item->ep) {
                uint32_t revents =
                    (uint32_t)vfs_poll(item->file, item->events);
                if (revents)
                    epoll_mark_ready(item, revents);
            }
            epoll_item_put(item);
        }

        kfree(items);
        return;
    }
}

int epoll_wait_events(int epfd, struct epoll_event *events, size_t maxevents,
                      int timeout_ms) {
    if (!events || maxevents == 0)
        return -EINVAL;

    struct file *ep_file = NULL;
    struct epoll_instance *ep = epoll_from_fd(epfd, &ep_file);
    if (!ep)
        return -EBADF;

    uint64_t start = arch_timer_get_ticks();
    uint64_t deadline = 0;
    if (timeout_ms > 0) {
        uint64_t delta = ((uint64_t)timeout_ms * CONFIG_HZ + 999) / 1000;
        if (!delta)
            delta = 1;
        deadline = start + delta;
    }

    int ret;
    while (1) {
        int ready = epoll_collect_ready(ep, events, maxevents);
        if (ready != 0 || timeout_ms == 0) {
            ret = ready;
            goto out;
        }

        /* Rescan once before blocking to cover non-event-driven vnodes. */
        epoll_rescan(ep);
        ready = epoll_collect_ready(ep, events, maxevents);
        if (ready) {
            ret = ready;
            goto out;
        }

        uint64_t now = arch_timer_get_ticks();
        if (deadline && now >= deadline) {
            ret = 0;
            goto out;
        }

        struct process *curr = proc_current();
        struct poll_waiter waiter = {0};
        INIT_LIST_HEAD(&waiter.entry.node);
        waiter.entry.proc = curr;
        poll_wait_add(&ep->waiters, &waiter);

        ready = epoll_collect_ready(ep, events, maxevents);
        if (ready) {
            poll_wait_remove(&waiter);
            ret = ready;
            goto out;
        }

        /* One more rescan after registering the waiter to close the race. */
        epoll_rescan(ep);
        ready = epoll_collect_ready(ep, events, maxevents);
        if (ready) {
            poll_wait_remove(&waiter);
            ret = ready;
            goto out;
        }

        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        if (deadline)
            poll_sleep_arm(&sleep, curr, deadline);
        proc_sleep_on(NULL, NULL, true);
        poll_sleep_cancel(&sleep);
        poll_wait_remove(&waiter);
    }
out:
    file_put(ep_file);
    return ret;
}
