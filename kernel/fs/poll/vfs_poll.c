/**
 * kernel/fs/poll/vfs_poll.c - VFS poll helpers
 */

#include <kairos/poll.h>
#include <kairos/pipe.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/vfs.h>

static uint64_t vfs_poll_wake_invalid_vnode_total;

int vfs_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;
    if (file->vnode->type == VNODE_PIPE)
        return pipe_poll_file(file, events);
    if (file->vnode->ops && file->vnode->ops->poll)
        return file->vnode->ops->poll(file, events);
    return events & (POLLIN | POLLOUT);
}

void vfs_poll_register(struct file *file, struct poll_waiter *waiter,
                       uint32_t events) {
    if (!file || !file->vnode || !waiter)
        return;
    if (file->vnode->type == VNODE_PIPE) {
        pipe_poll_register_file(file, waiter, events);
        return;
    }
    if (waiter->vn)
        vnode_put(waiter->vn);
    waiter->vn = file->vnode;
    vnode_get(file->vnode);
    (void)events;
    poll_wait_add(&file->vnode->pollers, waiter);
}

void vfs_poll_unregister(struct poll_waiter *waiter) {
    if (waiter && waiter->vn) {
        vnode_put(waiter->vn);
        waiter->vn = NULL;
    }
    poll_wait_remove(waiter);
}

void vfs_poll_watch(struct vnode *vn, struct poll_watch *watch,
                    uint32_t events) {
    if (!vn || !watch)
        return;
    if (vn->type == VNODE_PIPE) {
        pipe_poll_watch_vnode(vn, watch, events);
        return;
    }
    watch->events = events;
    poll_watch_add(&vn->pollers, watch);
}

void vfs_poll_unwatch(struct poll_watch *watch) {
    poll_watch_remove(watch);
}

void vfs_poll_wake(struct vnode *vn, uint32_t events) {
    if (!vn)
        return;
    if ((uintptr_t)vn <= USER_SPACE_END) {
        uint64_t seen = __atomic_add_fetch(&vfs_poll_wake_invalid_vnode_total, 1,
                                           __ATOMIC_RELAXED);
        if (seen <= 8) {
            void *caller = __builtin_return_address(0);
            pr_warn("vfs_poll_wake: skip invalid vnode=%p events=0x%x caller=%p\n",
                    (void *)vn, (unsigned int)events, caller);
        }
        return;
    }
    if (vn->type == VNODE_PIPE) {
        pipe_poll_wake_vnode(vn, events);
        return;
    }
    poll_wait_wake(&vn->pollers, events);
}
