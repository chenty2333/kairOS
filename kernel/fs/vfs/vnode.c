/**
 * kernel/fs/vfs/vnode.c - vnode helpers
 */

#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

ssize_t vfs_readlink_vnode(struct vnode *vn, char *buf, size_t bufsz,
                           bool require_full) {
    if (!vn || vn->type != VNODE_SYMLINK || !vn->ops || !vn->ops->read)
        return -EINVAL;
    rwlock_read_lock(&vn->lock);
    size_t need = (size_t)vn->size;
    if (require_full && need >= bufsz) {
        rwlock_read_unlock(&vn->lock);
        return -ENAMETOOLONG;
    }
    size_t want = (need < bufsz) ? need : bufsz;
    if (!want) {
        rwlock_read_unlock(&vn->lock);
        return 0;
    }
    ssize_t ret = vn->ops->read(vn, buf, want, 0, 0);
    rwlock_read_unlock(&vn->lock);
    if (ret < 0)
        return ret;
    if (require_full && (size_t)ret != need)
        return -EIO;
    return ret;
}

void vnode_set_parent(struct vnode *vn, struct vnode *parent,
                      const char *name) {
    if (!vn)
        return;
    /* Caller must hold vn->lock if vnode is already visible. */
    if (vn->parent == parent) {
        if (name && name[0]) {
            if (strncmp(vn->name, name, sizeof(vn->name)) == 0)
                return;
        } else if (vn->name[0] == '\0') {
            return;
        }
    }

    if (vn->parent) {
        vnode_put(vn->parent);
        vn->parent = NULL;
    }

    if (parent) {
        vnode_get(parent);
        vn->parent = parent;
    }

    if (name && name[0]) {
        strncpy(vn->name, name, sizeof(vn->name) - 1);
        vn->name[sizeof(vn->name) - 1] = '\0';
    } else {
        vn->name[0] = '\0';
    }
}

void vnode_get(struct vnode *vn) {
    if (vn)
        atomic_inc(&vn->refcount);
}

void vnode_put(struct vnode *vn) {
    if (!vn)
        return;
    uint32_t cur = atomic_read(&vn->refcount);
    if (cur == 0)
        panic("vnode_put: refcount already zero on vnode ino=%lu",
              (unsigned long)vn->ino);
    uint32_t old = atomic_fetch_sub(&vn->refcount, 1);
    if (old == 1) {
        struct vnode *parent = vn->parent;
        vn->parent = NULL;
        vn->name[0] = '\0';
        if (vn->ops && vn->ops->close)
            vn->ops->close(vn);
        /* Iterate instead of recursing to avoid stack overflow */
        while (parent) {
            struct vnode *next = NULL;
            cur = atomic_read(&parent->refcount);
            if (cur == 0)
                panic("vnode_put: refcount already zero on vnode ino=%lu",
                      (unsigned long)parent->ino);
            old = atomic_fetch_sub(&parent->refcount, 1);
            if (old != 1)
                break;
            next = parent->parent;
            parent->parent = NULL;
            parent->name[0] = '\0';
            if (parent->ops && parent->ops->close)
                parent->ops->close(parent);
            parent = next;
        }
    }
}
