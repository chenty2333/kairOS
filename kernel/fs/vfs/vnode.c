/**
 * kernel/fs/vfs/vnode.c - vnode helpers
 */

#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

ssize_t vfs_readlink_vnode(struct vnode *vn, char *buf, size_t bufsz,
                           bool require_full) {
    if (!vn || vn->type != VNODE_SYMLINK || !vn->ops || !vn->ops->read)
        return -EINVAL;
    size_t need = (size_t)vn->size;
    if (require_full && need >= bufsz)
        return -ENAMETOOLONG;
    size_t want = (need < bufsz) ? need : bufsz;
    if (!want)
        return 0;
    ssize_t ret = vn->ops->read(vn, buf, want, 0);
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
    if (vn) {
        mutex_lock(&vn->lock);
        vn->refcount++;
        mutex_unlock(&vn->lock);
    }
}

void vnode_put(struct vnode *vn) {
    if (!vn)
        return;
    struct vnode *parent = NULL;
    mutex_lock(&vn->lock);
    if (--vn->refcount == 0) {
        parent = vn->parent;
        vn->parent = NULL;
        vn->name[0] = '\0';
        mutex_unlock(&vn->lock);
        if (vn->ops->close)
            vn->ops->close(vn);
        if (parent)
            vnode_put(parent);
    } else
        mutex_unlock(&vn->lock);
}
