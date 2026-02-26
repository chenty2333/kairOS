/**
 * kernel/fs/vfs/vnode.c - vnode helpers
 */

#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
#include <kairos/arch.h>
#include <kairos/mm.h>

#define VNODE_KOBJ_STATE_UNINIT  0U
#define VNODE_KOBJ_STATE_INITING 1U
#define VNODE_KOBJ_STATE_READY   2U
#define VNODE_KOBJ_STATE_FAILED  3U

struct vnode_kobj_bridge {
    struct kobj obj;
};

static void vnode_kobj_release(struct kobj *obj) {
    if (!obj)
        return;
    kfree((struct vnode_kobj_bridge *)obj);
}

static const struct kobj_ops vnode_kobj_ops = {
    .release = vnode_kobj_release,
};

static inline bool vnode_kobj_is_ready(struct vnode *vn) {
    return vn && atomic_read(&vn->kobj_state) == VNODE_KOBJ_STATE_READY &&
           vn->kobj != NULL;
}

void vnode_kobj_init(struct vnode *vn) {
    if (!vn)
        return;

    while (1) {
        uint32_t state = atomic_read(&vn->kobj_state);
        if (state == VNODE_KOBJ_STATE_READY)
            return;

        if (state == VNODE_KOBJ_STATE_UNINIT) {
            uint32_t expected = VNODE_KOBJ_STATE_UNINIT;
            if (atomic_cmpxchg(&vn->kobj_state, &expected,
                               VNODE_KOBJ_STATE_INITING)) {
                struct vnode_kobj_bridge *bridge = kzalloc(sizeof(*bridge));
                if (!bridge) {
                    atomic_set(&vn->kobj_state, VNODE_KOBJ_STATE_FAILED);
                    return;
                }
                kobj_init(&bridge->obj, VFS_KOBJ_TYPE_VNODE, &vnode_kobj_ops);
                vn->kobj = &bridge->obj;
                uint32_t refs = atomic_read(&vn->refcount);
                for (uint32_t i = 1; i < refs; i++)
                    kobj_get(vn->kobj);
                atomic_set(&vn->kobj_state, VNODE_KOBJ_STATE_READY);
                return;
            }
            continue;
        }

        if (state == VNODE_KOBJ_STATE_INITING) {
            arch_cpu_relax();
            continue;
        }

        if (state == VNODE_KOBJ_STATE_FAILED)
            return;

        atomic_set(&vn->kobj_state, VNODE_KOBJ_STATE_UNINIT);
    }
}

struct kobj *vnode_kobj(struct vnode *vn) {
    vnode_kobj_init(vn);
    if (!vnode_kobj_is_ready(vn))
        return NULL;
    return vn->kobj;
}

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
    if (!vn)
        return;
    vnode_kobj_init(vn);
    atomic_inc(&vn->refcount);
    if (vnode_kobj_is_ready(vn))
        kobj_get(vn->kobj);
}

void vnode_put(struct vnode *vn) {
    if (!vn)
        return;
    vnode_kobj_init(vn);
    uint32_t cur = atomic_read(&vn->refcount);
    if (cur == 0)
        panic("vnode_put: refcount already zero on vnode ino=%lu",
              (unsigned long)vn->ino);
    uint32_t old = atomic_fetch_sub(&vn->refcount, 1);
    if (vnode_kobj_is_ready(vn))
        kobj_put(vn->kobj);
    if (old == 1) {
        struct vnode *parent = vn->parent;
        vn->parent = NULL;
        vn->name[0] = '\0';
        if (vn->ops && vn->ops->close)
            vn->ops->close(vn);
        /* Iterate instead of recursing to avoid stack overflow */
        while (parent) {
            struct vnode *next = NULL;
            vnode_kobj_init(parent);
            cur = atomic_read(&parent->refcount);
            if (cur == 0)
                panic("vnode_put: refcount already zero on vnode ino=%lu",
                      (unsigned long)parent->ino);
            old = atomic_fetch_sub(&parent->refcount, 1);
            if (vnode_kobj_is_ready(parent))
                kobj_put(parent->kobj);
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
