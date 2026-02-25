/**
 * kernel/fs/vfs/mount.c - VFS mount and namespace operations
 */

#include <kairos/blkdev.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
#include <kairos/dentry.h>
#include <kairos/namei.h>

#include "vfs_internal.h"

LIST_HEAD(mount_list);
LIST_HEAD(fs_type_list);
spinlock_t vfs_lock = SPINLOCK_INIT;
struct mount *root_mount = NULL;
struct mutex mount_mutex;
struct mount_ns init_mnt_ns;
static uint32_t next_group_id = 1;

static struct mount_group *mount_group_alloc(void) {
    struct mount_group *grp = kzalloc(sizeof(*grp));
    if (!grp)
        return NULL;
    INIT_LIST_HEAD(&grp->members);
    grp->id = __atomic_add_fetch(&next_group_id, 1, __ATOMIC_RELAXED);
    return grp;
}

static void mount_group_add(struct mount_group *grp, struct mount *mnt) {
    if (!grp || !mnt)
        return;
    mnt->group = grp;
    list_add_tail(&mnt->group_node, &grp->members);
}

static void mount_group_remove(struct mount *mnt) {
    if (!mnt || !mnt->group)
        return;
    list_del(&mnt->group_node);
    struct mount_group *grp = mnt->group;
    mnt->group = NULL;
    if (list_empty(&grp->members))
        kfree(grp);
}

static void mount_set_private(struct mount *mnt) {
    if (!mnt)
        return;
    if (mnt->group)
        mount_group_remove(mnt);
    if (mnt->master) {
        list_del(&mnt->slave_node);
        mnt->master = NULL;
    }
    mnt->prop = MOUNT_PRIVATE;
}

static void mount_set_unbindable(struct mount *mnt) {
    if (!mnt)
        return;
    if (mnt->group)
        mount_group_remove(mnt);
    if (mnt->master) {
        list_del(&mnt->slave_node);
        mnt->master = NULL;
    }
    mnt->prop = MOUNT_UNBINDABLE;
}

static int mount_set_shared(struct mount *mnt) {
    if (!mnt)
        return -EINVAL;
    if (!mnt->group) {
        struct mount_group *grp = mount_group_alloc();
        if (!grp)
            return -ENOMEM;
        mount_group_add(grp, mnt);
    }
    if (mnt->master) {
        list_del(&mnt->slave_node);
        mnt->master = NULL;
    }
    mnt->prop = MOUNT_SHARED;
    return 0;
}

static int mount_set_slave(struct mount *mnt) {
    if (!mnt)
        return -EINVAL;
    if (mnt->group) {
        struct mount_group *grp = mnt->group;
        struct mount *master = NULL;
        list_for_each_entry(master, &grp->members, group_node) {
            if (master != mnt)
                break;
        }
        mount_group_remove(mnt);
        if (master && master != mnt) {
            if (mnt->master && !list_empty(&mnt->slave_node))
                list_del(&mnt->slave_node);
            mnt->master = master;
            if (list_empty(&mnt->slave_node))
                list_add_tail(&mnt->slave_node, &master->slaves);
        } else if (mnt->master) {
            if (!list_empty(&mnt->slave_node))
                list_del(&mnt->slave_node);
            mnt->master = NULL;
        }
    }
    mnt->prop = MOUNT_SLAVE;
    return 0;
}

static int mount_set_propagation_mode(struct mount *mnt, enum mount_prop prop) {
    if (!mnt)
        return -EINVAL;
    switch (prop) {
    case MOUNT_PRIVATE:
        mount_set_private(mnt);
        return 0;
    case MOUNT_SHARED:
        return mount_set_shared(mnt);
    case MOUNT_SLAVE:
        return mount_set_slave(mnt);
    case MOUNT_UNBINDABLE:
        mount_set_unbindable(mnt);
        return 0;
    default:
        return -EINVAL;
    }
}

static void mount_inherit_propagation(struct mount *mnt, struct mount *src) {
    if (!mnt || !src)
        return;
    mnt->prop = src->prop;
    if (src->prop == MOUNT_SHARED && src->group)
        mount_group_add(src->group, mnt);
    if (src->prop == MOUNT_SLAVE && src->master) {
        mnt->master = src->master;
        list_add_tail(&mnt->slave_node, &src->master->slaves);
    }
}

static int vfs_mount_bind_at(struct dentry *source, struct dentry *target,
                             uint32_t flags, bool propagate);

static int vfs_propagate_bind(struct dentry *source, struct dentry *target,
                              uint32_t flags) {
    if (!target || !target->mnt)
        return -EINVAL;
    struct mount *parent = target->mnt;
    if (!parent->group)
        return 0;

    char rel[CONFIG_PATH_MAX];
    int ret = vfs_build_relpath(parent->root_dentry, target, rel, sizeof(rel));
    if (ret < 0)
        return ret;

    struct mount *peer, *peer_next;
    list_for_each_entry_safe(peer, peer_next, &parent->group->members,
                             group_node) {
        struct mount *cur = peer;
        if (cur != parent) {
            struct path base;
            path_init(&base);
            base.dentry = cur->root_dentry;
            base.mnt = cur;
            struct path resolved;
            path_init(&resolved);
            ret = vfs_namei_locked(&base, rel, &resolved,
                                   NAMEI_FOLLOW | NAMEI_DIRECTORY);
            if (ret >= 0 && resolved.dentry && resolved.dentry->vnode) {
                vfs_mount_bind_at(source, resolved.dentry, flags, false);
            }
            if (resolved.dentry)
                dentry_put(resolved.dentry);
        }
        struct mount *slave, *slave_next;
        list_for_each_entry_safe(slave, slave_next, &cur->slaves, slave_node) {
            struct path base;
            path_init(&base);
            base.dentry = slave->root_dentry;
            base.mnt = slave;
            struct path resolved;
            path_init(&resolved);
            ret = vfs_namei_locked(&base, rel, &resolved,
                                   NAMEI_FOLLOW | NAMEI_DIRECTORY);
            if (ret >= 0 && resolved.dentry && resolved.dentry->vnode) {
                vfs_mount_bind_at(source, resolved.dentry, flags, false);
            }
            if (resolved.dentry)
                dentry_put(resolved.dentry);
        }
    }
    return 0;
}

static bool mount_is_descendant_of(const struct mount *child,
                                   const struct mount *ancestor) {
    if (!child || !ancestor || child == ancestor)
        return false;
    const struct mount *cur = child->parent;
    while (cur) {
        if (cur == ancestor)
            return true;
        cur = cur->parent;
    }
    return false;
}

static bool mount_has_child_locked(const struct mount *mnt,
                                   bool attached_only) {
    struct mount *child;
    list_for_each_entry(child, &mount_list, list) {
        if (child->parent != mnt)
            continue;
        if (attached_only && (child->mflags & MOUNT_F_DETACHED))
            continue;
        return true;
    }
    return false;
}

static bool mount_can_reap_detached_locked(struct mount *mnt) {
    if (!mnt || !(mnt->mflags & MOUNT_F_DETACHED))
        return false;
    if (mnt->mflags & MOUNT_F_REAP_FAILED)
        return false;
    if (mnt == init_mnt_ns.root || mnt == root_mount)
        return false;
    if (mount_has_child_locked(mnt, false))
        return false;
    uint32_t refs = atomic_read(&mnt->refcount);
    return refs <= 1;
}

static void mount_finalize_free(struct mount *mnt) {
    if (!mnt)
        return;

    if (mnt == init_mnt_ns.root) {
        vfs_mount_put(init_mnt_ns.root);
        init_mnt_ns.root = NULL;
        init_mnt_ns.root_dentry = NULL;
    }
    if (mnt->root_dentry) {
        dentry_drop(mnt->root_dentry);
        mnt->root_dentry = NULL;
    }
    if (mnt->mountpoint_dentry) {
        mnt->mountpoint_dentry->mounted = NULL;
        mnt->mountpoint_dentry->flags &= ~DENTRY_MOUNTPOINT;
        dentry_put(mnt->mountpoint_dentry);
        mnt->mountpoint_dentry = NULL;
    }
    if (mnt->root) {
        vnode_put(mnt->root);
        mnt->root = NULL;
    }
    if (mnt->group)
        mount_group_remove(mnt);
    if (mnt->master) {
        list_del(&mnt->slave_node);
        mnt->master = NULL;
    }
    if (mnt->dev && !(mnt->mflags & MOUNT_F_BIND))
        blkdev_put(mnt->dev);
    kfree(mnt->mountpoint);
    kfree(mnt);
}

static void mount_mark_detached_subtree_locked(struct mount *root) {
    if (!root)
        return;
    struct mount *mnt;
    list_for_each_entry(mnt, &mount_list, list) {
        if (mnt != root && !mount_is_descendant_of(mnt, root))
            continue;
        mnt->mflags |= MOUNT_F_DETACHED;
        mnt->mflags &= ~MOUNT_F_EXPIRE_MARK;
        mnt->mflags &= ~MOUNT_F_REAP_FAILED;
        if (mnt->mountpoint_dentry) {
            mnt->mountpoint_dentry->mounted = NULL;
            mnt->mountpoint_dentry->flags &= ~DENTRY_MOUNTPOINT;
            dentry_put(mnt->mountpoint_dentry);
            mnt->mountpoint_dentry = NULL;
        }
    }
}

static void mount_reap_detached_locked(void) {
    while (1) {
        struct mount *victim = NULL;
        struct mount *mnt;
        list_for_each_entry(mnt, &mount_list, list) {
            if (mount_can_reap_detached_locked(mnt)) {
                victim = mnt;
                break;
            }
        }
        if (!victim)
            return;

        spin_unlock(&vfs_lock);
        int unmount_ret = 0;
        if (victim->ops && victim->ops->unmount &&
            !(victim->mflags & MOUNT_F_BIND)) {
            unmount_ret = victim->ops->unmount(victim);
        }
        spin_lock(&vfs_lock);
        if (unmount_ret < 0) {
            victim->mflags |= MOUNT_F_REAP_FAILED;
            continue;
        }
        if (!mount_can_reap_detached_locked(victim))
            continue;

        list_del(&victim->list);
        if (victim == root_mount)
            root_mount = NULL;
        spin_unlock(&vfs_lock);
        mount_finalize_free(victim);
        spin_lock(&vfs_lock);
    }
}

struct mount *vfs_root_mount(void) {
    struct process *p = proc_current();
    if (p && p->mnt_ns && p->mnt_ns->root)
        return p->mnt_ns->root;
    return root_mount;
}

struct dentry *vfs_root_dentry(void) {
    struct process *p = proc_current();
    if (p && p->mnt_ns && p->mnt_ns->root_dentry)
        return p->mnt_ns->root_dentry;
    struct mount *mnt = vfs_root_mount();
    if (!mnt)
        return NULL;
    return mnt->root_dentry;
}

void vfs_mount_hold(struct mount *mnt) {
    if (!mnt)
        return;
    atomic_inc(&mnt->refcount);
}

void vfs_mount_put(struct mount *mnt) {
    if (!mnt)
        return;
    uint32_t old = atomic_fetch_sub(&mnt->refcount, 1);
    if (old == 0)
        panic("vfs_mount_put: refcount already zero");
    if (old == 1 && (mnt->mflags & MOUNT_F_DETACHED)) {
        vfs_mount_global_lock();
        spin_lock(&vfs_lock);
        mount_reap_detached_locked();
        spin_unlock(&vfs_lock);
        vfs_mount_global_unlock();
    }
}

void vfs_mount_global_lock(void) {
    mutex_lock(&mount_mutex);
}

void vfs_mount_global_unlock(void) {
    mutex_unlock(&mount_mutex);
}

int vfs_mount_set_shared(struct mount *mnt) {
    return mount_set_shared(mnt);
}

void vfs_mount_set_private(struct mount *mnt) {
    mount_set_private(mnt);
}

int vfs_mount_set_slave(struct mount *mnt) {
    return mount_set_slave(mnt);
}

void vfs_mount_set_unbindable(struct mount *mnt) {
    mount_set_unbindable(mnt);
}

int vfs_mount_set_propagation(struct mount *mnt, enum mount_prop prop,
                              bool recursive) {
    if (!mnt)
        return -EINVAL;
    if (!recursive)
        return mount_set_propagation_mode(mnt, prop);

    struct mount *iter;
    list_for_each_entry(iter, &mount_list, list) {
        if (iter != mnt && !mount_is_descendant_of(iter, mnt))
            continue;
        int ret = mount_set_propagation_mode(iter, prop);
        if (ret < 0)
            return ret;
    }
    return 0;
}

struct mount_ns *vfs_mount_ns_get(void) {
    return vfs_mount_ns_get_from(&init_mnt_ns);
}

struct mount_ns *vfs_mount_ns_get_from(struct mount_ns *ns) {
    if (!ns)
        return NULL;
    atomic_inc(&ns->refcount);
    return ns;
}

void vfs_mount_ns_put(struct mount_ns *ns) {
    if (!ns)
        return;
    uint32_t old = atomic_fetch_sub(&ns->refcount, 1);
    if (old == 0)
        panic("vfs_mount_ns_put: refcount underflow");
    if (ns == &init_mnt_ns)
        return;
    if (old == 1) {
        if (ns->root_dentry)
            dentry_put(ns->root_dentry);
        if (ns->root)
            vfs_mount_put(ns->root);
        kfree(ns);
    }
}

struct mount_ns *vfs_mount_ns_clone(struct mount_ns *ns) {
    if (!ns)
        return NULL;
    struct mount_ns *copy = kzalloc(sizeof(*copy));
    if (!copy)
        return NULL;
    copy->root = ns->root;
    copy->root_dentry = ns->root_dentry;
    if (copy->root)
        vfs_mount_hold(copy->root);
    if (copy->root_dentry)
        dentry_get(copy->root_dentry);
    atomic_init(&copy->refcount, 1);
    return copy;
}

int vfs_mount_ns_set_root(struct mount_ns *ns, struct dentry *root) {
    if (!ns || !root)
        return -EINVAL;
    if (!root->mnt)
        return -EINVAL;
    vfs_mount_hold(root->mnt);
    if (ns->root_dentry)
        dentry_put(ns->root_dentry);
    if (ns->root)
        vfs_mount_put(ns->root);
    ns->root_dentry = root;
    ns->root = root->mnt;
    dentry_get(ns->root_dentry);
    return 0;
}

static struct fs_type *find_fs_type(const char *name) {
    struct fs_type *fs;
    list_for_each_entry(fs, &fs_type_list, list) {
        if (strcmp(fs->name, name) == 0)
            return fs;
    }
    return NULL;
}

static struct mount *find_mount(const char *path) {
    struct mount *mnt, *best = NULL;
    size_t best_len = 0;
    vfs_mount_global_lock();
    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        if (mnt->mflags & MOUNT_F_DETACHED)
            continue;
        size_t len = strlen(mnt->mountpoint);
        if (strncmp(path, mnt->mountpoint, len) == 0 &&
            (path[len] == '\0' || path[len] == '/' || len == 1)) {
            if (len > best_len) {
                best = mnt;
                best_len = len;
            }
        }
    }
    spin_unlock(&vfs_lock);
    vfs_mount_global_unlock();
    return best;
}

struct mount *vfs_mount_for_path(const char *path) {
    return find_mount(path);
}

int vfs_mount(const char *src, const char *tgt, const char *fstype,
              uint32_t flags) {
    struct fs_type *fs;
    struct mount *mnt = NULL;
    struct blkdev *dev = NULL;
    int ret = -ENOMEM;
    bool mounted_ok = false;
    const char *src_use = src;
    if (src_use && strncmp(src_use, "/dev/", 5) == 0)
        src_use += 5;
    vfs_mount_global_lock();
    spin_lock(&vfs_lock);
    fs = find_fs_type(fstype);
    spin_unlock(&vfs_lock);
    if (!fs) {
        vfs_mount_global_unlock();
        return -ENODEV;
    }
    if (src_use && !(dev = blkdev_get(src_use))) {
        vfs_mount_global_unlock();
        return -ENODEV;
    }
    if (!(mnt = kzalloc(sizeof(*mnt))) ||
        !(mnt->mountpoint = kmalloc(strlen(tgt) + 1)))
        goto err;
    strcpy(mnt->mountpoint, tgt);
    mnt->ops = fs->ops;
    mnt->dev = dev;
    mnt->flags = flags;
    atomic_init(&mnt->refcount, 1);
    if ((ret = mnt->ops->mount(mnt)) < 0)
        goto err;
    mounted_ok = true;
    if (mnt->root) {
        mnt->root->parent = NULL;
        mnt->root->name[0] = '\0';
    }
    if (mnt->root && !mnt->root_dentry) {
        struct dentry *rootd = dentry_alloc(NULL, "");
        if (!rootd) {
            ret = -ENOMEM;
            goto err;
        }
        rootd->mnt = mnt;
        dentry_add(rootd, mnt->root);
        mnt->root_dentry = rootd;
    }
    mnt->parent = NULL;
    mnt->mountpoint_dentry = NULL;
    mnt->mflags = 0;
    mnt->group = NULL;
    INIT_LIST_HEAD(&mnt->group_node);
    mnt->master = NULL;
    INIT_LIST_HEAD(&mnt->slaves);
    INIT_LIST_HEAD(&mnt->slave_node);
    mnt->prop = MOUNT_PRIVATE;
    if (strcmp(tgt, "/") != 0) {
        struct path mp;
        path_init(&mp);
        ret = vfs_namei_locked(NULL, tgt, &mp,
                               NAMEI_FOLLOW | NAMEI_DIRECTORY);
        if (ret < 0)
            goto err;
        if (!mp.dentry || !mp.dentry->vnode ||
            mp.dentry->vnode->type != VNODE_DIR) {
            if (mp.dentry)
                dentry_put(mp.dentry);
            ret = -ENOTDIR;
            goto err;
        }
        if (mp.dentry->mounted) {
            dentry_put(mp.dentry);
            ret = -EBUSY;
            goto err;
        }
        mnt->parent = mp.mnt;
        mnt->mountpoint_dentry = mp.dentry;
        mp.dentry->flags |= DENTRY_MOUNTPOINT;
        mp.dentry->mounted = mnt;
    }
    spin_lock(&vfs_lock);
    list_add_tail(&mnt->list, &mount_list);
    if (strcmp(tgt, "/") == 0)
        root_mount = mnt;
    spin_unlock(&vfs_lock);
    if (strcmp(tgt, "/") == 0) {
        if (init_mnt_ns.root)
            vfs_mount_put(init_mnt_ns.root);
        init_mnt_ns.root = mnt;
        init_mnt_ns.root_dentry = mnt->root_dentry;
        vfs_mount_hold(mnt);
    }
    vfs_mount_global_unlock();
    return 0;
err:
    if (mnt && mnt->mountpoint_dentry) {
        mnt->mountpoint_dentry->mounted = NULL;
        mnt->mountpoint_dentry->flags &= ~DENTRY_MOUNTPOINT;
        dentry_put(mnt->mountpoint_dentry);
        mnt->mountpoint_dentry = NULL;
    }
    if (mnt && mnt->root_dentry) {
        dentry_drop(mnt->root_dentry);
        mnt->root_dentry = NULL;
    }
    if (mnt && mnt->root) {
        vnode_put(mnt->root);
        mnt->root = NULL;
    }
    if (mounted_ok && mnt && mnt->ops && mnt->ops->unmount)
        mnt->ops->unmount(mnt);
    vfs_mount_global_unlock();
    if (mnt) {
        kfree(mnt->mountpoint);
        kfree(mnt);
    }
    if (dev)
        blkdev_put(dev);
    return ret;
}

static int vfs_mount_bind_at(struct dentry *source, struct dentry *target,
                             uint32_t flags, bool propagate) {
    if (!source || !target || !source->vnode || !target->vnode)
        return -EINVAL;
    if (target->vnode->type != VNODE_DIR)
        return -ENOTDIR;
    if (target->mounted)
        return -EBUSY;

    struct mount *src_mnt = source->mnt;
    if (!src_mnt || !src_mnt->ops)
        return -EINVAL;
    if (src_mnt->prop == MOUNT_UNBINDABLE)
        return -EINVAL;

    struct mount *mnt = kzalloc(sizeof(*mnt));
    if (!mnt)
        return -ENOMEM;
    char target_path[CONFIG_PATH_MAX];
    int tplen = vfs_build_path_dentry(target, target_path,
                                      sizeof(target_path));
    if (tplen < 0) {
        mnt->mountpoint = kmalloc(1);
        if (!mnt->mountpoint) {
            kfree(mnt);
            return -ENOMEM;
        }
        mnt->mountpoint[0] = '\0';
    } else {
        mnt->mountpoint = kmalloc((size_t)tplen + 1);
        if (!mnt->mountpoint) {
            kfree(mnt);
            return -ENOMEM;
        }
        memcpy(mnt->mountpoint, target_path, (size_t)tplen + 1);
    }
    mnt->ops = src_mnt->ops;
    mnt->root = source->vnode;
    vnode_get(source->vnode);
    struct dentry *rootd = dentry_alloc(NULL, "");
    if (!rootd) {
        vnode_put(mnt->root);
        kfree(mnt->mountpoint);
        kfree(mnt);
        return -ENOMEM;
    }
    rootd->mnt = mnt;
    dentry_add(rootd, source->vnode);
    mnt->root_dentry = rootd;
    mnt->dev = src_mnt->dev;
    mnt->fs_data = src_mnt->fs_data;
    mnt->prop = MOUNT_PRIVATE;
    mnt->mflags = MOUNT_F_BIND;
    atomic_init(&mnt->refcount, 1);
    mnt->parent = target->mnt;
    mnt->mountpoint_dentry = target;
    dentry_get(target);
    INIT_LIST_HEAD(&mnt->list);
    INIT_LIST_HEAD(&mnt->group_node);
    INIT_LIST_HEAD(&mnt->slaves);
    INIT_LIST_HEAD(&mnt->slave_node);
    mount_inherit_propagation(mnt, target->mnt);

    target->flags |= DENTRY_MOUNTPOINT;
    target->mounted = mnt;

    spin_lock(&vfs_lock);
    list_add_tail(&mnt->list, &mount_list);
    spin_unlock(&vfs_lock);

    if (propagate)
        vfs_propagate_bind(source, target, flags);

    return 0;
}

int vfs_bind_mount(struct dentry *source, struct dentry *target,
                   uint32_t flags, bool propagate) {
    return vfs_mount_bind_at(source, target, flags, propagate);
}

int vfs_umount2(const char *tgt, uint32_t flags) {
    if (!tgt)
        return -EINVAL;
    uint32_t supported = VFS_UMOUNT_DETACH | VFS_UMOUNT_FORCE |
                         VFS_UMOUNT_EXPIRE;
    if (flags & ~supported)
        return -EINVAL;
    if ((flags & VFS_UMOUNT_DETACH) && (flags & VFS_UMOUNT_EXPIRE))
        return -EINVAL;
    if (flags & VFS_UMOUNT_FORCE) {
        if (flags & (VFS_UMOUNT_DETACH | VFS_UMOUNT_EXPIRE))
            return -EINVAL;
        return -EOPNOTSUPP;
    }

    bool expire = (flags & VFS_UMOUNT_EXPIRE) != 0;

    struct mount *mnt = NULL;
    bool found = false;
    vfs_mount_global_lock();
    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        if (mnt->mflags & MOUNT_F_DETACHED)
            continue;
        if (strcmp(mnt->mountpoint, tgt) == 0) {
            found = true;
            break;
        }
    }
    if (!found) {
        spin_unlock(&vfs_lock);
        vfs_mount_global_unlock();
        return -ENOENT;
    }

    if (flags & VFS_UMOUNT_DETACH) {
        if (mnt == init_mnt_ns.root || mnt == root_mount) {
            spin_unlock(&vfs_lock);
            vfs_mount_global_unlock();
            return -EBUSY;
        }
        mount_mark_detached_subtree_locked(mnt);
        mount_reap_detached_locked();
        spin_unlock(&vfs_lock);
        vfs_mount_global_unlock();
        return 0;
    }

    if (mount_has_child_locked(mnt, true)) {
        spin_unlock(&vfs_lock);
        vfs_mount_global_unlock();
        return -EBUSY;
    }
    uint32_t mount_refs = atomic_read(&mnt->refcount);
    uint32_t baseline_refs = 1;
    if (mnt == init_mnt_ns.root)
        baseline_refs++;
    if (mount_refs > baseline_refs) {
        spin_unlock(&vfs_lock);
        vfs_mount_global_unlock();
        return -EBUSY;
    }
    if (expire) {
        if (!(mnt->mflags & MOUNT_F_EXPIRE_MARK)) {
            mnt->mflags |= MOUNT_F_EXPIRE_MARK;
            spin_unlock(&vfs_lock);
            vfs_mount_global_unlock();
            return -EAGAIN;
        }
        mnt->mflags &= ~MOUNT_F_EXPIRE_MARK;
    } else {
        mnt->mflags &= ~MOUNT_F_EXPIRE_MARK;
    }
    spin_unlock(&vfs_lock);

    if (mnt->ops->unmount && !(mnt->mflags & MOUNT_F_BIND)) {
        int ret = mnt->ops->unmount(mnt);
        if (ret < 0) {
            vfs_mount_global_unlock();
            return ret;
        }
    }

    spin_lock(&vfs_lock);
    if (!list_empty(&mnt->list))
        list_del(&mnt->list);
    if (mnt == root_mount)
        root_mount = NULL;
    mount_reap_detached_locked();
    spin_unlock(&vfs_lock);

    mount_finalize_free(mnt);
    vfs_mount_global_unlock();
    return 0;
}

int vfs_umount(const char *tgt) {
    return vfs_umount2(tgt, 0);
}
