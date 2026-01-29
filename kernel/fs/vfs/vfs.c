/**
 * kernel/fs/vfs/vfs.c - Virtual File System Implementation
 */

#include <kairos/blkdev.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/process.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
#include <kairos/dentry.h>
#include <kairos/namei.h>

static LIST_HEAD(mount_list);
static LIST_HEAD(fs_type_list);
static spinlock_t vfs_lock = SPINLOCK_INIT;
static struct mount *root_mount = NULL;
static struct mutex mount_mutex;
static struct mount_ns init_mnt_ns;
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

static struct kmem_cache *vnode_cache;
static struct kmem_cache *file_cache;

int vfs_build_relpath(struct dentry *root, struct dentry *target,
                      char *out, size_t len) {
    if (!root || !target || !out || len == 0)
        return -EINVAL;
    if (root->mnt != target->mnt)
        return -EXDEV;
    if (root == target) {
        if (len < 2)
            return -ENAMETOOLONG;
        out[0] = '.';
        out[1] = '\0';
        return 0;
    }
    char tmp[CONFIG_PATH_MAX];
    size_t pos = sizeof(tmp) - 1;
    tmp[pos] = '\0';
    struct dentry *cur = target;
    while (cur && cur != root) {
        size_t nlen = strlen(cur->name);
        if (nlen + 1 > pos)
            return -ENAMETOOLONG;
        pos -= nlen;
        memcpy(&tmp[pos], cur->name, nlen);
        if (pos == 0)
            return -ENAMETOOLONG;
        tmp[--pos] = '/';
        cur = cur->parent;
    }
    if (cur != root)
        return -ENOENT;
    if (pos < sizeof(tmp) - 1 && tmp[pos] == '/')
        pos++;
    size_t plen = strlen(&tmp[pos]);
    if (plen + 1 > len)
        return -ENAMETOOLONG;
    memcpy(out, &tmp[pos], plen + 1);
    return 0;
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

static ssize_t vfs_readlink_target(struct vnode *vn, char *buf, size_t bufsz,
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

void vfs_init(void) {
    vnode_cache = kmem_cache_create("vnode", sizeof(struct vnode), NULL);
    file_cache = kmem_cache_create("file", sizeof(struct file), NULL);
    dentry_init();
    mutex_init(&mount_mutex, "mount");
    memset(&init_mnt_ns, 0, sizeof(init_mnt_ns));
    init_mnt_ns.refcount = 1;
    pr_info("VFS: initialized (caches ready)\n");
}

struct file *vfs_file_alloc(void) {
    struct file *file = kmem_cache_alloc(file_cache);
    if (!file)
        return NULL;
    memset(file, 0, sizeof(*file));
    file->refcount = 1;
    mutex_init(&file->lock, "file");
    return file;
}

void vfs_file_free(struct file *file) {
    if (!file)
        return;
    kmem_cache_free(file_cache, file);
}

void vfs_dump_mounts(void) {
    struct mount *mnt;
    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        pr_info("VFS mount: %s\n", mnt->mountpoint);
    }
    spin_unlock(&vfs_lock);
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
    __atomic_add_fetch(&mnt->refcount, 1, __ATOMIC_RELAXED);
}

void vfs_mount_put(struct mount *mnt) {
    if (!mnt)
        return;
    __atomic_sub_fetch(&mnt->refcount, 1, __ATOMIC_RELAXED);
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

struct mount_ns *vfs_mount_ns_get(void) {
    return vfs_mount_ns_get_from(&init_mnt_ns);
}

struct mount_ns *vfs_mount_ns_get_from(struct mount_ns *ns) {
    if (!ns)
        return NULL;
    __atomic_add_fetch(&ns->refcount, 1, __ATOMIC_RELAXED);
    return ns;
}

void vfs_mount_ns_put(struct mount_ns *ns) {
    if (!ns)
        return;
    if (ns == &init_mnt_ns) {
        __atomic_sub_fetch(&ns->refcount, 1, __ATOMIC_RELAXED);
        return;
    }
    if (__atomic_sub_fetch(&ns->refcount, 1, __ATOMIC_RELAXED) == 0) {
        if (ns->root_dentry)
            dentry_put(ns->root_dentry);
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
    if (copy->root_dentry)
        dentry_get(copy->root_dentry);
    copy->refcount = 1;
    return copy;
}

int vfs_mount_ns_set_root(struct mount_ns *ns, struct dentry *root) {
    if (!ns || !root)
        return -EINVAL;
    if (ns->root_dentry)
        dentry_put(ns->root_dentry);
    ns->root_dentry = root;
    ns->root = root->mnt;
    dentry_get(ns->root_dentry);
    return 0;
}

int vfs_register_fs(struct fs_type *fs) {
    if (!fs || !fs->name || !fs->ops)
        return -EINVAL;
    spin_lock(&vfs_lock);
    list_add_tail(&fs->list, &fs_type_list);
    spin_unlock(&vfs_lock);
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
    vfs_mount_global_lock();
    spin_lock(&vfs_lock);
    fs = find_fs_type(fstype);
    spin_unlock(&vfs_lock);
    if (!fs) {
        vfs_mount_global_unlock();
        return -ENODEV;
    }
    if (src && !(dev = blkdev_get(src))) {
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
    mnt->refcount = 1;
    if ((ret = mnt->ops->mount(mnt)) < 0)
        goto err;
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
        init_mnt_ns.root = mnt;
        init_mnt_ns.root_dentry = mnt->root_dentry;
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
    mnt->refcount = 1;
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

int vfs_umount(const char *tgt) {
    struct mount *mnt;
    vfs_mount_global_lock();
    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        if (strcmp(mnt->mountpoint, tgt) == 0) {
            list_del(&mnt->list);
            if (mnt == root_mount)
                root_mount = NULL;
            spin_unlock(&vfs_lock);
            if (mnt == init_mnt_ns.root) {
                init_mnt_ns.root = NULL;
                init_mnt_ns.root_dentry = NULL;
            }
            if (mnt->ops->unmount && !(mnt->mflags & MOUNT_F_BIND))
                mnt->ops->unmount(mnt);
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
            vfs_mount_global_unlock();
            return 0;
        }
    }
    spin_unlock(&vfs_lock);
    vfs_mount_global_unlock();
    return -ENOENT;
}

int vfs_build_path(struct vnode *vn, char *out, size_t len) {
    if (!vn || !out || len == 0)
        return -EINVAL;
    struct mount *mnt = vn->mount;
    if (!mnt || !mnt->mountpoint)
        return -EINVAL;

    char tmp[CONFIG_PATH_MAX];
    size_t pos = sizeof(tmp) - 1;
    tmp[pos] = '\0';

    struct vnode *cur = vn;
    while (cur && cur != mnt->root) {
        if (!cur->name[0])
            return -ENOENT;
        size_t nlen = strlen(cur->name);
        if (nlen + 1 > pos)
            return -ENAMETOOLONG;
        pos -= nlen;
        memcpy(&tmp[pos], cur->name, nlen);
        if (pos == 0)
            return -ENAMETOOLONG;
        tmp[--pos] = '/';
        cur = cur->parent;
    }
    if (!cur)
        return -ENOENT;
    if (pos == sizeof(tmp) - 1) {
        if (pos == 0)
            return -ENAMETOOLONG;
        tmp[--pos] = '/';
    }

    const char *mountpoint = mnt->mountpoint;
    if (strcmp(mountpoint, "/") == 0) {
        size_t plen = strlen(&tmp[pos]);
        if (plen + 1 > len)
            return -ERANGE;
        memcpy(out, &tmp[pos], plen + 1);
        return (int)plen;
    }

    const char *rel = &tmp[pos];
    if (strcmp(rel, "/") == 0) {
        size_t mlen = strlen(mountpoint);
        if (mlen + 1 > len)
            return -ERANGE;
        memcpy(out, mountpoint, mlen + 1);
        return (int)mlen;
    }

    size_t mlen = strlen(mountpoint);
    size_t rlen = strlen(rel);
    if (mlen + rlen + 1 > len)
        return -ERANGE;
    memcpy(out, mountpoint, mlen);
    memcpy(out + mlen, rel, rlen + 1);
    return (int)(mlen + rlen);
}

int vfs_build_path_dentry(struct dentry *d, char *out, size_t len) {
    if (!d || !out || len == 0)
        return -EINVAL;
    if (!d->mnt || !d->mnt->root_dentry)
        return -EINVAL;

    char tmp[CONFIG_PATH_MAX];
    size_t pos = sizeof(tmp) - 1;
    tmp[pos] = '\0';

    struct dentry *cur = d;
    struct mount *mnt = d->mnt;
    struct dentry *ns_root = vfs_root_dentry();
    while (cur) {
        if (ns_root && cur == ns_root) {
            if (pos == sizeof(tmp) - 1) {
                if (pos == 0)
                    return -ENAMETOOLONG;
                tmp[--pos] = '/';
            }
            break;
        }
        if (cur == mnt->root_dentry) {
            if (!mnt->parent || !mnt->mountpoint_dentry) {
                if (pos == sizeof(tmp) - 1) {
                    if (pos == 0)
                        return -ENAMETOOLONG;
                    tmp[--pos] = '/';
                }
                break;
            }
            cur = mnt->mountpoint_dentry;
            mnt = mnt->parent;
            continue;
        }
        if (!cur->name[0])
            return -ENOENT;
        size_t nlen = strlen(cur->name);
        if (nlen + 1 > pos)
            return -ENAMETOOLONG;
        pos -= nlen;
        memcpy(&tmp[pos], cur->name, nlen);
        if (pos == 0)
            return -ENAMETOOLONG;
        tmp[--pos] = '/';
        cur = cur->parent;
    }
    if (!cur)
        return -ENOENT;

    size_t plen = strlen(&tmp[pos]);
    if (plen + 1 > len)
        return -ERANGE;
    memcpy(out, &tmp[pos], plen + 1);
    return (int)plen;
}

int vfs_open_at_path(const struct path *base, const char *path, int flags,
                     mode_t mode, struct file **fp) {
    if (!path || !fp)
        return -EINVAL;
    uint32_t allowed = O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND |
                       O_NONBLOCK | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC |
                       O_LARGEFILE;
    if (flags & ~allowed)
        return -EINVAL;
    int accmode = flags & O_ACCMODE;
    if (accmode != O_RDONLY && accmode != O_WRONLY && accmode != O_RDWR)
        return -EINVAL;
    if ((flags & O_DIRECTORY) && (flags & O_CREAT))
        return -EINVAL;
    if ((flags & O_TRUNC) && accmode == O_RDONLY)
        return -EACCES;

    int nflags = NAMEI_FOLLOW;
    if (flags & O_DIRECTORY)
        nflags |= NAMEI_DIRECTORY;
    if (flags & O_CREAT)
        nflags |= NAMEI_CREATE;
    if (flags & O_EXCL)
        nflags |= NAMEI_EXCL;
    if (flags & O_NOFOLLOW) {
        nflags |= NAMEI_NOFOLLOW;
        nflags &= ~NAMEI_FOLLOW;
    }

    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei_at(base, path, &resolved, nflags);
    if (ret < 0)
        return ret;
    if (!resolved.dentry)
        return -ENOENT;

    struct vnode *vn = NULL;
    if (resolved.dentry->flags & DENTRY_NEGATIVE) {
        if (!(flags & O_CREAT)) {
            dentry_put(resolved.dentry);
            return -ENOENT;
        }
        if (!resolved.dentry->parent ||
            !resolved.dentry->parent->vnode ||
            !resolved.mnt || !resolved.mnt->ops ||
            !resolved.mnt->ops->create) {
            dentry_put(resolved.dentry);
            return -EOPNOTSUPP;
        }
        ret = resolved.mnt->ops->create(resolved.dentry->parent->vnode,
                                        resolved.dentry->name, mode);
        if (ret < 0) {
            dentry_put(resolved.dentry);
            return ret;
        }
        vn = resolved.mnt->ops->lookup(resolved.dentry->parent->vnode,
                                       resolved.dentry->name);
        if (!vn) {
            dentry_put(resolved.dentry);
            return -EIO;
        }
        dentry_add(resolved.dentry, vn);
        vnode_put(vn);
    } else {
        if ((flags & O_EXCL) && (flags & O_CREAT)) {
            dentry_put(resolved.dentry);
            return -EEXIST;
        }
        vn = resolved.dentry->vnode;
        if (!vn) {
            dentry_put(resolved.dentry);
            return -ENOENT;
        }
        if ((flags & O_NOFOLLOW) && vn->type == VNODE_SYMLINK) {
            dentry_put(resolved.dentry);
            return -ELOOP;
        }
        vnode_get(vn);
    }

    struct file *file = vfs_file_alloc();
    if (!file) {
        vnode_put(vn);
        dentry_put(resolved.dentry);
        return -ENOMEM;
    }
    file->vnode = vn;
    file->dentry = resolved.dentry;
    dentry_get(file->dentry);
    file->flags = (uint32_t)(flags & (O_ACCMODE | O_APPEND | O_NONBLOCK));
    if (vfs_build_path_dentry(resolved.dentry, file->path,
                              sizeof(file->path)) < 0) {
        strncpy(file->path, path, sizeof(file->path) - 1);
        file->path[sizeof(file->path) - 1] = '\0';
    }
    if ((flags & O_TRUNC) && vn->ops->truncate)
        vn->ops->truncate(vn, 0);
    *fp = file;
    dentry_put(resolved.dentry);
    return 0;
}

int vfs_open_at(const char *cwd, const char *path, int flags, mode_t mode,
                struct file **fp) {
    if (!path || !fp)
        return -EINVAL;
    if (path[0] == '/' || !cwd || !cwd[0])
        return vfs_open_at_path(NULL, path, flags, mode, fp);
    struct path base;
    path_init(&base);
    int ret = vfs_namei(cwd, &base, NAMEI_FOLLOW | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    ret = vfs_open_at_path(&base, path, flags, mode, fp);
    if (base.dentry)
        dentry_put(base.dentry);
    return ret;
}

int vfs_open(const char *path, int flags, mode_t mode, struct file **fp) {
    struct process *cur = proc_current();
    if (cur && cur->cwd_dentry) {
        struct path base;
        path_init(&base);
        base.dentry = cur->cwd_dentry;
        base.mnt = cur->cwd_dentry->mnt;
        return vfs_open_at_path(&base, path, flags, mode, fp);
    }
    return vfs_open_at_path(NULL, path, flags, mode, fp);
}

int vfs_close(struct file *file) {
    if (!file)
        return -EINVAL;
    mutex_lock(&file->lock);
    if (--file->refcount > 0) {
        mutex_unlock(&file->lock);
        return 0;
    }
    mutex_unlock(&file->lock);
    if (file->vnode && file->vnode->type == VNODE_PIPE) {
        extern void pipe_close_end(struct vnode *vn, uint32_t flags);
        pipe_close_end(file->vnode, file->flags);
    }
    if (file->dentry) {
        dentry_put(file->dentry);
        file->dentry = NULL;
    }
    vnode_put(file->vnode);
    vfs_file_free(file);
    return 0;
}

ssize_t vfs_read(struct file *file, void *buf, size_t len) {
    if (!file)
        return -EINVAL;
    if (file->vnode->type == VNODE_DIR)
        return -EISDIR;
    if (file->vnode->type == VNODE_PIPE) {
        extern ssize_t pipe_read_file(struct file *file, void *buf, size_t len);
        return pipe_read_file(file, buf, len);
    }
    if (!file->vnode->ops->read)
        return -EINVAL;
    mutex_lock(&file->lock);
    ssize_t ret = file->vnode->ops->read(file->vnode, buf, len, file->offset);
    if (ret > 0)
        file->offset += ret;
    mutex_unlock(&file->lock);
    return ret;
}

ssize_t vfs_write(struct file *file, const void *buf, size_t len) {
    if (!file)
        return -EINVAL;
    if (file->vnode->type == VNODE_DIR)
        return -EISDIR;
    if (file->vnode->type == VNODE_PIPE) {
        extern ssize_t pipe_write_file(struct file *file, const void *buf, size_t len);
        return pipe_write_file(file, buf, len);
    }
    if (!file->vnode->ops->write)
        return -EINVAL;
    mutex_lock(&file->lock);
    if (file->flags & O_APPEND)
        file->offset = file->vnode->size;
    ssize_t ret = file->vnode->ops->write(file->vnode, buf, len, file->offset);
    if (ret > 0)
        file->offset += ret;
    mutex_unlock(&file->lock);
    return ret;
}

int vfs_ioctl(struct file *file, uint64_t cmd, uint64_t arg) {
    if (!file || !file->vnode || !file->vnode->ops || !file->vnode->ops->ioctl)
        return -ENOTTY;
    return file->vnode->ops->ioctl(file->vnode, cmd, arg);
}

off_t vfs_seek(struct file *file, off_t offset, int whence) {
    mutex_lock(&file->lock);
    off_t next;
    if (whence == SEEK_SET)
        next = offset;
    else if (whence == SEEK_CUR)
        next = file->offset + offset;
    else if (whence == SEEK_END)
        next = file->vnode->size + offset;
    else {
        mutex_unlock(&file->lock);
        return -EINVAL;
    }
    if (next < 0) {
        mutex_unlock(&file->lock);
        return -EINVAL;
    }
    file->offset = next;
    mutex_unlock(&file->lock);
    return next;
}

int vfs_stat(const char *path, struct stat *st) {
    if (!path || !st)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, NAMEI_FOLLOW);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    ret = vfs_fstat(&(struct file){.vnode = resolved.dentry->vnode}, st);
    dentry_put(resolved.dentry);
    return ret;
}

int vfs_fstat(struct file *file, struct stat *st) {
    struct vnode *vn = file->vnode;
    if (vn->ops->stat)
        return vn->ops->stat(vn, st);
    st->st_ino = vn->ino;
    st->st_mode = vn->mode;
    st->st_size = vn->size;
    st->st_uid = vn->uid;
    st->st_gid = vn->gid;
    return 0;
}

int vfs_mkdir(const char *path, mode_t mode) {
    if (!path)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, NAMEI_CREATE | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    if (!resolved.dentry) {
        return -ENOENT;
    }
    if (!(resolved.dentry->flags & DENTRY_NEGATIVE)) {
        dentry_put(resolved.dentry);
        return -EEXIST;
    }
    if (!resolved.dentry->parent || !resolved.dentry->parent->vnode ||
        !resolved.mnt || !resolved.mnt->ops || !resolved.mnt->ops->mkdir) {
        dentry_put(resolved.dentry);
        return -ENOSYS;
    }
    ret = resolved.mnt->ops->mkdir(resolved.dentry->parent->vnode,
                                   resolved.dentry->name, mode);
    if (ret == 0) {
        struct vnode *vn =
            resolved.mnt->ops->lookup(resolved.dentry->parent->vnode,
                                      resolved.dentry->name);
        if (vn) {
            dentry_add(resolved.dentry, vn);
            vnode_put(vn);
        }
    }
    dentry_put(resolved.dentry);
    return ret;
}

int vfs_rmdir(const char *path) {
    if (!path)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->parent ||
        !resolved.dentry->parent->vnode || !resolved.mnt ||
        !resolved.mnt->ops || !resolved.mnt->ops->rmdir) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOSYS;
    }
    if (resolved.dentry->mounted) {
        dentry_put(resolved.dentry);
        return -EBUSY;
    }
    ret = resolved.mnt->ops->rmdir(resolved.dentry->parent->vnode,
                                   resolved.dentry->name);
    if (ret == 0)
        dentry_drop(resolved.dentry);
    dentry_put(resolved.dentry);
    return ret;
}

int vfs_readdir(struct file *file, struct dirent *ent) {
    if (!file || !file->vnode->ops->readdir)
        return -ENOSYS;
    mutex_lock(&file->lock);
    int ret = file->vnode->ops->readdir(file->vnode, ent, &file->offset);
    mutex_unlock(&file->lock);
    return ret;
}

int vfs_unlink(const char *path) {
    if (!path)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, 0);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->parent ||
        !resolved.dentry->parent->vnode || !resolved.mnt ||
        !resolved.mnt->ops || !resolved.mnt->ops->unlink) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOSYS;
    }
    if (resolved.dentry->mounted) {
        dentry_put(resolved.dentry);
        return -EBUSY;
    }
    ret = resolved.mnt->ops->unlink(resolved.dentry->parent->vnode,
                                    resolved.dentry->name);
    if (ret == 0)
        dentry_drop(resolved.dentry);
    dentry_put(resolved.dentry);
    return ret;
}

int vfs_rename(const char *old, const char *new) {
    struct path oldp, newp;
    path_init(&oldp);
    path_init(&newp);
    int ret = vfs_namei(old, &oldp, 0);
    if (ret < 0)
        return ret;
    ret = vfs_namei(new, &newp, NAMEI_CREATE);
    if (ret < 0) {
        if (oldp.dentry)
            dentry_put(oldp.dentry);
        return ret;
    }
    if (!oldp.dentry || !newp.dentry || !oldp.dentry->parent ||
        !newp.dentry->parent || !oldp.mnt || !newp.mnt ||
        oldp.mnt != newp.mnt || !oldp.mnt->ops ||
        !oldp.mnt->ops->rename) {
        if (oldp.dentry)
            dentry_put(oldp.dentry);
        if (newp.dentry)
            dentry_put(newp.dentry);
        return -EXDEV;
    }
    if (oldp.dentry->mounted) {
        dentry_put(oldp.dentry);
        dentry_put(newp.dentry);
        return -EBUSY;
    }

    ret = oldp.mnt->ops->rename(oldp.dentry->parent->vnode, oldp.dentry->name,
                                newp.dentry->parent->vnode, newp.dentry->name);
    if (ret == 0) {
        if (newp.dentry && !(newp.dentry->flags & DENTRY_NEGATIVE))
            dentry_drop(newp.dentry);
        dentry_move(oldp.dentry, newp.dentry->parent, newp.dentry->name);
    }
    if (oldp.dentry)
        dentry_put(oldp.dentry);
    if (newp.dentry)
        dentry_put(newp.dentry);
    return ret;
}

int vfs_symlink(const char *target, const char *linkpath) {
    if (!target || !linkpath)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(linkpath, &resolved, NAMEI_CREATE);
    if (ret < 0)
        return ret;
    if (!resolved.dentry) {
        return -ENOENT;
    }
    if (!(resolved.dentry->flags & DENTRY_NEGATIVE)) {
        dentry_put(resolved.dentry);
        return -EEXIST;
    }
    if (!resolved.dentry->parent || !resolved.dentry->parent->vnode ||
        !resolved.mnt || !resolved.mnt->ops || !resolved.mnt->ops->symlink) {
        dentry_put(resolved.dentry);
        return -ENOSYS;
    }
    ret = resolved.mnt->ops->symlink(resolved.dentry->parent->vnode,
                                     resolved.dentry->name, target);
    if (ret == 0) {
        struct vnode *vn =
            resolved.mnt->ops->lookup(resolved.dentry->parent->vnode,
                                      resolved.dentry->name);
        if (vn) {
            dentry_add(resolved.dentry, vn);
            vnode_put(vn);
        }
    }
    dentry_put(resolved.dentry);
    return ret;
}

ssize_t vfs_readlink(const char *path, char *buf, size_t bufsz) {
    if (!path || !buf || bufsz == 0)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, 0);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    if (resolved.dentry->vnode->type != VNODE_SYMLINK) {
        dentry_put(resolved.dentry);
        return -EINVAL;
    }
    ssize_t rl = vfs_readlink_target(resolved.dentry->vnode, buf, bufsz, false);
    dentry_put(resolved.dentry);
    return rl;
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
