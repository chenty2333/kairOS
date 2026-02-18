/**
 * kernel/fs/vfs/namei.c - Path resolution (component-walk)
 */

#include <kairos/namei.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

static int namei_walk_locked(const struct path *base, const char *path,
                             struct path *out, int flags, int depth);

static int namei_get_start(const struct path *base, const char *path,
                           struct dentry **start, struct mount **mnt) {
    if (!start || !mnt)
        return -EINVAL;
    *start = NULL;
    *mnt = NULL;

    if (!path || !path[0])
        return -EINVAL;

    if (path[0] == '/') {
        struct dentry *root = vfs_root_dentry();
        if (!root)
            return -ENOENT;
        dentry_get(root);
        *start = root;
        *mnt = root->mnt;
        return 0;
    }

    if (base && base->dentry) {
        dentry_get(base->dentry);
        *start = base->dentry;
        *mnt = base->dentry->mnt;
        return 0;
    }

    struct process *p = proc_current();
    if (p && p->cwd_dentry) {
        dentry_get(p->cwd_dentry);
        *start = p->cwd_dentry;
        *mnt = p->cwd_dentry->mnt;
        return 0;
    }

    struct dentry *root = vfs_root_dentry();
    if (!root)
        return -ENOENT;
    dentry_get(root);
    *start = root;
    *mnt = root->mnt;
    return 0;
}

static int namei_follow_symlink(struct dentry *d, const char *remain,
                                struct path *out, int flags, int depth) {
    char target[CONFIG_PATH_MAX];
    ssize_t tlen = vfs_readlink_vnode(d->vnode, target, sizeof(target), true);
    if (tlen < 0)
        return (int)tlen;
    target[tlen] = '\0';

    char newpath[CONFIG_PATH_MAX];
    size_t n = 0;
    struct path base;
    path_init(&base);
    if (target[0] == '/') {
        size_t t = (size_t)tlen;
        if (t >= sizeof(newpath))
            return -ENAMETOOLONG;
        memcpy(newpath, target, t);
        n = t;
    } else {
        if (tlen >= (ssize_t)sizeof(newpath))
            return -ENAMETOOLONG;
        memcpy(newpath, target, (size_t)tlen);
        n = (size_t)tlen;
        if (d->parent) {
            base.dentry = d->parent;
            base.mnt = d->parent->mnt;
        } else {
            struct dentry *root = vfs_root_dentry();
            if (!root)
                return -ENOENT;
            base.dentry = root;
            base.mnt = root->mnt;
        }
    }

    if (remain && *remain) {
        if (n && newpath[n - 1] != '/')
            newpath[n++] = '/';
        size_t rlen = strlen(remain);
        if (n + rlen >= sizeof(newpath))
            return -ENAMETOOLONG;
        memcpy(newpath + n, remain, rlen);
        n += rlen;
    }
    newpath[n] = '\0';

    return namei_walk_locked(&base, newpath, out, flags | NAMEI_FOLLOW,
                             depth + 1);
}

static int namei_walk_locked(const struct path *base, const char *path,
                             struct path *out, int flags, int depth) {
    if (!path || !out)
        return -EINVAL;
    if (depth > CONFIG_SYMLINK_MAX)
        return -ELOOP;

    struct dentry *cur = NULL;
    struct mount *mnt = NULL;
    bool trailing_slash = false;
    size_t path_len = strlen(path);
    if (path_len > 0 && path[path_len - 1] == '/')
        trailing_slash = true;
    int ret = namei_get_start(base, path, &cur, &mnt);
    if (ret < 0)
        return ret;

    const char *p = path;
    if (*p == '/') {
        while (*p == '/')
            p++;
    }

    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        const char *end = p;
        while (*end && *end != '/')
            end++;
        size_t len = (size_t)(end - p);
        if (len >= CONFIG_NAME_MAX) {
            dentry_put(cur);
            return -ENAMETOOLONG;
        }
        char comp[CONFIG_NAME_MAX];
        memcpy(comp, p, len);
        comp[len] = '\0';

        const char *remain = end;
        while (*remain == '/')
            remain++;
        bool last = (*remain == '\0');

        if (strcmp(comp, ".") == 0) {
            p = end;
            continue;
        }
        if (strcmp(comp, "..") == 0) {
            struct dentry *ns_root = vfs_root_dentry();
            if (ns_root && cur == ns_root) {
                p = end;
                continue;
            }
            if (cur == mnt->root_dentry) {
                if (mnt->parent && mnt->mountpoint_dentry) {
                    struct dentry *mp = mnt->mountpoint_dentry;
                    if (mp->parent) {
                        dentry_get(mp->parent);
                        dentry_put(cur);
                        cur = mp->parent;
                        mnt = cur->mnt;
                    } else {
                        dentry_get(mp);
                        dentry_put(cur);
                        cur = mp;
                        mnt = cur->mnt;
                    }
                }
            } else if (cur->parent) {
                dentry_get(cur->parent);
                dentry_put(cur);
                cur = cur->parent;
                mnt = cur->mnt;
            }
            p = end;
            continue;
        }

        if (!cur->vnode || cur->vnode->type != VNODE_DIR) {
            dentry_put(cur);
            return -ENOTDIR;
        }

        struct dentry *d = dentry_lookup(cur, comp, mnt);
        if (!d) {
            d = dentry_alloc(cur, comp);
            if (!d) {
                dentry_put(cur);
                return -ENOMEM;
            }
            d->mnt = mnt;
            if (!mnt->ops || !mnt->ops->lookup) {
                dentry_put(cur);
                dentry_put(d);
                return -ENOSYS;
            }
            struct vnode *vn = mnt->ops->lookup(cur->vnode, comp);
            if (!vn) {
                if (last && (flags & NAMEI_CREATE)) {
                    dentry_add_negative(d);
                    dentry_put(cur);
                    out->dentry = d;
                    out->mnt = mnt;
                    return 0;
                }
                dentry_add_negative(d);
                dentry_put(cur);
                dentry_put(d);
                return -ENOENT;
            }
            rwlock_write_lock(&vn->lock);
            vnode_set_parent(vn, cur->vnode, comp);
            rwlock_write_unlock(&vn->lock);
            dentry_add(d, vn);
            vnode_put(vn);
        } else if (d->flags & DENTRY_NEGATIVE) {
            if (last && (flags & NAMEI_CREATE)) {
                dentry_put(cur);
                out->dentry = d;
                out->mnt = mnt;
                return 0;
            }
            dentry_put(cur);
            dentry_put(d);
            return -ENOENT;
        } else if ((flags & NAMEI_EXCL) && last) {
            dentry_put(cur);
            dentry_put(d);
            return -EEXIST;
        }

        if (d->vnode && d->vnode->type == VNODE_SYMLINK &&
            ((flags & NAMEI_FOLLOW) || !last)) {
            dentry_put(cur);
            ret = namei_follow_symlink(d, remain, out, flags, depth);
            dentry_put(d);
            return ret;
        }

        if (d->mounted && d->mounted->root_dentry) {
            struct dentry *root = d->mounted->root_dentry;
            dentry_get(root);
            dentry_put(d);
            d = root;
            mnt = d->mnt;
        }

        dentry_put(cur);
        cur = d;
        p = end;
    }

    if (flags & NAMEI_DIRECTORY) {
        if (cur->vnode) {
            if (cur->vnode->type != VNODE_DIR) {
                dentry_put(cur);
                return -ENOTDIR;
            }
        } else if (!(flags & NAMEI_CREATE)) {
            dentry_put(cur);
            return -ENOENT;
        }
    }
    if (trailing_slash) {
        if (!cur->vnode) {
            if (!((flags & NAMEI_CREATE) && (flags & NAMEI_DIRECTORY))) {
                dentry_put(cur);
                return -ENOENT;
            }
        } else if (cur->vnode->type != VNODE_DIR) {
            dentry_put(cur);
            return -ENOTDIR;
        }
    }
    out->dentry = cur;
    out->mnt = mnt;
    return 0;
}

int vfs_namei_at(const struct path *base, const char *path,
                 struct path *out, int flags) {
    if (!path || !out)
        return -EINVAL;
    path_init(out);
    if (!path[0])
        return -EINVAL;
    vfs_mount_global_lock();
    int ret = namei_walk_locked(base, path, out, flags, 0);
    vfs_mount_global_unlock();
    return ret;
}

int vfs_namei(const char *path, struct path *out, int flags) {
    struct path base;
    path_init(&base);
    return vfs_namei_at(&base, path, out, flags);
}

int vfs_namei_locked(const struct path *base, const char *path,
                     struct path *out, int flags) {
    if (!path || !out)
        return -EINVAL;
    path_init(out);
    if (!path[0])
        return -EINVAL;
    return namei_walk_locked(base, path, out, flags, 0);
}
