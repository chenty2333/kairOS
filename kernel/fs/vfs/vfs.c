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

static struct kmem_cache *vnode_cache;
static struct kmem_cache *file_cache;

int vfs_normalize_path(const char *cwd, const char *input, char *output);

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

int vfs_normalize_path(const char *cwd, const char *input, char *output) {
    struct path_comp {
        char *s;
        size_t len;
    };
    char temp[CONFIG_PATH_MAX];
    struct path_comp stack[32];
    int top = 0;
    if (!output || !input)
        return -EINVAL;

    if (input[0] == '/') {
        if (strlen(input) >= CONFIG_PATH_MAX)
            return -ENAMETOOLONG;
        strcpy(temp, input);
    } else {
        if (!cwd || cwd[0] != '/')
            return -EINVAL;
        if (strlen(cwd) + strlen(input) + 2 >= CONFIG_PATH_MAX)
            return -ENAMETOOLONG;
        strcpy(temp, cwd);
        if (temp[strlen(temp) - 1] != '/')
            strcat(temp, "/");
        strcat(temp, input);
    }

    char *p = temp;
    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        char *start = p;
        while (*p && *p != '/')
            p++;
        size_t len = (size_t)(p - start);
        char saved = *p;
        *p = '\0';
        if (strcmp(start, ".") == 0)
            ;
        else if (strcmp(start, "..") == 0) {
            if (top > 0)
                top--;
        } else {
            if (top < 32) {
                stack[top].s = start;
                stack[top].len = len;
                top++;
            }
            else
                return -ENAMETOOLONG;
        }
        *p = saved;
    }

    char *out = output;
    *out++ = '/';
    for (int i = 0; i < top; i++) {
        size_t len = stack[i].len;
        memcpy(out, stack[i].s, len);
        out += len;
        if (i < top - 1)
            *out++ = '/';
    }
    *out = '\0';
    return 0;
}

void vfs_init(void) {
    vnode_cache = kmem_cache_create("vnode", sizeof(struct vnode), NULL);
    file_cache = kmem_cache_create("file", sizeof(struct file), NULL);
    dentry_init();
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
    return root_mount;
}

struct dentry *vfs_root_dentry(void) {
    if (!root_mount)
        return NULL;
    return root_mount->root_dentry;
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
    spin_lock(&vfs_lock);
    fs = find_fs_type(fstype);
    spin_unlock(&vfs_lock);
    if (!fs)
        return -ENODEV;
    if (src && !(dev = blkdev_get(src)))
        return -ENODEV;
    if (!(mnt = kzalloc(sizeof(*mnt))) ||
        !(mnt->mountpoint = kmalloc(strlen(tgt) + 1)))
        goto err;
    strcpy(mnt->mountpoint, tgt);
    mnt->ops = fs->ops;
    mnt->dev = dev;
    mnt->flags = flags;
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
    if (strcmp(tgt, "/") != 0) {
        struct path mp;
        path_init(&mp);
        ret = vfs_namei(tgt, &mp, NAMEI_FOLLOW | NAMEI_DIRECTORY);
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
    return 0;
err:
    if (mnt && mnt->mountpoint_dentry) {
        mnt->mountpoint_dentry->mounted = NULL;
        mnt->mountpoint_dentry->flags &= ~DENTRY_MOUNTPOINT;
        dentry_put(mnt->mountpoint_dentry);
        mnt->mountpoint_dentry = NULL;
    }
    if (mnt) {
        kfree(mnt->mountpoint);
        kfree(mnt);
    }
    if (dev)
        blkdev_put(dev);
    return ret;
}

int vfs_umount(const char *tgt) {
    struct mount *mnt;
    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        if (strcmp(mnt->mountpoint, tgt) == 0) {
            list_del(&mnt->list);
            if (mnt == root_mount)
                root_mount = NULL;
            spin_unlock(&vfs_lock);
            if (mnt->ops->unmount)
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
            if (mnt->dev)
                blkdev_put(mnt->dev);
            kfree(mnt->mountpoint);
            kfree(mnt);
            return 0;
        }
    }
    spin_unlock(&vfs_lock);
    return -ENOENT;
}

static struct vnode *vfs_lookup_at_internal(const char *cwd, const char *path,
                                            bool follow_final, int depth) {
    char norm[CONFIG_PATH_MAX], comp[CONFIG_NAME_MAX];
    struct vnode *vn, *dir;
    if (!path || depth > CONFIG_SYMLINK_MAX)
        return NULL;
    if (vfs_normalize_path(cwd ? cwd : "/", path, norm) < 0)
        return NULL;
    struct mount *mnt = find_mount(norm);
    if (!mnt || !(dir = mnt->root))
        return NULL;
    vnode_get(dir);
    const char *p = norm + strlen(mnt->mountpoint);
    if (strlen(mnt->mountpoint) > 1 && *p == '/')
        p++;
    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        const char *end = p;
        while (*end && *end != '/')
            end++;
        size_t len = end - p;
        if (len >= CONFIG_NAME_MAX) {
            vnode_put(dir);
            return NULL;
        }
        memcpy(comp, p, len);
        comp[len] = '\0';
        if (!mnt->ops->lookup || !(vn = mnt->ops->lookup(dir, comp))) {
            vnode_put(dir);
            return NULL;
        }
        vnode_set_parent(vn, dir, comp);
        vnode_put(dir);

        const char *remain = end;
        while (*remain == '/')
            remain++;
        bool last = (*remain == '\0');

        if (vn->type == VNODE_SYMLINK && (follow_final || !last)) {
            char target[CONFIG_PATH_MAX];
            ssize_t tlen = vfs_readlink_target(vn, target, sizeof(target), true);
            vnode_put(vn);
            if (tlen < 0)
                return NULL;
            target[tlen] = '\0';

            char newpath[CONFIG_PATH_MAX];
            size_t n = 0;
            if (target[0] == '/') {
                if ((size_t)tlen >= sizeof(newpath))
                    return NULL;
                memcpy(newpath, target, (size_t)tlen);
                n = (size_t)tlen;
            } else {
                size_t base_len = (p > norm) ? (size_t)(p - norm) - 1 : 0;
                if (base_len == 0) {
                    newpath[n++] = '/';
                } else {
                    if (base_len >= sizeof(newpath))
                        return NULL;
                    memcpy(newpath, norm, base_len);
                    n = base_len;
                }
                if (n == 0 || newpath[n - 1] != '/')
                    newpath[n++] = '/';
                if (n + (size_t)tlen >= sizeof(newpath))
                    return NULL;
                memcpy(newpath + n, target, (size_t)tlen);
                n += (size_t)tlen;
            }

            if (*remain) {
                if (n == 0 || newpath[n - 1] != '/')
                    newpath[n++] = '/';
                size_t rlen = strlen(remain);
                if (n + rlen >= sizeof(newpath))
                    return NULL;
                memcpy(newpath + n, remain, rlen);
                n += rlen;
            }
            newpath[n] = '\0';
            return vfs_lookup_at_internal("/", newpath, follow_final, depth + 1);
        }

        dir = vn;
        p = end;
    }
    return dir;
}

struct vnode *vfs_lookup_at(const char *cwd, const char *path) {
    return vfs_lookup_at_internal(cwd, path, true, 0);
}

static struct vnode *vfs_lookup_from_dir_internal(struct vnode *start,
                                                  const char *path,
                                                  bool follow_final,
                                                  int depth) {
    (void)depth;
    if (!start || !path)
        return NULL;

    char full[CONFIG_PATH_MAX];
    if (path[0] == '/') {
        size_t plen = strlen(path);
        if (plen + 1 > sizeof(full))
            return NULL;
        memcpy(full, path, plen + 1);
    } else {
        int ret = vfs_build_path(start, full, sizeof(full));
        if (ret < 0)
            return NULL;
        size_t blen = strlen(full);
        size_t plen = strlen(path);
        if (blen + plen + 2 > sizeof(full))
            return NULL;
        if (blen == 0 || full[blen - 1] != '/')
            full[blen++] = '/';
        memcpy(full + blen, path, plen + 1);
    }

    int nflags = follow_final ? NAMEI_FOLLOW : NAMEI_NOFOLLOW;
    struct path resolved;
    path_init(&resolved);
    if (vfs_namei(full, &resolved, nflags) < 0)
        return NULL;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return NULL;
    }
    struct vnode *vn = resolved.dentry->vnode;
    vnode_get(vn);
    dentry_put(resolved.dentry);
    return vn;
}

struct vnode *vfs_lookup_from_dir(struct vnode *dir, const char *path) {
    return vfs_lookup_from_dir_internal(dir, path, true, 0);
}

struct vnode *vfs_lookup_from_dir_nofollow(struct vnode *dir,
                                           const char *path) {
    return vfs_lookup_from_dir_internal(dir, path, false, 0);
}

static struct vnode *vfs_lookup_legacy(const char *path) {
    struct process *cur = proc_current();
    (void)cur;
    (void)path;
    return NULL;
}

struct vnode *vfs_lookup(const char *path) {
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, NAMEI_FOLLOW);
    if (ret == 0 && resolved.dentry && resolved.dentry->vnode) {
        struct vnode *vn = resolved.dentry->vnode;
        vnode_get(vn);
        dentry_put(resolved.dentry);
        return vn;
    }
    if (resolved.dentry)
        dentry_put(resolved.dentry);
    return vfs_lookup_legacy(path);
}

struct vnode *vfs_lookup_parent(const char *path, char *name) {
    if (!path || !name || path[0] != '/')
        return NULL;
    const char *last = strrchr(path, '/');
    if (!last)
        return NULL;
    strncpy(name, last + 1, CONFIG_NAME_MAX - 1);
    name[CONFIG_NAME_MAX - 1] = '\0';
    if (last == path)
        return vfs_lookup("/");
    char parent[CONFIG_PATH_MAX];
    size_t len = last - path;
    memcpy(parent, path, len);
    parent[len] = '\0';
    return vfs_lookup(parent);
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
    while (cur) {
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

struct vnode *vfs_lookup_parent_from_dir(struct vnode *dir, const char *path,
                                         char *name) {
    if (!dir || !path || !name)
        return NULL;
    if (path[0] == '/')
        return vfs_lookup_parent(path, name);
    char full[CONFIG_PATH_MAX];
    int ret = vfs_build_path(dir, full, sizeof(full));
    if (ret < 0)
        return NULL;
    size_t blen = strlen(full);
    size_t plen = strlen(path);
    if (blen + plen + 2 > sizeof(full))
        return NULL;
    if (blen == 0 || full[blen - 1] != '/')
        full[blen++] = '/';
    memcpy(full + blen, path, plen + 1);

    struct path resolved;
    path_init(&resolved);
    ret = vfs_namei(full, &resolved, NAMEI_CREATE);
    if (ret < 0)
        return NULL;
    if (!resolved.dentry || !resolved.dentry->parent ||
        !resolved.dentry->parent->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return NULL;
    }
    strncpy(name, resolved.dentry->name, CONFIG_NAME_MAX - 1);
    name[CONFIG_NAME_MAX - 1] = '\0';
    struct vnode *parent = resolved.dentry->parent->vnode;
    vnode_get(parent);
    dentry_put(resolved.dentry);
    return parent;
}

int vfs_open_at_dir(struct vnode *dir, const char *path, int flags, mode_t mode,
                    struct file **fp) {
    if (!dir || !path || !fp)
        return -EINVAL;
    if (path[0] == '/')
        return vfs_open_at("/", path, flags, mode, fp);
    char full[CONFIG_PATH_MAX];
    int ret = vfs_build_path(dir, full, sizeof(full));
    if (ret < 0)
        return ret;
    size_t blen = strlen(full);
    size_t plen = strlen(path);
    if (blen + plen + 2 > sizeof(full))
        return -ENAMETOOLONG;
    if (blen == 0 || full[blen - 1] != '/')
        full[blen++] = '/';
    memcpy(full + blen, path, plen + 1);
    return vfs_open_at("/", full, flags, mode, fp);
}

int vfs_open_at(const char *cwd, const char *path, int flags, mode_t mode,
                struct file **fp) {
    if (!path || !fp)
        return -EINVAL;
    if ((flags & O_DIRECTORY) && (flags & O_CREAT))
        return -EINVAL;
    char full[CONFIG_PATH_MAX];
    const char *usepath = path;
    if (path[0] != '/' && cwd && cwd[0]) {
        size_t blen = strlen(cwd);
        size_t plen = strlen(path);
        if (blen + plen + 2 > sizeof(full))
            return -ENAMETOOLONG;
        memcpy(full, cwd, blen);
        if (blen == 0 || full[blen - 1] != '/')
            full[blen++] = '/';
        memcpy(full + blen, path, plen + 1);
        usepath = full;
    }

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
    int ret = vfs_namei(usepath, &resolved, nflags);
    if (ret < 0)
        return ret;
    if (!resolved.dentry) {
        return -ENOENT;
    }

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
            return -ENOSYS;
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
    file->flags = flags;
    if (vfs_build_path_dentry(resolved.dentry, file->path,
                              sizeof(file->path)) < 0) {
        strncpy(file->path, usepath, sizeof(file->path) - 1);
        file->path[sizeof(file->path) - 1] = '\0';
    }
    if ((flags & O_TRUNC) && vn->ops->truncate)
        vn->ops->truncate(vn, 0);
    *fp = file;
    dentry_put(resolved.dentry);
    return 0;
}

int vfs_open(const char *path, int flags, mode_t mode, struct file **fp) {
    struct process *cur = proc_current();
    return vfs_open_at(cur ? cur->cwd : "/", path, flags, mode, fp);
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

int vfs_poll_vnode(struct vnode *vn, uint32_t events) {
    if (!vn)
        return POLLNVAL;
    if (vn->type == VNODE_PIPE) {
        extern int pipe_poll_vnode(struct vnode *vn, uint32_t events);
        return pipe_poll_vnode(vn, events);
    }
    if (vn->ops->poll)
        return vn->ops->poll(vn, events);
    return events & (POLLIN | POLLOUT);
}

int vfs_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;
    if (file->vnode->type == VNODE_PIPE) {
        extern int pipe_poll_file(struct file *file, uint32_t events);
        return pipe_poll_file(file, events);
    }
    return vfs_poll_vnode(file->vnode, events);
}

int vfs_ioctl(struct file *file, uint64_t cmd, uint64_t arg) {
    if (!file || !file->vnode || !file->vnode->ops || !file->vnode->ops->ioctl)
        return -ENOTTY;
    return file->vnode->ops->ioctl(file->vnode, cmd, arg);
}

void vfs_poll_register(struct file *file, struct poll_waiter *waiter,
                       uint32_t events) {
    if (!file || !file->vnode || !waiter)
        return;
    if (file->vnode->type == VNODE_PIPE) {
        extern void pipe_poll_register_file(struct file *file,
                                            struct poll_waiter *waiter,
                                            uint32_t events);
        pipe_poll_register_file(file, waiter, events);
        return;
    }
    poll_wait_add(&file->vnode->pollers, waiter);
}

void vfs_poll_unregister(struct poll_waiter *waiter) {
    poll_wait_remove(waiter);
}

void vfs_poll_watch(struct vnode *vn, struct poll_watch *watch,
                    uint32_t events) {
    if (!vn || !watch)
        return;
    if (vn->type == VNODE_PIPE) {
        extern void pipe_poll_watch_vnode(struct vnode *vn,
                                          struct poll_watch *watch,
                                          uint32_t events);
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
    if (vn->type == VNODE_PIPE) {
        extern void pipe_poll_wake_vnode(struct vnode *vn, uint32_t events);
        pipe_poll_wake_vnode(vn, events);
        return;
    }
    poll_wait_wake(&vn->pollers, events);
}

off_t vfs_seek(struct file *file, off_t offset, int whence) {
    mutex_lock(&file->lock);
    off_t next = (whence == SEEK_SET)   ? offset
                 : (whence == SEEK_CUR) ? file->offset + offset
                                        : file->vnode->size + offset;
    if (next < 0) {
        mutex_unlock(&file->lock);
        return -EINVAL;
    }
    file->offset = next;
    mutex_unlock(&file->lock);
    return next;
}

int vfs_stat(const char *path, struct stat *st) {
    struct vnode *vn = vfs_lookup(path);
    if (!vn)
        return -ENOENT;
    int ret = vfs_fstat(&(struct file){.vnode = vn}, st);
    vnode_put(vn);
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

int vfs_mkdir_at_dir(struct vnode *dir, const char *path, mode_t mode) {
    if (!dir || !path)
        return -EINVAL;
    if (path[0] == '/')
        return vfs_mkdir(path, mode);
    char full[CONFIG_PATH_MAX];
    int ret = vfs_build_path(dir, full, sizeof(full));
    if (ret < 0)
        return ret;
    size_t blen = strlen(full);
    size_t plen = strlen(path);
    if (blen + plen + 2 > sizeof(full))
        return -ENAMETOOLONG;
    if (blen == 0 || full[blen - 1] != '/')
        full[blen++] = '/';
    memcpy(full + blen, path, plen + 1);
    return vfs_mkdir(full, mode);
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

int vfs_rmdir_at_dir(struct vnode *dir, const char *path) {
    if (!dir || !path)
        return -EINVAL;
    if (path[0] == '/')
        return vfs_rmdir(path);
    char full[CONFIG_PATH_MAX];
    int ret = vfs_build_path(dir, full, sizeof(full));
    if (ret < 0)
        return ret;
    size_t blen = strlen(full);
    size_t plen = strlen(path);
    if (blen + plen + 2 > sizeof(full))
        return -ENAMETOOLONG;
    if (blen == 0 || full[blen - 1] != '/')
        full[blen++] = '/';
    memcpy(full + blen, path, plen + 1);
    return vfs_rmdir(full);
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

int vfs_unlink_at_dir(struct vnode *dir, const char *path) {
    if (!dir || !path)
        return -EINVAL;
    if (path[0] == '/')
        return vfs_unlink(path);
    char full[CONFIG_PATH_MAX];
    int ret = vfs_build_path(dir, full, sizeof(full));
    if (ret < 0)
        return ret;
    size_t blen = strlen(full);
    size_t plen = strlen(path);
    if (blen + plen + 2 > sizeof(full))
        return -ENAMETOOLONG;
    if (blen == 0 || full[blen - 1] != '/')
        full[blen++] = '/';
    memcpy(full + blen, path, plen + 1);
    return vfs_unlink(full);
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

int vfs_rename_at_dir(struct vnode *odir, const char *oldpath,
                      struct vnode *ndir, const char *newpath) {
    if (!odir || !ndir || !oldpath || !newpath)
        return -EINVAL;
    if (oldpath[0] == '/' || newpath[0] == '/')
        return vfs_rename(oldpath, newpath);
    char oldfull[CONFIG_PATH_MAX];
    char newfull[CONFIG_PATH_MAX];
    int ret = vfs_build_path(odir, oldfull, sizeof(oldfull));
    if (ret < 0)
        return ret;
    ret = vfs_build_path(ndir, newfull, sizeof(newfull));
    if (ret < 0)
        return ret;
    size_t oblen = strlen(oldfull);
    size_t nblen = strlen(newfull);
    size_t olen = strlen(oldpath);
    size_t nlen = strlen(newpath);
    if (oblen + olen + 2 > sizeof(oldfull))
        return -ENAMETOOLONG;
    if (nblen + nlen + 2 > sizeof(newfull))
        return -ENAMETOOLONG;
    if (oblen == 0 || oldfull[oblen - 1] != '/')
        oldfull[oblen++] = '/';
    memcpy(oldfull + oblen, oldpath, olen + 1);
    if (nblen == 0 || newfull[nblen - 1] != '/')
        newfull[nblen++] = '/';
    memcpy(newfull + nblen, newpath, nlen + 1);
    return vfs_rename(oldfull, newfull);
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

int vfs_symlink_at_dir(struct vnode *dir, const char *target,
                       const char *linkpath) {
    if (!dir || !target || !linkpath)
        return -EINVAL;
    if (linkpath[0] == '/')
        return vfs_symlink(target, linkpath);
    char full[CONFIG_PATH_MAX];
    int ret = vfs_build_path(dir, full, sizeof(full));
    if (ret < 0)
        return ret;
    size_t blen = strlen(full);
    size_t plen = strlen(linkpath);
    if (blen + plen + 2 > sizeof(full))
        return -ENAMETOOLONG;
    if (blen == 0 || full[blen - 1] != '/')
        full[blen++] = '/';
    memcpy(full + blen, linkpath, plen + 1);
    return vfs_symlink(target, full);
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

ssize_t vfs_readlink_at_dir(struct vnode *dir, const char *path, char *buf,
                            size_t bufsz) {
    if (!dir || !path || !buf || bufsz == 0)
        return -EINVAL;
    if (path[0] == '/')
        return vfs_readlink(path, buf, bufsz);
    char full[CONFIG_PATH_MAX];
    int ret = vfs_build_path(dir, full, sizeof(full));
    if (ret < 0)
        return ret;
    size_t blen = strlen(full);
    size_t plen = strlen(path);
    if (blen + plen + 2 > sizeof(full))
        return -ENAMETOOLONG;
    if (blen == 0 || full[blen - 1] != '/')
        full[blen++] = '/';
    memcpy(full + blen, path, plen + 1);
    return vfs_readlink(full, buf, bufsz);
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
