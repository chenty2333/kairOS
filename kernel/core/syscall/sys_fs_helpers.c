/**
 * kernel/core/syscall/sys_fs_helpers.c - FS syscall helpers (internal)
 */

#include <kairos/dentry.h>
#include <kairos/config.h>
#include <kairos/namei.h>
#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#include "sys_fs_helpers.h"

struct dentry *sysfs_proc_cwd_dentry(struct process *p) {
    if (!p)
        return NULL;
    if (p->cwd_dentry)
        return p->cwd_dentry;
    struct dentry *root = vfs_root_dentry();
    if (!root)
        return NULL;
    p->cwd_dentry = root;
    dentry_get(root);
    return p->cwd_dentry;
}

struct vnode *sysfs_proc_cwd_vnode(struct process *p) {
    if (!p)
        return NULL;
    if (!p->cwd_vnode && p->cwd_dentry && p->cwd_dentry->vnode) {
        p->cwd_vnode = p->cwd_dentry->vnode;
        vnode_get(p->cwd_vnode);
    }
    return p->cwd_vnode;
}

int sysfs_copy_path(uint64_t uptr, char *kbuf, size_t klen) {
    if (!uptr || !kbuf || klen == 0)
        return -EFAULT;
    long len = strncpy_from_user(kbuf, (const char *)uptr, klen);
    if (len < 0)
        return (int)len;
    if ((size_t)len >= klen)
        return -ENAMETOOLONG;
    kbuf[klen - 1] = '\0';
    return 0;
}

int sysfs_get_base_path(int64_t dirfd, const char *path, struct path *base,
                        struct path **basep) {
    if (!path || !basep)
        return -EINVAL;
    *basep = NULL;
    if (path[0] == '/')
        return 0;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    int64_t kdirfd = (int64_t)(int32_t)(uint32_t)dirfd;

    if (kdirfd == AT_FDCWD) {
        struct dentry *cwd_d = sysfs_proc_cwd_dentry(p);
        if (!cwd_d)
            return -ENOENT;
        base->dentry = cwd_d;
        base->mnt = cwd_d->mnt;
        *basep = base;
        return 0;
    }

    struct file *f = fd_get(p, (int)kdirfd);
    if (!f)
        return -EBADF;
    if (!f->vnode || f->vnode->type != VNODE_DIR) {
        file_put(f);
        return -ENOTDIR;
    }
    if (!f->dentry) {
        file_put(f);
        return -ENOENT;
    }
    base->dentry = f->dentry;
    base->mnt = f->dentry->mnt;
    *basep = base;
    file_put(f);
    return 0;
}

int sysfs_resolve_at(int64_t dirfd, const char *path, struct path *out,
                     int flags) {
    if (!path || !out)
        return -EINVAL;
    struct path base;
    path_init(&base);
    struct path *basep = NULL;
    int ret = sysfs_get_base_path(dirfd, path, &base, &basep);
    if (ret < 0)
        return ret;
    return vfs_namei_at(basep, path, out, flags);
}

int sysfs_resolve_at_user(int64_t dirfd, uint64_t upath, struct path *out,
                          int flags) {
    char kpath[CONFIG_PATH_MAX];
    int ret = sysfs_copy_path(upath, kpath, sizeof(kpath));
    if (ret < 0)
        return ret;
    return sysfs_resolve_at(dirfd, kpath, out, flags);
}

ssize_t sysfs_readlink_from_vnode(struct vnode *vn, char *buf, size_t bufsz) {
    if (!vn || !buf || bufsz == 0)
        return -EINVAL;
    if (vn->type != VNODE_SYMLINK || !vn->ops || !vn->ops->read)
        return -EINVAL;
    rwlock_read_lock(&vn->lock);
    size_t need = (size_t)vn->size;
    size_t want = (need < bufsz) ? need : bufsz;
    if (!want) {
        rwlock_read_unlock(&vn->lock);
        return 0;
    }
    ssize_t ret = vn->ops->read(vn, buf, want, 0, 0);
    rwlock_read_unlock(&vn->lock);
    return ret;
}

mode_t sysfs_apply_umask(mode_t mode) {
    struct process *p = proc_current();
    mode_t mask = p ? p->umask : 0;
    return mode & ~mask;
}
