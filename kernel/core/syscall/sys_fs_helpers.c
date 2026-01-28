/**
 * kernel/core/syscall/sys_fs_helpers.c - FS syscall helpers (internal)
 */

#include <kairos/dentry.h>
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

    if (dirfd == AT_FDCWD) {
        struct dentry *cwd_d = sysfs_proc_cwd_dentry(p);
        if (!cwd_d)
            return -ENOENT;
        base->dentry = cwd_d;
        base->mnt = cwd_d->mnt;
        *basep = base;
        return 0;
    }

    struct file *f = fd_get(p, (int)dirfd);
    if (!f)
        return -EBADF;
    if (!f->vnode || f->vnode->type != VNODE_DIR)
        return -ENOTDIR;
    if (!f->dentry)
        return -ENOENT;
    base->dentry = f->dentry;
    base->mnt = f->dentry->mnt;
    *basep = base;
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

ssize_t sysfs_readlink_from_vnode(struct vnode *vn, char *buf, size_t bufsz) {
    if (!vn || !buf || bufsz == 0)
        return -EINVAL;
    if (vn->type != VNODE_SYMLINK || !vn->ops || !vn->ops->read)
        return -EINVAL;
    size_t need = (size_t)vn->size;
    size_t want = (need < bufsz) ? need : bufsz;
    if (!want)
        return 0;
    return vn->ops->read(vn, buf, want, 0);
}

mode_t sysfs_apply_umask(mode_t mode) {
    struct process *p = proc_current();
    mode_t mask = p ? p->umask : 0;
    return mode & ~mask;
}
