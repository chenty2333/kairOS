/**
 * kernel/core/syscall/sys_fs_path.c - Path-related syscalls
 */

#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/namei.h>
#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/string.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#include "sys_fs_helpers.h"

int64_t sys_getcwd(uint64_t buf_ptr, uint64_t size, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (!buf_ptr)
        return -EFAULT;
    if (size == 0)
        return -EINVAL;
    struct dentry *cwd_d = sysfs_proc_cwd_dentry(p);
    if (!cwd_d)
        return -ENOENT;
    char kpath[CONFIG_PATH_MAX];
    int plen = vfs_build_path_dentry(cwd_d, kpath, sizeof(kpath));
    if (plen < 0)
        return -ENOENT;
    strncpy(p->cwd, kpath, sizeof(p->cwd) - 1);
    p->cwd[sizeof(p->cwd) - 1] = '\0';
    size_t len = strlen(p->cwd) + 1;
    if (len > size)
        return -ERANGE;
    if (copy_to_user((void *)buf_ptr, p->cwd, len) < 0)
        return -EFAULT;
    return (int64_t)len;
}

int64_t sys_chdir(uint64_t path_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path_ptr, sizeof(kpath)) < 0)
        return -EFAULT;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(kpath, &resolved,
                        NAMEI_FOLLOW | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    if (resolved.dentry->vnode->type != VNODE_DIR) {
        dentry_put(resolved.dentry);
        return -ENOTDIR;
    }

    struct process *p = proc_current();
    if (p->cwd_vnode)
        vnode_put(p->cwd_vnode);
    if (p->cwd_dentry)
        dentry_put(p->cwd_dentry);
    p->cwd_vnode = resolved.dentry->vnode;
    vnode_get(p->cwd_vnode);
    p->cwd_dentry = resolved.dentry;
    dentry_get(p->cwd_dentry);
    if (vfs_build_path_dentry(resolved.dentry, p->cwd, sizeof(p->cwd)) < 0)
        strcpy(p->cwd, "/");
    dentry_put(resolved.dentry);
    return 0;
}

int64_t sys_fchdir(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct file *f = fd_get(p, (int)fd);
    if (!f)
        return -EBADF;
    if (!f->vnode || f->vnode->type != VNODE_DIR)
        return -ENOTDIR;
    if (!f->dentry)
        return -ENOENT;

    if (p->cwd_vnode)
        vnode_put(p->cwd_vnode);
    if (p->cwd_dentry)
        dentry_put(p->cwd_dentry);
    p->cwd_vnode = f->vnode;
    vnode_get(p->cwd_vnode);
    p->cwd_dentry = f->dentry;
    dentry_get(p->cwd_dentry);
    if (vfs_build_path_dentry(f->dentry, p->cwd, sizeof(p->cwd)) < 0)
        strcpy(p->cwd, "/");
    return 0;
}

int64_t sys_openat(uint64_t dirfd, uint64_t path, uint64_t flags, uint64_t mode,
                   uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    struct file *f;
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0)
        return -EFAULT;
    struct path base;
    path_init(&base);
    struct path *basep = NULL;
    int ret = sysfs_get_base_path((int64_t)dirfd, kpath, &base, &basep);
    if (ret < 0)
        return ret;
    mode_t umode = (flags & O_CREAT) ? sysfs_apply_umask((mode_t)mode)
                                     : (mode_t)mode;
    ret = vfs_open_at_path(basep, kpath, (int)flags, umode, &f);
    if (ret < 0) {
        if (strcmp(kpath, "/bin/busybox") == 0 ||
            strcmp(kpath, "/oldroot/bin/busybox") == 0) {
            pr_warn("openat: %s failed (ret=%d)\n", kpath, ret);
        }
        return ret;
    }

    int fd_out = fd_alloc(proc_current(), f);
    if (fd_out < 0) {
        vfs_close(f);
        return -EMFILE;
    }
    return fd_out;
}

int64_t sys_open(uint64_t path, uint64_t flags, uint64_t mode, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_openat((uint64_t)(int64_t)AT_FDCWD, path, flags, mode, 0, 0);
}

int64_t sys_faccessat(uint64_t dirfd, uint64_t path_ptr, uint64_t mode,
                      uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW))
        return -EINVAL;
    if (mode & ~(F_OK | R_OK | W_OK | X_OK))
        return -EINVAL;

    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path_ptr, sizeof(kpath)) < 0)
        return -EFAULT;

    int nflags = NAMEI_FOLLOW;
    if (flags & AT_SYMLINK_NOFOLLOW)
        nflags = NAMEI_NOFOLLOW;

    struct path resolved;
    path_init(&resolved);
    int ret = sysfs_resolve_at((int64_t)dirfd, kpath, &resolved, nflags);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    dentry_put(resolved.dentry);
    return 0;
}

int64_t sys_unlinkat(uint64_t dirfd, uint64_t path_ptr, uint64_t flags,
                     uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (flags & ~AT_REMOVEDIR)
        return -EINVAL;

    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path_ptr, sizeof(kpath)) < 0)
        return -EFAULT;

    int nflags = (flags & AT_REMOVEDIR) ? NAMEI_DIRECTORY : 0;
    struct path resolved;
    path_init(&resolved);
    int ret = sysfs_resolve_at((int64_t)dirfd, kpath, &resolved, nflags);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->parent ||
        !resolved.dentry->parent->vnode || !resolved.mnt ||
        !resolved.mnt->ops) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -EOPNOTSUPP;
    }
    if (resolved.dentry->mounted) {
        dentry_put(resolved.dentry);
        return -EBUSY;
    }
    if (flags & AT_REMOVEDIR) {
        if (!resolved.mnt->ops->rmdir) {
            dentry_put(resolved.dentry);
            return -EOPNOTSUPP;
        }
        ret = resolved.mnt->ops->rmdir(resolved.dentry->parent->vnode,
                                       resolved.dentry->name);
    } else {
        if (!resolved.mnt->ops->unlink) {
            dentry_put(resolved.dentry);
            return -EOPNOTSUPP;
        }
        ret = resolved.mnt->ops->unlink(resolved.dentry->parent->vnode,
                                        resolved.dentry->name);
    }
    if (ret == 0)
        dentry_drop(resolved.dentry);
    dentry_put(resolved.dentry);
    return ret;
}

int64_t sys_mkdirat(uint64_t dirfd, uint64_t path_ptr, uint64_t mode,
                    uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path_ptr, sizeof(kpath)) < 0)
        return -EFAULT;

    mode_t umode = sysfs_apply_umask((mode_t)mode);
    struct path resolved;
    path_init(&resolved);
    int ret = sysfs_resolve_at((int64_t)dirfd, kpath, &resolved,
                               NAMEI_CREATE | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    if (!resolved.dentry)
        return -ENOENT;
    if (!(resolved.dentry->flags & DENTRY_NEGATIVE)) {
        dentry_put(resolved.dentry);
        return -EEXIST;
    }
    if (!resolved.dentry->parent || !resolved.dentry->parent->vnode ||
        !resolved.mnt || !resolved.mnt->ops || !resolved.mnt->ops->mkdir) {
        dentry_put(resolved.dentry);
        return -EOPNOTSUPP;
    }
    ret = resolved.mnt->ops->mkdir(resolved.dentry->parent->vnode,
                                   resolved.dentry->name, umode);
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

int64_t sys_renameat(uint64_t olddirfd, uint64_t oldpath_ptr,
                     uint64_t newdirfd, uint64_t newpath_ptr, uint64_t a4,
                     uint64_t a5) {
    (void)a4; (void)a5;
    char oldpath[CONFIG_PATH_MAX];
    char newpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(oldpath, (const char *)oldpath_ptr, sizeof(oldpath)) < 0)
        return -EFAULT;
    if (strncpy_from_user(newpath, (const char *)newpath_ptr, sizeof(newpath)) < 0)
        return -EFAULT;

    struct path oldp, newp;
    path_init(&oldp);
    path_init(&newp);
    int ret = sysfs_resolve_at((int64_t)olddirfd, oldpath, &oldp, 0);
    if (ret < 0)
        return ret;
    ret = sysfs_resolve_at((int64_t)newdirfd, newpath, &newp, NAMEI_CREATE);
    if (ret < 0) {
        if (oldp.dentry)
            dentry_put(oldp.dentry);
        return ret;
    }
    if (!oldp.dentry || !newp.dentry || !oldp.dentry->parent ||
        !newp.dentry->parent || !oldp.mnt || !newp.mnt) {
        if (oldp.dentry)
            dentry_put(oldp.dentry);
        if (newp.dentry)
            dentry_put(newp.dentry);
        return -EXDEV;
    }
    if (oldp.mnt != newp.mnt) {
        dentry_put(oldp.dentry);
        dentry_put(newp.dentry);
        return -EXDEV;
    }
    if (!oldp.mnt->ops || !oldp.mnt->ops->rename) {
        dentry_put(oldp.dentry);
        dentry_put(newp.dentry);
        return -EOPNOTSUPP;
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

int64_t sys_readlinkat(uint64_t dirfd, uint64_t path_ptr, uint64_t buf_ptr,
                       uint64_t bufsz, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (!buf_ptr)
        return -EFAULT;
    if (bufsz == 0)
        return -EINVAL;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path_ptr, sizeof(kpath)) < 0)
        return -EFAULT;

    char kbuf[CONFIG_PATH_MAX];
    size_t klen = (bufsz < sizeof(kbuf)) ? (size_t)bufsz : sizeof(kbuf);
    struct path resolved;
    path_init(&resolved);
    int ret = sysfs_resolve_at((int64_t)dirfd, kpath, &resolved, 0);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    ssize_t rl = sysfs_readlink_from_vnode(resolved.dentry->vnode, kbuf, klen);
    dentry_put(resolved.dentry);
    if (rl < 0)
        return (int64_t)rl;
    if (copy_to_user((void *)buf_ptr, kbuf, (size_t)rl) < 0)
        return -EFAULT;
    return (int64_t)rl;
}

int64_t sys_symlinkat(uint64_t target_ptr, uint64_t dirfd, uint64_t linkpath_ptr,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    char target[CONFIG_PATH_MAX];
    char linkpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(target, (const char *)target_ptr, sizeof(target)) < 0)
        return -EFAULT;
    if (strncpy_from_user(linkpath, (const char *)linkpath_ptr, sizeof(linkpath)) < 0)
        return -EFAULT;
    struct path resolved;
    path_init(&resolved);
    int ret = sysfs_resolve_at((int64_t)dirfd, linkpath, &resolved, NAMEI_CREATE);
    if (ret < 0)
        return ret;
    if (!resolved.dentry)
        return -ENOENT;
    if (!(resolved.dentry->flags & DENTRY_NEGATIVE)) {
        dentry_put(resolved.dentry);
        return -EEXIST;
    }
    if (!resolved.dentry->parent || !resolved.dentry->parent->vnode ||
        !resolved.mnt || !resolved.mnt->ops || !resolved.mnt->ops->symlink) {
        dentry_put(resolved.dentry);
        return -EOPNOTSUPP;
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
    return (int64_t)ret;
}

int64_t sys_unlink(uint64_t path_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_unlinkat((uint64_t)(int64_t)AT_FDCWD, path_ptr, 0, 0, 0, 0);
}

int64_t sys_mkdir(uint64_t path_ptr, uint64_t mode, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_mkdirat((uint64_t)(int64_t)AT_FDCWD, path_ptr, mode, 0, 0, 0);
}

int64_t sys_rmdir(uint64_t path_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_unlinkat((uint64_t)(int64_t)AT_FDCWD, path_ptr, AT_REMOVEDIR,
                        0, 0, 0);
}

int64_t sys_access(uint64_t path_ptr, uint64_t mode, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_faccessat((uint64_t)(int64_t)AT_FDCWD, path_ptr, mode, 0, 0, 0);
}
