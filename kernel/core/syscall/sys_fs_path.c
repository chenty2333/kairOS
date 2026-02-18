/**
 * kernel/core/syscall/sys_fs_path.c - Path-related syscalls
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/namei.h>
#include <kairos/process.h>
#include <kairos/printk.h>
#include <kairos/syscall.h>
#include <kairos/string.h>
#include <kairos/time.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#define NS_PER_SEC 1000000000ULL
#define UTIME_NOW  ((int64_t)0x3fffffff)
#define UTIME_OMIT ((int64_t)0x3ffffffe)

static time_t current_time_sec(void)
{
    return time_now_sec();
}

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
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0)
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

int64_t sys_fchmodat(uint64_t dirfd, uint64_t path_ptr, uint64_t mode,
                     uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (flags & ~AT_SYMLINK_NOFOLLOW)
        return -EINVAL;
    if (!path_ptr)
        return -EFAULT;
    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0)
        return -EFAULT;

    int nflags = (flags & AT_SYMLINK_NOFOLLOW) ? NAMEI_NOFOLLOW : NAMEI_FOLLOW;
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
    struct vnode *vn = resolved.dentry->vnode;
    mutex_lock(&vn->lock);
    vn->mode = (vn->mode & S_IFMT) | ((mode_t)mode & 07777);
    vn->ctime = current_time_sec();
    if (resolved.mnt && resolved.mnt->ops && resolved.mnt->ops->chmod) {
        resolved.mnt->ops->chmod(vn, vn->mode);
    }
    mutex_unlock(&vn->lock);
    dentry_put(resolved.dentry);
    return 0;
}

int64_t sys_fchownat(uint64_t dirfd, uint64_t path_ptr, uint64_t owner,
                     uint64_t group, uint64_t flags, uint64_t a5) {
    (void)a5;
    if (flags & ~AT_SYMLINK_NOFOLLOW)
        return -EINVAL;
    if (!path_ptr)
        return -EFAULT;
    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0)
        return -EFAULT;

    int nflags = (flags & AT_SYMLINK_NOFOLLOW) ? NAMEI_NOFOLLOW : NAMEI_FOLLOW;
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
    struct vnode *vn = resolved.dentry->vnode;
    mutex_lock(&vn->lock);
    if (owner != (uint64_t)-1) {
        vn->uid = (uid_t)owner;
    }
    if (group != (uint64_t)-1) {
        vn->gid = (gid_t)group;
    }
    vn->ctime = current_time_sec();
    if (resolved.mnt && resolved.mnt->ops && resolved.mnt->ops->chown) {
        resolved.mnt->ops->chown(vn, vn->uid, vn->gid);
    }
    mutex_unlock(&vn->lock);
    dentry_put(resolved.dentry);
    return 0;
}

int64_t sys_utimensat(uint64_t dirfd, uint64_t path_ptr, uint64_t times_ptr,
                      uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (flags & ~AT_SYMLINK_NOFOLLOW) {
        return -EINVAL;
    }
    if (!path_ptr) {
        return -EFAULT;
    }
    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0) {
        return -EFAULT;
    }

    int nflags = (flags & AT_SYMLINK_NOFOLLOW) ? NAMEI_NOFOLLOW : NAMEI_FOLLOW;
    struct path resolved;
    path_init(&resolved);
    int ret = sysfs_resolve_at((int64_t)dirfd, kpath, &resolved, nflags);
    if (ret < 0) {
        return ret;
    }
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry) {
            dentry_put(resolved.dentry);
        }
        return -ENOENT;
    }

    struct vnode *vn = resolved.dentry->vnode;
    time_t now = current_time_sec();
    struct timespec ts[2];
    if (times_ptr) {
        if (copy_from_user(ts, (const void *)times_ptr, sizeof(ts)) < 0) {
            dentry_put(resolved.dentry);
            return -EFAULT;
        }
    } else {
        ts[0].tv_sec = now;
        ts[0].tv_nsec = 0;
        ts[1].tv_sec = now;
        ts[1].tv_nsec = 0;
    }

    mutex_lock(&vn->lock);
    if (ts[0].tv_nsec == UTIME_NOW) {
        vn->atime = now;
    } else if (ts[0].tv_nsec != UTIME_OMIT) {
        vn->atime = ts[0].tv_sec;
    }
    if (ts[1].tv_nsec == UTIME_NOW) {
        vn->mtime = now;
    } else if (ts[1].tv_nsec != UTIME_OMIT) {
        vn->mtime = ts[1].tv_sec;
    }
    vn->ctime = now;
    if (resolved.mnt && resolved.mnt->ops && resolved.mnt->ops->utimes) {
        resolved.mnt->ops->utimes(vn, &ts[0], &ts[1]);
    }
    mutex_unlock(&vn->lock);
    dentry_put(resolved.dentry);
    return 0;
}

int64_t sys_openat(uint64_t dirfd, uint64_t path, uint64_t flags, uint64_t mode,
                   uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    struct file *f;
    if (sysfs_copy_path(path, kpath, sizeof(kpath)) < 0)
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

    uint32_t fd_flags = (flags & O_CLOEXEC) ? FD_CLOEXEC : 0;
    int fd_out = fd_alloc_flags(proc_current(), f, fd_flags);
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
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0)
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

    if (mode != F_OK) {
        struct process *p = proc_current();
        uid_t uid = p ? p->uid : 0;
        gid_t gid = p ? p->gid : 0;
        struct vnode *vn = resolved.dentry->vnode;
        mode_t perms = vn->mode & 0777;
        uint32_t bits = 0;
        if (uid == vn->uid)
            bits = (perms >> 6) & 0x7;
        else if (gid == vn->gid)
            bits = (perms >> 3) & 0x7;
        else
            bits = perms & 0x7;

        if ((mode & R_OK) && !(bits & 0x4)) {
            dentry_put(resolved.dentry);
            return -EACCES;
        }
        if ((mode & W_OK) && !(bits & 0x2)) {
            dentry_put(resolved.dentry);
            return -EACCES;
        }
        if ((mode & X_OK) && !(bits & 0x1)) {
            dentry_put(resolved.dentry);
            return -EACCES;
        }
    }

    dentry_put(resolved.dentry);
    return 0;
}

int64_t sys_faccessat2(uint64_t dirfd, uint64_t path_ptr, uint64_t mode,
                       uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW))
        return -EINVAL;
    return sys_faccessat(dirfd, path_ptr, mode, flags, 0, 0);
}

int64_t sys_unlinkat(uint64_t dirfd, uint64_t path_ptr, uint64_t flags,
                     uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (flags & ~AT_REMOVEDIR)
        return -EINVAL;

    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0)
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
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0)
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

int64_t sys_mknodat(uint64_t dirfd, uint64_t path_ptr, uint64_t mode,
                    uint64_t dev, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (!path_ptr) {
        return -EFAULT;
    }
    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0) {
        return -EFAULT;
    }

    mode_t type = (mode_t)mode & S_IFMT;
    if (!type) {
        type = S_IFREG;
    }

    mode_t umode = sysfs_apply_umask((mode_t)mode);

    switch (type) {
    case S_IFREG: {
        /* Regular file: use existing O_CREAT|O_EXCL path */
        struct path base;
        path_init(&base);
        struct path *basep = NULL;
        int ret = sysfs_get_base_path((int64_t)dirfd, kpath, &base, &basep);
        if (ret < 0) {
            return ret;
        }
        struct file *f = NULL;
        ret = vfs_open_at_path(basep, kpath, O_CREAT | O_EXCL | O_WRONLY,
                               umode, &f);
        if (ret < 0) {
            return ret;
        }
        vfs_close(f);
        return 0;
    }
    case S_IFCHR:
    case S_IFBLK:
    case S_IFIFO: {
        /* Character/block device or FIFO: use vfs_ops->mknod */
        struct path resolved;
        path_init(&resolved);
        int ret = sysfs_resolve_at((int64_t)dirfd, kpath, &resolved,
                                   NAMEI_CREATE);
        if (ret < 0) {
            return ret;
        }
        if (!resolved.dentry) {
            return -ENOENT;
        }
        if (!(resolved.dentry->flags & DENTRY_NEGATIVE)) {
            dentry_put(resolved.dentry);
            return -EEXIST;
        }
        if (!resolved.dentry->parent || !resolved.dentry->parent->vnode ||
            !resolved.mnt || !resolved.mnt->ops ||
            !resolved.mnt->ops->mknod) {
            dentry_put(resolved.dentry);
            return -EOPNOTSUPP;
        }
        ret = resolved.mnt->ops->mknod(resolved.dentry->parent->vnode,
                                       resolved.dentry->name, umode,
                                       (dev_t)dev);
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
    default:
        return -EINVAL;
    }
}

int64_t sys_renameat(uint64_t olddirfd, uint64_t oldpath_ptr,
                     uint64_t newdirfd, uint64_t newpath_ptr, uint64_t a4,
                     uint64_t a5) {
    (void)a4; (void)a5;
    char oldpath[CONFIG_PATH_MAX];
    char newpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(oldpath_ptr, oldpath, sizeof(oldpath)) < 0)
        return -EFAULT;
    if (sysfs_copy_path(newpath_ptr, newpath, sizeof(newpath)) < 0)
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

int64_t sys_renameat2(uint64_t olddirfd, uint64_t oldpath_ptr,
                      uint64_t newdirfd, uint64_t newpath_ptr, uint64_t flags,
                      uint64_t a5) {
    (void)a5;
    if (flags != 0)
        return -EINVAL;
    return sys_renameat(olddirfd, oldpath_ptr, newdirfd, newpath_ptr, 0, 0);
}

int64_t sys_readlinkat(uint64_t dirfd, uint64_t path_ptr, uint64_t buf_ptr,
                       uint64_t bufsz, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (!buf_ptr)
        return -EFAULT;
    if (bufsz == 0)
        return -EINVAL;
    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0)
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
    if (sysfs_copy_path(target_ptr, target, sizeof(target)) < 0)
        return -EFAULT;
    if (sysfs_copy_path(linkpath_ptr, linkpath, sizeof(linkpath)) < 0)
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

int64_t sys_truncate(uint64_t path_ptr, uint64_t length, uint64_t a2,
                     uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if ((int64_t)length < 0)
        return -EINVAL;
    if (!path_ptr)
        return -EFAULT;
    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path_ptr, kpath, sizeof(kpath)) < 0)
        return -EFAULT;

    struct path resolved;
    path_init(&resolved);
    int ret = sysfs_resolve_at(AT_FDCWD, kpath, &resolved, NAMEI_FOLLOW);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }

    struct vnode *vn = resolved.dentry->vnode;
    if (vn->type == VNODE_DIR) {
        dentry_put(resolved.dentry);
        return -EISDIR;
    }
    if (!vn->ops || !vn->ops->truncate) {
        dentry_put(resolved.dentry);
        return -EINVAL;
    }

    ret = vn->ops->truncate(vn, (off_t)length);
    dentry_put(resolved.dentry);
    return ret;
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

int64_t sys_linkat(uint64_t olddirfd, uint64_t oldpath_ptr,
                   uint64_t newdirfd, uint64_t newpath_ptr,
                   uint64_t flags, uint64_t a5) {
    (void)a5;
    /* AT_EMPTY_PATH (0x1000) is the only supported flag besides
     * AT_SYMLINK_FOLLOW (0x400) */
    if (flags & ~(AT_SYMLINK_NOFOLLOW | 0x400)) {
        return -EINVAL;
    }

    char oldpath[CONFIG_PATH_MAX];
    char newpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(oldpath_ptr, oldpath, sizeof(oldpath)) < 0) {
        return -EFAULT;
    }
    if (sysfs_copy_path(newpath_ptr, newpath, sizeof(newpath)) < 0) {
        return -EFAULT;
    }

    /* Resolve old path (target of the link) */
    int nflags = (flags & 0x400) ? NAMEI_FOLLOW : 0; /* AT_SYMLINK_FOLLOW */
    struct path oldp;
    path_init(&oldp);
    int ret = sysfs_resolve_at((int64_t)olddirfd, oldpath, &oldp, nflags);
    if (ret < 0) {
        return ret;
    }
    if (!oldp.dentry || !oldp.dentry->vnode) {
        if (oldp.dentry) {
            dentry_put(oldp.dentry);
        }
        return -ENOENT;
    }

    struct vnode *target = oldp.dentry->vnode;

    /* Cannot hardlink directories */
    if (target->type == VNODE_DIR) {
        dentry_put(oldp.dentry);
        return -EPERM;
    }

    /* Resolve new path (where the link will be created) */
    struct path newp;
    path_init(&newp);
    ret = sysfs_resolve_at((int64_t)newdirfd, newpath, &newp, NAMEI_CREATE);
    if (ret < 0) {
        dentry_put(oldp.dentry);
        return ret;
    }
    if (!newp.dentry) {
        dentry_put(oldp.dentry);
        return -ENOENT;
    }
    if (!(newp.dentry->flags & DENTRY_NEGATIVE)) {
        dentry_put(oldp.dentry);
        dentry_put(newp.dentry);
        return -EEXIST;
    }

    /* Must be on same mount */
    if (!oldp.mnt || !newp.mnt || oldp.mnt != newp.mnt) {
        dentry_put(oldp.dentry);
        dentry_put(newp.dentry);
        return -EXDEV;
    }

    /* Filesystem must support link */
    if (!newp.mnt->ops || !newp.mnt->ops->link) {
        dentry_put(oldp.dentry);
        dentry_put(newp.dentry);
        return -EOPNOTSUPP;
    }

    ret = newp.mnt->ops->link(newp.dentry->parent->vnode,
                              newp.dentry->name, target);
    if (ret == 0) {
        mutex_lock(&target->lock);
        target->nlink++;
        target->ctime = current_time_sec();
        mutex_unlock(&target->lock);
        /* Re-lookup and attach the new dentry */
        struct vnode *vn =
            newp.mnt->ops->lookup(newp.dentry->parent->vnode,
                                  newp.dentry->name);
        if (vn) {
            dentry_add(newp.dentry, vn);
            vnode_put(vn);
        }
    }

    dentry_put(oldp.dentry);
    dentry_put(newp.dentry);
    return ret;
}
