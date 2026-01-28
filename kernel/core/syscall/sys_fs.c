/**
 * kernel/core/syscall/sys_fs.c - File-system-related syscalls
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/mm.h>
#include <kairos/namei.h>
#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
} __packed;

/* Linux riscv64 struct stat from asm-generic/stat.h. */
struct linux_stat {
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned int st_mode;
    unsigned int st_nlink;
    unsigned int st_uid;
    unsigned int st_gid;
    unsigned long st_rdev;
    unsigned long __pad1;
    long st_size;
    int st_blksize;
    int __pad2;
    long st_blocks;
    long st_atime;
    unsigned long st_atime_nsec;
    long st_mtime;
    unsigned long st_mtime_nsec;
    long st_ctime;
    unsigned long st_ctime_nsec;
    unsigned int __unused4;
    unsigned int __unused5;
};

static void stat_to_linux(const struct stat *st, struct linux_stat *lst) {
    memset(lst, 0, sizeof(*lst));
    lst->st_dev = (unsigned long)st->st_dev;
    lst->st_ino = (unsigned long)st->st_ino;
    lst->st_mode = (unsigned int)st->st_mode;
    lst->st_nlink = (unsigned int)st->st_nlink;
    lst->st_uid = (unsigned int)st->st_uid;
    lst->st_gid = (unsigned int)st->st_gid;
    lst->st_rdev = (unsigned long)st->st_rdev;
    lst->st_size = (long)st->st_size;
    lst->st_blksize = (int)st->st_blksize;
    lst->st_blocks = (long)st->st_blocks;
    lst->st_atime = (long)st->st_atime;
    lst->st_mtime = (long)st->st_mtime;
    lst->st_ctime = (long)st->st_ctime;
}

static int copy_linux_stat_to_user(uint64_t st_ptr, const struct stat *st) {
    struct linux_stat lst;
    stat_to_linux(st, &lst);
    if (copy_to_user((void *)st_ptr, &lst, sizeof(lst)) < 0)
        return -EFAULT;
    return 0;
}

static bool use_linux_abi(void) {
    struct process *p = proc_current();
    return !p || p->syscall_abi == SYSCALL_ABI_LINUX;
}

static struct dentry *proc_cwd_dentry(struct process *p) {
    if (!p)
        return NULL;
    if (!p->cwd_dentry && p->cwd[0]) {
        struct path resolved;
        path_init(&resolved);
        if (vfs_namei(p->cwd, &resolved, NAMEI_FOLLOW | NAMEI_DIRECTORY) == 0 &&
            resolved.dentry && resolved.dentry->vnode &&
            resolved.dentry->vnode->type == VNODE_DIR) {
            p->cwd_dentry = resolved.dentry;
        } else if (resolved.dentry) {
            dentry_put(resolved.dentry);
        }
    }
    return p->cwd_dentry;
}

static struct vnode *proc_cwd_vnode(struct process *p) {
    if (!p)
        return NULL;
    if (!p->cwd_vnode && p->cwd_dentry && p->cwd_dentry->vnode) {
        p->cwd_vnode = p->cwd_dentry->vnode;
        vnode_get(p->cwd_vnode);
    } else if (!p->cwd_vnode && p->cwd[0]) {
        struct vnode *vn = vfs_lookup(p->cwd);
        if (vn && vn->type == VNODE_DIR) {
            p->cwd_vnode = vn;
        } else if (vn) {
            vnode_put(vn);
        }
    }
    return p->cwd_vnode;
}

static int build_at_path(int64_t dirfd, const char *path, char *out) {
    if (!path || !out)
        return -EINVAL;
    if (path[0] == '/') {
        size_t plen = strlen(path);
        if (plen + 1 > CONFIG_PATH_MAX)
            return -ENAMETOOLONG;
        memcpy(out, path, plen + 1);
        return 0;
    }

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    char basebuf[CONFIG_PATH_MAX];
    const char *base = NULL;

    if (dirfd == AT_FDCWD) {
        struct dentry *cwd_d = proc_cwd_dentry(p);
        if (cwd_d &&
            vfs_build_path_dentry(cwd_d, basebuf, sizeof(basebuf)) >= 0) {
            base = basebuf;
        } else if (p->cwd[0]) {
            base = p->cwd;
        }
    } else {
        struct file *f = fd_get(p, (int)dirfd);
        if (!f)
            return -EBADF;
        if (!f->vnode || f->vnode->type != VNODE_DIR)
            return -ENOTDIR;
        if (f->dentry &&
            vfs_build_path_dentry(f->dentry, basebuf, sizeof(basebuf)) >= 0) {
            base = basebuf;
        } else if (f->path[0]) {
            base = f->path;
        }
    }

    if (!base)
        return -ENOENT;

    size_t blen = strlen(base);
    size_t plen = strlen(path);
    if (blen + plen + 2 > CONFIG_PATH_MAX)
        return -ENAMETOOLONG;
    memcpy(out, base, blen);
    if (blen == 0 || out[blen - 1] != '/')
        out[blen++] = '/';
    memcpy(out + blen, path, plen + 1);
    return 0;
}

static mode_t apply_umask(mode_t mode) {
    struct process *p = proc_current();
    mode_t mask = p ? p->umask : 0;
    return mode & ~mask;
}

int64_t sys_getcwd(uint64_t buf_ptr, uint64_t size, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p || !buf_ptr || size == 0)
        return -EINVAL;
    const char *src = p->cwd;
    char kpath[CONFIG_PATH_MAX];
    struct dentry *cwd_d = proc_cwd_dentry(p);
    if (cwd_d) {
        int plen = vfs_build_path_dentry(cwd_d, kpath, sizeof(kpath));
        if (plen >= 0) {
            strncpy(p->cwd, kpath, sizeof(p->cwd) - 1);
            p->cwd[sizeof(p->cwd) - 1] = '\0';
            src = p->cwd;
        }
    } else {
        struct vnode *cwd_vn = proc_cwd_vnode(p);
        if (cwd_vn) {
            int plen = vfs_build_path(cwd_vn, kpath, sizeof(kpath));
            if (plen >= 0) {
                strncpy(p->cwd, kpath, sizeof(p->cwd) - 1);
                p->cwd[sizeof(p->cwd) - 1] = '\0';
                src = p->cwd;
            }
        }
    }
    size_t len = strlen(src) + 1;
    if (len > size)
        return -ERANGE;
    if (copy_to_user((void *)buf_ptr, src, len) < 0)
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
    if (!p) {
        dentry_put(resolved.dentry);
        return -EINVAL;
    }
    if (p->cwd_vnode)
        vnode_put(p->cwd_vnode);
    if (p->cwd_dentry)
        dentry_put(p->cwd_dentry);
    p->cwd_vnode = resolved.dentry->vnode;
    vnode_get(p->cwd_vnode);
    p->cwd_dentry = resolved.dentry;
    dentry_get(p->cwd_dentry);
    if (vfs_build_path_dentry(resolved.dentry, p->cwd,
                              sizeof(p->cwd)) < 0) {
        strncpy(p->cwd, kpath, sizeof(p->cwd) - 1);
        p->cwd[sizeof(p->cwd) - 1] = '\0';
    }
    dentry_put(resolved.dentry);
    return 0;
}

int64_t sys_fchdir(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    struct file *f = fd_get(p, (int)fd);
    if (!f)
        return -EBADF;
    if (!f->vnode || f->vnode->type != VNODE_DIR)
        return -ENOTDIR;
    if (p->cwd_vnode)
        vnode_put(p->cwd_vnode);
    if (p->cwd_dentry)
        dentry_put(p->cwd_dentry);

    p->cwd_vnode = f->vnode;
    vnode_get(p->cwd_vnode);

    if (f->dentry) {
        p->cwd_dentry = f->dentry;
        dentry_get(p->cwd_dentry);
        if (vfs_build_path_dentry(f->dentry, p->cwd, sizeof(p->cwd)) < 0) {
            if (f->path[0]) {
                strncpy(p->cwd, f->path, sizeof(p->cwd) - 1);
                p->cwd[sizeof(p->cwd) - 1] = '\0';
            } else {
                p->cwd[0] = '\0';
            }
        }
        return 0;
    }

    if (f->path[0]) {
        struct path resolved;
        path_init(&resolved);
        if (vfs_namei(f->path, &resolved,
                      NAMEI_FOLLOW | NAMEI_DIRECTORY) == 0 &&
            resolved.dentry) {
            p->cwd_dentry = resolved.dentry;
            dentry_get(p->cwd_dentry);
            if (vfs_build_path_dentry(resolved.dentry, p->cwd,
                                      sizeof(p->cwd)) < 0) {
                strncpy(p->cwd, f->path, sizeof(p->cwd) - 1);
                p->cwd[sizeof(p->cwd) - 1] = '\0';
            }
            dentry_put(resolved.dentry);
            return 0;
        }
        if (resolved.dentry)
            dentry_put(resolved.dentry);
    }
    p->cwd[0] = '\0';
    return 0;
}

int64_t sys_umask(uint64_t mask, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    mode_t old = p->umask;
    p->umask = (mode_t)mask & 0777;
    return (int64_t)old;
}

int64_t sys_openat(uint64_t dirfd, uint64_t path, uint64_t flags, uint64_t mode,
                   uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    struct file *f;
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0)
        return -EFAULT;
    char full[CONFIG_PATH_MAX];
    int ret = build_at_path((int64_t)dirfd, kpath, full);
    if (ret < 0)
        return ret;
    mode_t umode = (flags & O_CREAT) ? apply_umask((mode_t)mode) : (mode_t)mode;
    ret = vfs_open_at("/", full, (int)flags, umode, &f);
    if (ret < 0)
        return ret;

    int fd = fd_alloc(proc_current(), f);
    if (fd < 0) {
        vfs_close(f);
        return -EMFILE;
    }
    return fd;
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
    char full[CONFIG_PATH_MAX];
    int ret = build_at_path((int64_t)dirfd, kpath, full);
    if (ret < 0)
        return ret;

    int nflags = NAMEI_FOLLOW;
    if (flags & AT_SYMLINK_NOFOLLOW)
        nflags = NAMEI_NOFOLLOW;

    struct path resolved;
    path_init(&resolved);
    ret = vfs_namei(full, &resolved, nflags);
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
    char full[CONFIG_PATH_MAX];
    int ret = build_at_path((int64_t)dirfd, kpath, full);
    if (ret < 0)
        return ret;

    if (flags & AT_REMOVEDIR)
        return vfs_rmdir(full);
    return vfs_unlink(full);
}

int64_t sys_mkdirat(uint64_t dirfd, uint64_t path_ptr, uint64_t mode,
                    uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path_ptr, sizeof(kpath)) < 0)
        return -EFAULT;

    mode_t umode = apply_umask((mode_t)mode);
    char full[CONFIG_PATH_MAX];
    int ret = build_at_path((int64_t)dirfd, kpath, full);
    if (ret < 0)
        return ret;
    return vfs_mkdir(full, umode);
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

    char oldfull[CONFIG_PATH_MAX];
    char newfull[CONFIG_PATH_MAX];
    int ret = build_at_path((int64_t)olddirfd, oldpath, oldfull);
    if (ret < 0)
        return ret;
    ret = build_at_path((int64_t)newdirfd, newpath, newfull);
    if (ret < 0)
        return ret;
    return vfs_rename(oldfull, newfull);
}

int64_t sys_readlinkat(uint64_t dirfd, uint64_t path_ptr, uint64_t buf_ptr,
                       uint64_t bufsz, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (!buf_ptr || bufsz == 0)
        return -EINVAL;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path_ptr, sizeof(kpath)) < 0)
        return -EFAULT;

    char kbuf[CONFIG_PATH_MAX];
    size_t klen = (bufsz < sizeof(kbuf)) ? (size_t)bufsz : sizeof(kbuf);
    char full[CONFIG_PATH_MAX];
    int ret = build_at_path((int64_t)dirfd, kpath, full);
    if (ret < 0)
        return ret;
    ssize_t rl = vfs_readlink(full, kbuf, klen);
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
    char full[CONFIG_PATH_MAX];
    int ret = build_at_path((int64_t)dirfd, linkpath, full);
    if (ret < 0)
        return ret;
    ret = vfs_symlink(target, full);
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

static int64_t sys_read_write(uint64_t fd, uint64_t buf, uint64_t count,
                              bool is_write) {
    struct file *f = fd_get(proc_current(), (int)fd);
    uint8_t kbuf[512];
    size_t done = 0;

    if (!f) {
        if (is_write && (fd == 1 || fd == 2)) {
            while (done < count) {
                size_t chunk = (count - done > sizeof(kbuf))
                                   ? sizeof(kbuf)
                                   : (size_t)(count - done);
                if (copy_from_user(kbuf, (const void *)(buf + done), chunk) < 0)
                    return done ? (int64_t)done : -EFAULT;
                for (size_t i = 0; i < chunk; i++)
                    arch_early_putchar((char)kbuf[i]);
                done += chunk;
            }
            return (int64_t)done;
        }
        return -EBADF;
    }

    while (done < count) {
        size_t chunk = (count - done > sizeof(kbuf)) ? sizeof(kbuf)
                                                     : (size_t)(count - done);
        if (is_write) {
            if (copy_from_user(kbuf, (const void *)(buf + done), chunk) < 0)
                return done ? (int64_t)done : -EFAULT;
            ssize_t n = vfs_write(f, kbuf, chunk);
            if (n < 0)
                return done ? (int64_t)done : (int64_t)n;
            if (n == 0)
                break;
            done += (size_t)n;
        } else {
            ssize_t n = vfs_read(f, kbuf, chunk);
            if (n < 0)
                return done ? (int64_t)done : (int64_t)n;
            if (n == 0)
                break;
            if (copy_to_user((void *)(buf + done), kbuf, (size_t)n) < 0)
                return done ? (int64_t)done : -EFAULT;
            done += (size_t)n;
        }
    }
    return (int64_t)done;
}

int64_t sys_read(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, false);
}

int64_t sys_write(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, true);
}

int64_t sys_close(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_close(proc_current(), (int)fd);
}

int64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    if (f->vnode && f->vnode->type == VNODE_PIPE)
        return -ESPIPE;
    return (int64_t)vfs_seek(f, (off_t)offset, (int)whence);
}

int64_t sys_stat(uint64_t path, uint64_t st_ptr, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    struct stat st;
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0)
        return -EFAULT;

    int ret = vfs_stat(kpath, &st);
    if (ret < 0)
        return ret;
    if (use_linux_abi())
        return copy_linux_stat_to_user(st_ptr, &st);
    if (copy_to_user((void *)st_ptr, &st, sizeof(st)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_fstat(uint64_t fd, uint64_t st_ptr, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;

    struct stat st;
    int ret = vfs_fstat(f, &st);
    if (ret < 0)
        return ret;
    if (use_linux_abi())
        return copy_linux_stat_to_user(st_ptr, &st);
    if (copy_to_user((void *)st_ptr, &st, sizeof(st)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_newfstatat(uint64_t dirfd, uint64_t path, uint64_t st_ptr,
                       uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (flags & ~AT_SYMLINK_NOFOLLOW)
        return -ENOSYS;

    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0)
        return -EFAULT;

    struct stat st;
    char full[CONFIG_PATH_MAX];
    int ret = build_at_path((int64_t)dirfd, kpath, full);
    if (ret < 0)
        return ret;

    int nflags = NAMEI_FOLLOW;
    if (flags & AT_SYMLINK_NOFOLLOW)
        nflags = NAMEI_NOFOLLOW;

    struct path resolved;
    path_init(&resolved);
    ret = vfs_namei(full, &resolved, nflags);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    ret = vfs_fstat(&(struct file){.vnode = resolved.dentry->vnode}, &st);
    dentry_put(resolved.dentry);
    if (ret < 0)
        return ret;
    return copy_linux_stat_to_user(st_ptr, &st);
}

int64_t sys_getdents64(uint64_t fd, uint64_t dirp, uint64_t count, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (!dirp || count == 0)
        return -EINVAL;
    if (count > 65536)
        return -EINVAL;

    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    if (!f->vnode || f->vnode->type != VNODE_DIR)
        return -ENOTDIR;

    uint8_t *kbuf = kmalloc((size_t)count);
    if (!kbuf)
        return -ENOMEM;

    size_t pos = 0;
    const size_t base = offsetof(struct linux_dirent64, d_name);

    while (pos < (size_t)count) {
        struct dirent ent;
        int ret = vfs_readdir(f, &ent);
        if (ret < 0) {
            kfree(kbuf);
            return ret;
        }
        if (ret == 0)
            break;

        size_t name_len = strlen(ent.d_name);
        size_t reclen = ALIGN_UP(base + name_len + 1, 8);
        if (pos + reclen > (size_t)count)
            break;

        struct linux_dirent64 *ld = (struct linux_dirent64 *)(kbuf + pos);
        ld->d_ino = ent.d_ino;
        ld->d_off = (int64_t)f->offset;
        ld->d_reclen = (uint16_t)reclen;
        ld->d_type = ent.d_type;
        memcpy(ld->d_name, ent.d_name, name_len);
        ld->d_name[name_len] = '\0';
        pos += reclen;
    }

    if (pos > 0 && copy_to_user((void *)dirp, kbuf, pos) < 0) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return (int64_t)pos;
}

int64_t sys_dup2(uint64_t oldfd, uint64_t newfd, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_dup2(proc_current(), (int)oldfd, (int)newfd);
}

int64_t sys_dup(uint64_t oldfd, uint64_t a1, uint64_t a2, uint64_t a3,
                uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_dup(proc_current(), (int)oldfd);
}

int64_t sys_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (flags != 0)
        return -EINVAL;
    if (oldfd == newfd)
        return -EINVAL;
    return (int64_t)fd_dup2(proc_current(), (int)oldfd, (int)newfd);
}

static int pipe_create_fds(uint64_t fd_array, uint32_t flags) {
    struct file *rf = NULL, *wf = NULL;
    int fds[2] = {-1, -1}, ret = 0;
    extern int pipe_create(struct file **read_pipe, struct file **write_pipe);

    if ((ret = pipe_create(&rf, &wf)) < 0)
        return ret;

    if (flags & O_NONBLOCK) {
        mutex_lock(&rf->lock);
        rf->flags |= O_NONBLOCK;
        mutex_unlock(&rf->lock);
        mutex_lock(&wf->lock);
        wf->flags |= O_NONBLOCK;
        mutex_unlock(&wf->lock);
    }

    if ((fds[0] = fd_alloc(proc_current(), rf)) < 0) {
        ret = -EMFILE;
        goto err;
    }
    if ((fds[1] = fd_alloc(proc_current(), wf)) < 0) {
        ret = -EMFILE;
        goto err;
    }
    if (copy_to_user((void *)fd_array, fds, sizeof(fds)) < 0) {
        ret = -EFAULT;
        goto err;
    }
    return 0;
err:
    if (fds[0] >= 0) {
        fd_close(proc_current(), fds[0]);
    } else if (rf) {
        vfs_close(rf);
    }
    if (fds[1] >= 0) {
        fd_close(proc_current(), fds[1]);
    } else if (wf) {
        vfs_close(wf);
    }
    return ret;
}

int64_t sys_pipe(uint64_t fd_array, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)pipe_create_fds(fd_array, 0);
}

int64_t sys_pipe2(uint64_t fd_array, uint64_t flags, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    uint32_t allowed = O_NONBLOCK;
    if (flags & ~allowed)
        return -EINVAL;
    return (int64_t)pipe_create_fds(fd_array, (uint32_t)flags);
}

int64_t sys_fcntl(uint64_t fd, uint64_t cmd, uint64_t arg, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;

    switch ((int)cmd) {
    case F_GETFL: {
        mutex_lock(&f->lock);
        int flags = (int)f->flags;
        mutex_unlock(&f->lock);
        return flags;
    }
    case F_SETFL: {
        uint32_t setmask = O_NONBLOCK | O_APPEND;
        mutex_lock(&f->lock);
        f->flags = (f->flags & ~setmask) | ((uint32_t)arg & setmask);
        int flags = (int)f->flags;
        mutex_unlock(&f->lock);
        return flags;
    }
    default:
        return -EINVAL;
    }
}
