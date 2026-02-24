/**
 * kernel/core/syscall/sys_fs_stat.c - Stat-related syscalls
 */

#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/mm.h>
#include <kairos/namei.h>
#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/string.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#include "sys_fs_helpers.h"

/* Linux ABI statfs layout */
struct linux_statfs {
    long f_type;
    long f_bsize;
    long f_blocks;
    long f_bfree;
    long f_bavail;
    long f_files;
    long f_ffree;
    struct { int val[2]; } f_fsid;
    long f_namelen;
    long f_frsize;
    long f_flags;
    long f_spare[4];
};

static void kstatfs_to_linux(const struct kstatfs *kst,
                             struct linux_statfs *lst) {
    memset(lst, 0, sizeof(*lst));
    lst->f_type = (long)kst->f_type;
    lst->f_bsize = (long)kst->f_bsize;
    lst->f_blocks = (long)kst->f_blocks;
    lst->f_bfree = (long)kst->f_bfree;
    lst->f_bavail = (long)kst->f_bavail;
    lst->f_files = (long)kst->f_files;
    lst->f_ffree = (long)kst->f_ffree;
    lst->f_fsid.val[0] = (int)kst->f_fsid[0];
    lst->f_fsid.val[1] = (int)kst->f_fsid[1];
    lst->f_namelen = (long)kst->f_namelen;
    lst->f_frsize = (long)kst->f_frsize;
    lst->f_flags = (long)kst->f_flags;
}

int64_t sys_statfs(uint64_t path, uint64_t buf, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!buf)
        return -EFAULT;
    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path, kpath, sizeof(kpath)) < 0)
        return -EFAULT;

    struct path resolved;
    path_init(&resolved);
    int namei_ret = sysfs_resolve_at(AT_FDCWD, kpath, &resolved, NAMEI_FOLLOW);
    if (namei_ret < 0)
        return namei_ret;
    if (!resolved.dentry || !resolved.dentry->mnt) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }

    struct kstatfs kst;
    int ret = vfs_statfs(resolved.dentry->mnt, &kst);
    dentry_put(resolved.dentry);
    if (ret < 0)
        return ret;

    struct linux_statfs lst;
    kstatfs_to_linux(&kst, &lst);
    if (copy_to_user((void *)buf, &lst, sizeof(lst)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_fstatfs(uint64_t fd, uint64_t buf, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!buf)
        return -EFAULT;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    struct mount *mnt = NULL;
    if (f->vnode && f->vnode->mount)
        mnt = f->vnode->mount;
    else if (f->dentry && f->dentry->mnt)
        mnt = f->dentry->mnt;
    if (!mnt) {
        file_put(f);
        return -EINVAL;
    }

    struct kstatfs kst;
    int ret = vfs_statfs(mnt, &kst);
    if (ret < 0) {
        file_put(f);
        return ret;
    }

    struct linux_statfs lst;
    kstatfs_to_linux(&kst, &lst);
    if (copy_to_user((void *)buf, &lst, sizeof(lst)) < 0) {
        file_put(f);
        return -EFAULT;
    }
    file_put(f);
    return 0;
}

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

struct linux_statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
};

struct linux_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __pad0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct linux_statx_timestamp stx_atime;
    struct linux_statx_timestamp stx_btime;
    struct linux_statx_timestamp stx_ctime;
    struct linux_statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t __pad1[14];
};

#define STATX_TYPE 0x00000001U
#define STATX_MODE 0x00000002U
#define STATX_NLINK 0x00000004U
#define STATX_UID 0x00000008U
#define STATX_GID 0x00000010U
#define STATX_ATIME 0x00000020U
#define STATX_MTIME 0x00000040U
#define STATX_CTIME 0x00000080U
#define STATX_INO 0x00000100U
#define STATX_SIZE 0x00000200U
#define STATX_BLOCKS 0x00000400U
#define STATX_BASIC_STATS 0x000007ffU
#define STATX_BTIME 0x00000800U
#define STATX_ALL 0x00000fffU
#define STATX__RESERVED 0x80000000U

#define AT_NO_AUTOMOUNT 0x800
#define AT_STATX_SYNC_TYPE 0x6000
#define AT_STATX_SYNC_AS_STAT 0x0000
#define AT_STATX_FORCE_SYNC 0x2000
#define AT_STATX_DONT_SYNC 0x4000

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

static void linux_statx_set_ts(struct linux_statx_timestamp *dst, time_t sec) {
    dst->tv_sec = (int64_t)sec;
    dst->tv_nsec = 0;
    dst->__reserved = 0;
}

static uint32_t dev_major(dev_t dev) {
    return (uint32_t)((dev >> 16) & 0xffffU);
}

static uint32_t dev_minor(dev_t dev) {
    return (uint32_t)(dev & 0xffffU);
}

static void stat_to_linux_statx(const struct stat *st, struct linux_statx *sx,
                                uint32_t req_mask) {
    (void)req_mask;
    memset(sx, 0, sizeof(*sx));
    sx->stx_mask = STATX_BASIC_STATS;
    sx->stx_blksize = (uint32_t)st->st_blksize;
    sx->stx_nlink = (uint32_t)st->st_nlink;
    sx->stx_uid = (uint32_t)st->st_uid;
    sx->stx_gid = (uint32_t)st->st_gid;
    sx->stx_mode = (uint16_t)st->st_mode;
    sx->stx_ino = (uint64_t)st->st_ino;
    sx->stx_size = (uint64_t)st->st_size;
    sx->stx_blocks = (uint64_t)st->st_blocks;
    linux_statx_set_ts(&sx->stx_atime, st->st_atime);
    linux_statx_set_ts(&sx->stx_btime, 0);
    linux_statx_set_ts(&sx->stx_ctime, st->st_ctime);
    linux_statx_set_ts(&sx->stx_mtime, st->st_mtime);
    sx->stx_rdev_major = dev_major(st->st_rdev);
    sx->stx_rdev_minor = dev_minor(st->st_rdev);
    sx->stx_dev_major = dev_major(st->st_dev);
    sx->stx_dev_minor = dev_minor(st->st_dev);
}

static int copy_linux_stat_to_user(uint64_t st_ptr, const struct stat *st) {
    struct linux_stat lst;
    stat_to_linux(st, &lst);
    if (copy_to_user((void *)st_ptr, &lst, sizeof(lst)) < 0)
        return -EFAULT;
    return 0;
}

static int copy_linux_statx_to_user(uint64_t stx_ptr, const struct stat *st,
                                    uint32_t req_mask) {
    struct linux_statx sx;
    stat_to_linux_statx(st, &sx, req_mask);
    if (copy_to_user((void *)stx_ptr, &sx, sizeof(sx)) < 0)
        return -EFAULT;
    return 0;
}

static bool use_linux_abi(void) {
    struct process *p = proc_current();
    return !p || p->syscall_abi == SYSCALL_ABI_LINUX;
}

int64_t sys_stat(uint64_t path, uint64_t st_ptr, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!st_ptr)
        return -EFAULT;
    char kpath[CONFIG_PATH_MAX];
    struct stat st;
    if (sysfs_copy_path(path, kpath, sizeof(kpath)) < 0)
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
    if (!st_ptr)
        return -EFAULT;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;

    struct stat st;
    int ret = vfs_fstat(f, &st);
    if (ret < 0) {
        file_put(f);
        return ret;
    }
    if (use_linux_abi()) {
        ret = copy_linux_stat_to_user(st_ptr, &st);
        file_put(f);
        return ret;
    }
    if (copy_to_user((void *)st_ptr, &st, sizeof(st)) < 0) {
        file_put(f);
        return -EFAULT;
    }
    file_put(f);
    return 0;
}

int64_t sys_newfstatat(uint64_t dirfd, uint64_t path, uint64_t st_ptr,
                       uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (!st_ptr)
        return -EFAULT;
    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
        return -EINVAL;

    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path, kpath, sizeof(kpath)) < 0)
        return -EFAULT;
    if (kpath[0] == '\0' && !(flags & AT_EMPTY_PATH))
        return -ENOENT;

    struct stat st;
    if ((flags & AT_EMPTY_PATH) && kpath[0] == '\0') {
        struct process *p = proc_current();
        if (!p)
            return -EINVAL;
        if ((int64_t)dirfd == AT_FDCWD) {
            struct vnode *cwd_vn = sysfs_proc_cwd_vnode(p);
            if (!cwd_vn)
                return -ENOENT;
            int ret = vfs_stat_vnode(cwd_vn, &st);
            if (ret < 0)
                return ret;
            return copy_linux_stat_to_user(st_ptr, &st);
        }
        struct file *f = fd_get(p, (int)dirfd);
        if (!f)
            return -EBADF;
        if (!f->vnode) {
            file_put(f);
            return -ENOENT;
        }
        int ret = vfs_stat_vnode(f->vnode, &st);
        file_put(f);
        if (ret < 0)
            return ret;
        return copy_linux_stat_to_user(st_ptr, &st);
    }

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
    ret = vfs_stat_vnode(resolved.dentry->vnode, &st);
    dentry_put(resolved.dentry);
    if (ret < 0)
        return ret;
    return copy_linux_stat_to_user(st_ptr, &st);
}

int64_t sys_statx(uint64_t dirfd, uint64_t path, uint64_t flags, uint64_t mask,
                  uint64_t stx_ptr, uint64_t a5) {
    (void)a5;
    if (!stx_ptr)
        return -EFAULT;

    uint64_t allowed_flags = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH |
                             AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE;
    if (flags & ~allowed_flags)
        return -EINVAL;

    uint64_t sync_type = flags & AT_STATX_SYNC_TYPE;
    if (sync_type != AT_STATX_SYNC_AS_STAT &&
        sync_type != AT_STATX_FORCE_SYNC &&
        sync_type != AT_STATX_DONT_SYNC)
        return -EINVAL;

    uint32_t req_mask = (uint32_t)mask;
    if (req_mask & STATX__RESERVED)
        return -EINVAL;
    if (req_mask & ~STATX_ALL)
        return -EINVAL;

    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path, kpath, sizeof(kpath)) < 0)
        return -EFAULT;
    if (kpath[0] == '\0' && !(flags & AT_EMPTY_PATH))
        return -ENOENT;

    struct stat st;
    if ((flags & AT_EMPTY_PATH) && kpath[0] == '\0') {
        struct process *p = proc_current();
        if (!p)
            return -EINVAL;
        if ((int64_t)dirfd == AT_FDCWD) {
            struct vnode *cwd_vn = sysfs_proc_cwd_vnode(p);
            if (!cwd_vn)
                return -ENOENT;
            int ret = vfs_stat_vnode(cwd_vn, &st);
            if (ret < 0)
                return ret;
            return copy_linux_statx_to_user(stx_ptr, &st, req_mask);
        }

        struct file *f = fd_get(p, (int)dirfd);
        if (!f)
            return -EBADF;
        if (!f->vnode) {
            file_put(f);
            return -ENOENT;
        }
        int ret = vfs_stat_vnode(f->vnode, &st);
        file_put(f);
        if (ret < 0)
            return ret;
        return copy_linux_statx_to_user(stx_ptr, &st, req_mask);
    }

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
    ret = vfs_stat_vnode(resolved.dentry->vnode, &st);
    dentry_put(resolved.dentry);
    if (ret < 0)
        return ret;
    return copy_linux_statx_to_user(stx_ptr, &st, req_mask);
}

int64_t sys_getdents64(uint64_t fd, uint64_t dirp, uint64_t count, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (!dirp)
        return -EINVAL;
    /* Linux ABI takes unsigned int count; ignore upper 32 bits. */
    uint32_t ucount = (uint32_t)count;
    if (ucount == 0)
        return -EINVAL;
    const size_t base = offsetof(struct linux_dirent64, d_name);
    if ((size_t)ucount < base + 1)
        return -EINVAL;

    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    if (!f->vnode || f->vnode->type != VNODE_DIR) {
        file_put(f);
        return -ENOTDIR;
    }

    uint8_t *kbuf = kmalloc((size_t)ucount);
    if (!kbuf) {
        file_put(f);
        return -ENOMEM;
    }

    size_t pos = 0;
    while (pos < (size_t)ucount) {
        struct dirent ent;
        int ret = vfs_readdir(f, &ent);
        if (ret < 0) {
            kfree(kbuf);
            file_put(f);
            return ret;
        }
        if (ret == 0)
            break;

        size_t name_len = strlen(ent.d_name);
        size_t reclen = ALIGN_UP(base + name_len + 1, 8);
        if (pos + reclen > (size_t)ucount)
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
        file_put(f);
        return -EFAULT;
    }

    kfree(kbuf);
    file_put(f);
    return (int64_t)pos;
}
