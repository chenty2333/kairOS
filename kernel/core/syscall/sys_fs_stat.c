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
    if (!st_ptr)
        return -EFAULT;
    if (flags & ~AT_SYMLINK_NOFOLLOW)
        return -EINVAL;

    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(path, kpath, sizeof(kpath)) < 0)
        return -EFAULT;

    struct stat st;
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
    if (count > 0xffffffffULL)
        return -EINVAL;
    const size_t base = offsetof(struct linux_dirent64, d_name);
    if (count < base + 1)
        return -EINVAL;

    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    if (!f->vnode || f->vnode->type != VNODE_DIR)
        return -ENOTDIR;

    if (count > (uint64_t)(size_t)-1)
        return -EINVAL;
    uint8_t *kbuf = kmalloc((size_t)count);
    if (!kbuf)
        return -ENOMEM;

    size_t pos = 0;
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
