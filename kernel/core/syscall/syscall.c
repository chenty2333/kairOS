/**
 * kernel/core/syscall/syscall.c - Optimized System Call Dispatch
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/epoll.h>
#include <kairos/epoll_internal.h>
#include <kairos/futex.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/select.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/sync.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>
#include <kairos/string.h>
#include <kairos/mm.h>

/* Forward declarations for internal implementations */
extern int do_sem_init(int count);
extern int do_sem_wait(int sem_id);
extern int do_sem_post(int sem_id);

/* --- Linux ABI helpers --- */

#define NS_PER_SEC 1000000000ULL

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_STACK 0x20000

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

struct linux_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

static uint64_t ns_to_sched_ticks(uint64_t ns) {
    uint64_t ticks = (ns * CONFIG_HZ + NS_PER_SEC - 1) / NS_PER_SEC;
    return ticks ? ticks : 1;
}

static int copy_timespec_from_user(uint64_t ptr, struct timespec *out) {
    if (!ptr || !out)
        return 0;
    if (copy_from_user(out, (const void *)ptr, sizeof(*out)) < 0)
        return -EFAULT;
    if (out->tv_sec < 0 || out->tv_nsec < 0 || out->tv_nsec >= (int64_t)NS_PER_SEC)
        return -EINVAL;
    return 1;
}

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

/* --- Process Handlers --- */

int64_t sys_exit(uint64_t status, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    proc_exit((int)status);
}

int64_t sys_fork(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_fork();
    return p ? (int64_t)p->pid : -1;
}

int64_t sys_exec(uint64_t path, uint64_t argv, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0) return -EFAULT;
    return (int64_t)proc_exec(kpath, (char *const *)argv);
}

int64_t sys_getpid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)proc_current()->pid;
}

int64_t sys_getppid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    return (int64_t)(p ? p->ppid : 0);
}

int64_t sys_getuid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    return (int64_t)(p ? p->uid : 0);
}

int64_t sys_getgid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    return (int64_t)(p ? p->gid : 0);
}

int64_t sys_setuid(uint64_t uid, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    p->uid = (uid_t)uid;
    return 0;
}

int64_t sys_setgid(uint64_t gid, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    p->gid = (gid_t)gid;
    return 0;
}

int64_t sys_wait(uint64_t pid, uint64_t status_ptr, uint64_t options, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int status = 0;
    pid_t ret = proc_wait((pid_t)pid, &status, (int)options);
    if (ret >= 0 && status_ptr) {
        if (copy_to_user((void *)status_ptr, &status, sizeof(status)) < 0) return -EFAULT;
    }
    return (int64_t)ret;
}

int64_t sys_wait4(uint64_t pid, uint64_t status_ptr, uint64_t options,
                  uint64_t rusage_ptr, uint64_t a4, uint64_t a5) {
    (void)rusage_ptr; (void)a4; (void)a5;
    return sys_wait(pid, status_ptr, options, 0, 0, 0);
}

int64_t sys_brk(uint64_t addr, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)mm_brk(proc_current()->mm, (vaddr_t)addr);
}

int64_t sys_exit_group(uint64_t status, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_exit(status, 0, 0, 0, 0, 0);
}

int64_t sys_clone(uint64_t flags, uint64_t newsp, uint64_t parent_tid,
                  uint64_t child_tid, uint64_t tls, uint64_t a5) {
    (void)newsp; (void)parent_tid; (void)child_tid; (void)tls; (void)a5;
    /*
     * Minimal clone: accept fork-like usage where only the low signal bits
     * are set (e.g., SIGCHLD).
     */
    if ((flags & ~0xffULL) != 0)
        return -ENOSYS;
    struct process *p = proc_fork();
    return p ? (int64_t)p->pid : -ENOMEM;
}

int64_t sys_getcwd(uint64_t buf_ptr, uint64_t size, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p || !buf_ptr || size == 0)
        return -EINVAL;
    size_t len = strlen(p->cwd) + 1;
    if (len > size)
        return -ERANGE;
    if (copy_to_user((void *)buf_ptr, p->cwd, len) < 0)
        return -EFAULT;
    return (int64_t)len;
}

/* --- File/IO Handlers --- */

int64_t sys_openat(uint64_t dirfd, uint64_t path, uint64_t flags, uint64_t mode,
                   uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    struct file *f;
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0)
        return -EFAULT;

    struct process *p = proc_current();
    const char *base = (kpath[0] == '/') ? "/" : (p ? p->cwd : "/");
    int64_t dfd = (int64_t)dirfd;
    if (kpath[0] != '/' && dfd != AT_FDCWD)
        return -ENOSYS;

    int ret = vfs_open_at(base, kpath, (int)flags, (mode_t)mode, &f);
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

static int64_t sys_read_write(uint64_t fd, uint64_t buf, uint64_t count, bool is_write) {
    struct file *f = fd_get(proc_current(), (int)fd);
    uint8_t kbuf[512];
    size_t done = 0;

    if (!f) {
        if (is_write && (fd == 1 || fd == 2)) {
            while (done < count) {
                size_t chunk = (count - done > sizeof(kbuf)) ? sizeof(kbuf) : (size_t)(count - done);
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
        size_t chunk = (count - done > sizeof(kbuf)) ? sizeof(kbuf) : (size_t)(count - done);
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

int64_t sys_read(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, false);
}

int64_t sys_write(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, true);
}

int64_t sys_close(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
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

int64_t sys_stat(uint64_t path, uint64_t st_ptr, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
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

int64_t sys_fstat(uint64_t fd, uint64_t st_ptr, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
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
    if (flags != 0)
        return -ENOSYS;

    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0)
        return -EFAULT;

    struct process *p = proc_current();
    const char *base = (kpath[0] == '/') ? "/" : (p ? p->cwd : "/");
    int64_t dfd = (int64_t)dirfd;
    if (kpath[0] != '/' && dfd != AT_FDCWD)
        return -ENOSYS;

    char norm[CONFIG_PATH_MAX];
    if (vfs_normalize_path(base, kpath, norm) < 0)
        return -EINVAL;

    struct stat st;
    int ret = vfs_stat(norm, &st);
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

int64_t sys_dup2(uint64_t oldfd, uint64_t newfd, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
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

int64_t sys_pipe(uint64_t fd_array, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)pipe_create_fds(fd_array, 0);
}

int64_t sys_pipe2(uint64_t fd_array, uint64_t flags, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    uint32_t allowed = O_NONBLOCK;
    if (flags & ~allowed)
        return -EINVAL;
    return (int64_t)pipe_create_fds(fd_array, (uint32_t)flags);
}

int64_t sys_fcntl(uint64_t fd, uint64_t cmd, uint64_t arg, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f) return -EBADF;

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

int64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)cmd; (void)arg; (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    return -ENOTTY;
}

/* --- Memory / Time / Futex (Linux ABI) --- */

static uint32_t prot_to_vm(uint64_t prot) {
    uint32_t vm = 0;
    if (prot & PROT_READ)
        vm |= VM_READ;
    if (prot & PROT_WRITE)
        vm |= VM_WRITE;
    if (prot & PROT_EXEC)
        vm |= VM_EXEC;
    return vm;
}

int64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                 uint64_t fd, uint64_t offset) {
    (void)fd;
    struct process *p = proc_current();
    if (!p || !p->mm || len == 0)
        return -EINVAL;

    uint32_t vm_flags = prot_to_vm(prot);
    if (flags & MAP_SHARED)
        vm_flags |= VM_SHARED;
    if (flags & MAP_STACK)
        vm_flags |= VM_STACK;

    if (flags & MAP_FIXED)
        mm_munmap(p->mm, (vaddr_t)addr, (size_t)len);

    vaddr_t mapped = mm_mmap(p->mm, (vaddr_t)addr, (size_t)len, vm_flags,
                              vm_flags, NULL, (off_t)offset);
    return mapped ? (int64_t)mapped : -ENOMEM;
}

int64_t sys_munmap(uint64_t addr, uint64_t len, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p || !p->mm)
        return -EINVAL;
    return (int64_t)mm_munmap(p->mm, (vaddr_t)addr, (size_t)len);
}

int64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p || !p->mm)
        return -EINVAL;
    return (int64_t)mm_mprotect(p->mm, (vaddr_t)addr, (size_t)len,
                                prot_to_vm(prot));
}

int64_t sys_clock_gettime(uint64_t clockid, uint64_t tp_ptr, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!tp_ptr)
        return -EINVAL;
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
        return -EINVAL;

    uint64_t ns = arch_timer_ticks_to_ns(arch_timer_ticks());
    struct timespec ts = {
        .tv_sec = (time_t)(ns / NS_PER_SEC),
        .tv_nsec = (int64_t)(ns % NS_PER_SEC),
    };
    if (copy_to_user((void *)tp_ptr, &ts, sizeof(ts)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_nanosleep(uint64_t req_ptr, uint64_t rem_ptr, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)rem_ptr; (void)a2; (void)a3; (void)a4; (void)a5;
    struct timespec req;
    int rc = copy_timespec_from_user(req_ptr, &req);
    if (rc < 0)
        return rc;
    if (rc == 0)
        return -EINVAL;

    uint64_t ns = (uint64_t)req.tv_sec * NS_PER_SEC + (uint64_t)req.tv_nsec;
    uint64_t delta = ns_to_sched_ticks(ns);
    uint64_t deadline = arch_timer_get_ticks() + delta;

    struct process *curr = proc_current();
    while (arch_timer_get_ticks() < deadline) {
        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        poll_sleep_arm(&sleep, curr, deadline);
        curr->state = PROC_SLEEPING;
        curr->wait_channel = NULL;
        schedule();
        poll_sleep_cancel(&sleep);
        if (curr->sig_pending)
            return -EINTR;
    }
    return 0;
}

int64_t sys_uname(uint64_t buf_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (!buf_ptr)
        return -EINVAL;
    struct linux_utsname uts;
    memset(&uts, 0, sizeof(uts));
    strcpy(uts.sysname, "Kairos");
    strcpy(uts.nodename, "kairos");
    strcpy(uts.release, "0.1.0");
    strcpy(uts.version, "kairos");
    strcpy(uts.machine, "riscv64");
    if (copy_to_user((void *)buf_ptr, &uts, sizeof(uts)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_futex(uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_ptr,
                  uint64_t uaddr2, uint64_t val3) {
    (void)uaddr2; (void)val3;
    uint32_t cmd = (uint32_t)(op & ~FUTEX_PRIVATE_FLAG);
    switch (cmd) {
    case FUTEX_WAIT: {
        struct timespec ts;
        struct timespec *tsp = NULL;
        int rc = copy_timespec_from_user(timeout_ptr, &ts);
        if (rc < 0)
            return rc;
        if (rc > 0)
            tsp = &ts;
        return futex_wait(uaddr, (uint32_t)val, tsp);
    }
    case FUTEX_WAKE:
        return futex_wake(uaddr, (int)val);
    default:
        return -ENOSYS;
    }
}

static int poll_check_fds(struct pollfd *fds, size_t nfds) {
    int ready = 0;
    for (size_t i = 0; i < nfds; i++) {
        fds[i].revents = 0;
        if (fds[i].fd < 0) {
            fds[i].revents = POLLNVAL;
            ready++;
            continue;
        }
        struct file *f = fd_get(proc_current(), fds[i].fd);
        if (!f) {
            fds[i].revents = POLLNVAL;
            ready++;
            continue;
        }
        uint32_t revents = (uint32_t)vfs_poll(f, (uint32_t)fds[i].events);
        fds[i].revents = (short)revents;
        if (revents)
            ready++;
    }
    return ready;
}

static void poll_unregister_waiters(struct poll_waiter *waiters, size_t nfds) {
    if (!waiters)
        return;
    for (size_t i = 0; i < nfds; i++)
        vfs_poll_unregister(&waiters[i]);
}

static void poll_register_waiters(struct pollfd *fds, struct poll_waiter *waiters,
                                  size_t nfds) {
    struct process *curr = proc_current();
    if (!waiters || !curr)
        return;

    for (size_t i = 0; i < nfds; i++) {
        waiters[i].proc = curr;
        if (fds[i].fd < 0 || fds[i].revents)
            continue;
        struct file *f = fd_get(curr, fds[i].fd);
        if (!f)
            continue;
        vfs_poll_register(f, &waiters[i], (uint32_t)fds[i].events);
    }
}

static int poll_wait_kernel(struct pollfd *fds, size_t nfds, int timeout_ms) {
    struct poll_waiter *waiters = kzalloc(nfds * sizeof(*waiters));
    if (!waiters)
        return -ENOMEM;

    uint64_t deadline = 0;
    if (timeout_ms > 0) {
        uint64_t delta = ((uint64_t)timeout_ms * CONFIG_HZ + 999) / 1000;
        if (!delta)
            delta = 1;
        deadline = arch_timer_get_ticks() + delta;
    }

    int ready;
    do {
        poll_unregister_waiters(waiters, nfds);
        ready = poll_check_fds(fds, nfds);
        if (ready || timeout_ms == 0)
            break;

        uint64_t now = arch_timer_get_ticks();
        if (deadline && now >= deadline) {
            ready = 0;
            break;
        }

        poll_register_waiters(fds, waiters, nfds);

        struct process *curr = proc_current();
        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        if (deadline)
            poll_sleep_arm(&sleep, curr, deadline);
        proc_sleep(&sleep);
        poll_sleep_cancel(&sleep);
    } while (1);

    poll_unregister_waiters(waiters, nfds);
    kfree(waiters);
    return ready;
}

int64_t sys_poll(uint64_t fds_ptr, uint64_t nfds, uint64_t timeout_ms,
                 uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (nfds == 0) return 0;
    if (nfds > 1024) return -EINVAL;

    size_t bytes = nfds * sizeof(struct pollfd);
    struct pollfd *kfds = kmalloc(bytes);
    if (!kfds) return -ENOMEM;
    if (copy_from_user(kfds, (void *)fds_ptr, bytes) < 0) {
        kfree(kfds);
        return -EFAULT;
    }

    int ready = poll_wait_kernel(kfds, (size_t)nfds, (int)timeout_ms);
    if (ready < 0) {
        kfree(kfds);
        return ready;
    }

    if (copy_to_user((void *)fds_ptr, kfds, bytes) < 0) {
        kfree(kfds);
        return -EFAULT;
    }
    kfree(kfds);
    return ready;
}

static int do_select_common(uint64_t nfds, uint64_t readfds_ptr,
                            uint64_t writefds_ptr, int timeout_ms) {
    if (nfds > FD_SETSIZE)
        return -EINVAL;

    fd_set rfds = {0}, wfds = {0};
    if (readfds_ptr &&
        copy_from_user(&rfds, (void *)readfds_ptr, sizeof(rfds)) < 0)
        return -EFAULT;
    if (writefds_ptr &&
        copy_from_user(&wfds, (void *)writefds_ptr, sizeof(wfds)) < 0)
        return -EFAULT;

    struct pollfd fds[FD_SETSIZE];
    size_t count = 0;
    for (uint64_t fd = 0; fd < nfds; fd++) {
        uint64_t mask = 1ULL << fd;
        short events = 0;
        if (readfds_ptr && (rfds.bits & mask))
            events |= POLLIN;
        if (writefds_ptr && (wfds.bits & mask))
            events |= POLLOUT;
        if (events) {
            fds[count].fd = (int)fd;
            fds[count].events = events;
            fds[count].revents = 0;
            count++;
        }
    }

    if (count == 0)
        return 0;

    int ready = poll_wait_kernel(fds, count, timeout_ms);
    if (ready < 0)
        return ready;

    if (readfds_ptr)
        rfds.bits = 0;
    if (writefds_ptr)
        wfds.bits = 0;
    for (size_t i = 0; i < count; i++) {
        if (fds[i].revents & POLLIN)
            rfds.bits |= (1ULL << fds[i].fd);
        if (fds[i].revents & POLLOUT)
            wfds.bits |= (1ULL << fds[i].fd);
    }

    if (readfds_ptr &&
        copy_to_user((void *)readfds_ptr, &rfds, sizeof(rfds)) < 0)
        ready = -EFAULT;
    if (writefds_ptr &&
        copy_to_user((void *)writefds_ptr, &wfds, sizeof(wfds)) < 0)
        ready = -EFAULT;

    return ready;
}

int64_t sys_select(uint64_t nfds, uint64_t readfds_ptr, uint64_t writefds_ptr,
                   uint64_t exceptfds_ptr, uint64_t timeout_ptr, uint64_t a5) {
    (void)exceptfds_ptr; (void)a5;

    int timeout_ms = -1;
    if (timeout_ptr) {
        struct timeval tv;
        if (copy_from_user(&tv, (void *)timeout_ptr, sizeof(tv)) < 0)
            return -EFAULT;
        if (tv.tv_sec < 0 || tv.tv_usec < 0)
            return -EINVAL;
        timeout_ms = (int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
    }

    return do_select_common(nfds, readfds_ptr, writefds_ptr, timeout_ms);
}

int64_t sys_epoll_create1(uint64_t flags, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (flags != 0)
        return -EINVAL;

    struct file *file = NULL;
    int ret = epoll_create_file(&file);
    if (ret < 0)
        return ret;

    int fd = fd_alloc(proc_current(), file);
    if (fd < 0) {
        vfs_close(file);
        return fd;
    }
    return fd;
}

int64_t sys_epoll_ctl(uint64_t epfd, uint64_t op, uint64_t fd,
                      uint64_t event_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    struct epoll_event ev = {0};

    if (op != EPOLL_CTL_DEL) {
        if (!event_ptr)
            return -EFAULT;
        if (copy_from_user(&ev, (void *)event_ptr, sizeof(ev)) < 0)
            return -EFAULT;
    }

    return epoll_ctl_fd((int)epfd, (int)op, (int)fd,
                        (op == EPOLL_CTL_DEL) ? NULL : &ev);
}

int64_t sys_epoll_wait(uint64_t epfd, uint64_t events_ptr, uint64_t maxevents,
                       uint64_t timeout_ms, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (!events_ptr || maxevents == 0 || maxevents > 1024)
        return -EINVAL;

    struct epoll_event *out = kzalloc(maxevents * sizeof(*out));
    if (!out) {
        return -ENOMEM;
    }

    int ready = epoll_wait_events((int)epfd, out, (size_t)maxevents,
                                  (int)timeout_ms);
    int64_t ret = ready;
    if (ready > 0 &&
        copy_to_user((void *)events_ptr, out,
                     (size_t)ready * sizeof(*out)) < 0)
        ret = -EFAULT;

    kfree(out);
    return ret;
}

/* --- Semaphore Handlers --- */

int64_t sys_sem_init(uint64_t count, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_init((int)count);
}

int64_t sys_sem_wait(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_wait((int)sem_id);
}

int64_t sys_sem_post(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_post((int)sem_id);
}

/* --- Linux ABI Dispatch --- */

static int linux_timespec_to_timeout_ms(uint64_t tsp_ptr, int *out_ms) {
    if (!out_ms)
        return -EINVAL;
    if (!tsp_ptr) {
        *out_ms = -1;
        return 0;
    }

    struct timespec ts;
    int rc = copy_timespec_from_user(tsp_ptr, &ts);
    if (rc < 0)
        return rc;

    uint64_t ns = (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
    uint64_t ms = (ns + 999999ULL) / 1000000ULL;
    if (ms > 0x7fffffffULL)
        ms = 0x7fffffffULL;
    *out_ms = (int)ms;
    return 0;
}

static int64_t linux_ppoll(uint64_t fds_ptr, uint64_t nfds, uint64_t tsp_ptr,
                           uint64_t sigmask_ptr, uint64_t sigsetsize,
                           uint64_t a5) {
    (void)sigmask_ptr; (void)sigsetsize; (void)a5;
    int timeout_ms = -1;
    int rc = linux_timespec_to_timeout_ms(tsp_ptr, &timeout_ms);
    if (rc < 0)
        return rc;
    return sys_poll(fds_ptr, nfds, (uint64_t)timeout_ms, 0, 0, 0);
}

static int64_t linux_pselect6(uint64_t nfds, uint64_t readfds_ptr,
                              uint64_t writefds_ptr, uint64_t exceptfds_ptr,
                              uint64_t tsp_ptr, uint64_t sigmask_ptr) {
    (void)exceptfds_ptr; (void)sigmask_ptr;
    int timeout_ms = -1;
    int rc = linux_timespec_to_timeout_ms(tsp_ptr, &timeout_ms);
    if (rc < 0)
        return rc;
    return do_select_common(nfds, readfds_ptr, writefds_ptr, timeout_ms);
}

static int64_t linux_syscall_dispatch(uint64_t num, uint64_t a0, uint64_t a1,
                                      uint64_t a2, uint64_t a3, uint64_t a4,
                                      uint64_t a5) {
    switch (num) {
    case LINUX_NR_getcwd:
        return sys_getcwd(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_epoll_create1:
        return sys_epoll_create1(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_epoll_ctl:
        return sys_epoll_ctl(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_epoll_pwait:
        return sys_epoll_wait(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_dup:
        return sys_dup(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_dup3:
        return sys_dup3(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_fcntl:
        return sys_fcntl(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_ioctl:
        return sys_ioctl(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_openat:
        return sys_openat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_close:
        return sys_close(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_pipe2:
        return sys_pipe2(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getdents64:
        return sys_getdents64(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_lseek:
        return sys_lseek(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_read:
        return sys_read(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_write:
        return sys_write(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_ppoll:
        return linux_ppoll(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_pselect6:
        return linux_pselect6(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_newfstatat:
        return sys_newfstatat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_fstat:
        return sys_fstat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_exit:
        return sys_exit(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_exit_group:
        return sys_exit_group(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_futex:
        return sys_futex(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_nanosleep:
        return sys_nanosleep(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_clock_gettime:
        return sys_clock_gettime(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_kill:
        return sys_kill(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_rt_sigaction:
        return sys_sigaction(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_rt_sigprocmask:
        return sys_sigprocmask(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_rt_sigreturn:
        return sys_sigreturn(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_setgid:
        return sys_setgid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_setuid:
        return sys_setuid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_uname:
        return sys_uname(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getpid:
        return sys_getpid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getppid:
        return sys_getppid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getuid:
        return sys_getuid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getgid:
        return sys_getgid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_brk:
        return sys_brk(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_munmap:
        return sys_munmap(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_clone:
        return sys_clone(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_mmap:
        return sys_mmap(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_mprotect:
        return sys_mprotect(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_wait4:
        return sys_wait4(a0, a1, a2, a3, a4, a5);
    default:
        return -ENOSYS;
    }
}

/* --- Table & Dispatch --- */

syscall_fn_t syscall_table[SYS_MAX] = {
    [SYS_exit]    = sys_exit,
    [SYS_fork]    = sys_fork,
    [SYS_exec]    = sys_exec,
    [SYS_getpid]  = sys_getpid,
    [SYS_wait]    = sys_wait,
    [SYS_brk]     = sys_brk,
    [SYS_open]    = sys_open,
    [SYS_read]    = sys_read,
    [SYS_write]   = sys_write,
    [SYS_close]   = sys_close,
    [SYS_stat]    = sys_stat,
    [SYS_fstat]   = sys_fstat,
    [SYS_dup2]    = sys_dup2,
    [SYS_fcntl]   = sys_fcntl,
    [SYS_pipe]    = sys_pipe,
    [SYS_pipe2]   = sys_pipe2,
    [SYS_sem_init] = sys_sem_init,
    [SYS_sem_wait] = sys_sem_wait,
    [SYS_sem_post] = sys_sem_post,
    [SYS_poll]    = sys_poll,
    [SYS_select]  = sys_select,
    [SYS_epoll_create1] = sys_epoll_create1,
    [SYS_epoll_ctl] = sys_epoll_ctl,
    [SYS_epoll_wait] = sys_epoll_wait,
    [SYS_kill]    = sys_kill,
    [SYS_sigaction] = sys_sigaction,
    [SYS_sigprocmask] = sys_sigprocmask,
    [SYS_sigreturn] = sys_sigreturn,
};

int64_t syscall_dispatch(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5) {
    struct process *p = proc_current();
    if (!p || p->syscall_abi == SYSCALL_ABI_LINUX)
        return linux_syscall_dispatch(num, a0, a1, a2, a3, a4, a5);

    if (num >= SYS_MAX || !syscall_table[num])
        return -ENOSYS;
    return syscall_table[num](a0, a1, a2, a3, a4, a5);
}

void syscall_init(void) {
    pr_info("Syscall: initialized\n");
}
