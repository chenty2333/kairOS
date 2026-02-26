/**
 * kernel/core/tests/vfs_ipc_tests.c - VFS/tmpfs/pipe/epoll semantic tests
 */

#include <kairos/epoll.h>
#include <kairos/epoll_internal.h>
#include <kairos/inotify.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/handle.h>
#include <kairos/mm.h>
#include <kairos/pipe.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/select.h>
#include <kairos/signal.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/time.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#if CONFIG_KERNEL_TESTS

#define VFS_IPC_MNT "/tmp/.kairos_vfs_ipc"
#define VFS_IPC_UMOUNT_ABI_MNT "/tmp/.kairos_umount_abi"
#define TEST_EFD_SEMAPHORE 0x1U
#define TEST_TFD_TIMER_ABSTIME 0x1U
#define TEST_TFD_TIMER_CANCEL_ON_SET 0x2U
#define TEST_NS_PER_SEC 1000000000ULL
#define TEST_UTC_2015_01_01_SEC 1420070400ULL
#define TEST_UTC_2017_01_01_SEC 1483228800ULL
#define TEST_RESOLVE_NO_MAGICLINKS 0x02U
#define TEST_RESOLVE_BENEATH 0x08U
#define TEST_RENAME_NOREPLACE 0x01U
#define TEST_CLOSE_RANGE_CLOEXEC (1U << 2)
#define TEST_RWF_DSYNC 0x00000002U
#define TEST_RWF_NOWAIT 0x00000008U
#define TEST_STATX_MODE 0x00000002U
#define TEST_STATX_SIZE 0x00000200U
#define TEST_STATX_BASIC_STATS 0x000007ffU
#define TEST_STATX__RESERVED 0x80000000U
#define TEST_AT_STATX_SYNC_AS_STAT 0x0000
#define TEST_MONO_PROGRESS_MAX_SPINS 200000U

static int tests_failed;

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("vfs_ipc_tests: %s failed\n", name);
        tests_failed++;
    }
}

static void close_file_if_open(struct file **f) {
    if (f && *f) {
        vfs_close(*f);
        *f = NULL;
    }
}

static void close_fd_if_open(int *fd) {
    if (!fd || *fd < 0)
        return;
    (void)fd_close(proc_current(), *fd);
    *fd = -1;
}

static uint64_t abs_diff_u64(uint64_t a, uint64_t b) {
    return (a >= b) ? (a - b) : (b - a);
}

static int64_t signed_delta_ns(uint64_t lhs, uint64_t rhs) {
    if (lhs >= rhs) {
        uint64_t d = lhs - rhs;
        if (d > (uint64_t)INT64_MAX)
            return INT64_MAX;
        return (int64_t)d;
    }
    uint64_t d = rhs - lhs;
    if (d > (uint64_t)INT64_MAX)
        return -INT64_MAX;
    return -(int64_t)d;
}

static uint64_t apply_signed_offset(uint64_t base, int64_t off) {
    if (off >= 0) {
        uint64_t uoff = (uint64_t)off;
        if (base > UINT64_MAX - uoff)
            return UINT64_MAX;
        return base + uoff;
    }
    uint64_t neg = (uint64_t)(-off);
    return (base > neg) ? (base - neg) : 0;
}

static uint64_t timespec_to_ns_u64(const struct timespec *ts) {
    if (!ts || ts->tv_sec < 0 || ts->tv_nsec < 0)
        return 0;
    uint64_t sec = (uint64_t)ts->tv_sec;
    if (sec > UINT64_MAX / TEST_NS_PER_SEC)
        return UINT64_MAX;
    uint64_t ns = sec * TEST_NS_PER_SEC;
    uint64_t nsec = (uint64_t)ts->tv_nsec;
    if (UINT64_MAX - ns < nsec)
        return UINT64_MAX;
    return ns + nsec;
}

static ssize_t fd_read_once(int fd, void *buf, size_t len) {
    struct file *f = fd_get(proc_current(), fd);
    if (!f)
        return -EBADF;
    ssize_t ret = vfs_read(f, buf, len);
    file_put(f);
    return ret;
}

static ssize_t fd_write_once(int fd, const void *buf, size_t len) {
    struct file *f = fd_get(proc_current(), fd);
    if (!f)
        return -EBADF;
    ssize_t ret = vfs_write(f, buf, len);
    file_put(f);
    return ret;
}

static void fd_set_nonblock(int fd, bool enabled) {
    struct file *f = fd_get(proc_current(), fd);
    if (!f)
        return;
    mutex_lock(&f->lock);
    if (enabled)
        f->flags |= O_NONBLOCK;
    else
        f->flags &= ~O_NONBLOCK;
    mutex_unlock(&f->lock);
    file_put(f);
}

static off_t fd_get_offset(int fd) {
    struct file *f = fd_get(proc_current(), fd);
    if (!f)
        return (off_t)-1;
    off_t off = 0;
    mutex_lock(&f->lock);
    off = f->offset;
    mutex_unlock(&f->lock);
    file_put(f);
    return off;
}

static off_t fd_set_offset(int fd, off_t off, int whence) {
    struct file *f = fd_get(proc_current(), fd);
    if (!f)
        return (off_t)-1;
    off_t ret = vfs_seek(f, off, whence);
    file_put(f);
    return ret;
}

static bool fd_has_cloexec(int fd) {
    struct process *p = proc_current();
    if (!p || !p->fdtable || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC)
        return false;
    bool cloexec = false;
    mutex_lock(&p->fdtable->lock);
    cloexec = (p->fdtable->fd_flags[fd] & FD_CLOEXEC) != 0;
    mutex_unlock(&p->fdtable->lock);
    return cloexec;
}

struct user_map_ctx {
    struct process *proc;
    struct mm_struct *saved_mm;
    struct mm_struct *active_mm;
    struct mm_struct *temp_mm;
    paddr_t saved_pgdir;
    vaddr_t base;
    size_t len;
    bool switched_pgdir;
};

struct test_linux_itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

struct test_linux_signalfd_siginfo {
    uint32_t ssi_signo;
    uint8_t pad[124];
};

struct test_linux_inotify_event {
    int32_t wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len;
};

struct test_linux_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

struct test_iovec {
    void *iov_base;
    size_t iov_len;
};

struct test_linux_statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
};

struct test_linux_statx {
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
    struct test_linux_statx_timestamp stx_atime;
    struct test_linux_statx_timestamp stx_btime;
    struct test_linux_statx_timestamp stx_ctime;
    struct test_linux_statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t __pad1[14];
};

struct test_pselect_sigset {
    uint64_t sigmask;
    uint64_t sigsetsize;
};

static int user_map_begin(struct user_map_ctx *ctx, size_t len) {
    if (!ctx || len == 0)
        return -EINVAL;

    memset(ctx, 0, sizeof(*ctx));
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    ctx->proc = p;
    ctx->saved_mm = p->mm;
    ctx->active_mm = p->mm;
    ctx->saved_pgdir = arch_mmu_current();

    if (!ctx->active_mm) {
        ctx->temp_mm = mm_create();
        if (!ctx->temp_mm)
            return -ENOMEM;
        p->mm = ctx->temp_mm;
        ctx->active_mm = ctx->temp_mm;
    }

    if (ctx->saved_pgdir != ctx->active_mm->pgdir) {
        arch_mmu_switch(ctx->active_mm->pgdir);
        ctx->switched_pgdir = true;
    }

    int rc = mm_mmap(ctx->active_mm, 0, len, VM_READ | VM_WRITE, 0, NULL, 0,
                     false, &ctx->base);
    if (rc < 0) {
        if (ctx->switched_pgdir)
            arch_mmu_switch(ctx->saved_pgdir);
        if (ctx->temp_mm) {
            p->mm = ctx->saved_mm;
            mm_destroy(ctx->temp_mm);
        }
        memset(ctx, 0, sizeof(*ctx));
        return rc;
    }
    ctx->len = len;
    return 0;
}

static void user_map_end(struct user_map_ctx *ctx) {
    if (!ctx || !ctx->proc)
        return;
    if (ctx->active_mm && ctx->base && ctx->len)
        (void)mm_munmap(ctx->active_mm, ctx->base, ctx->len);
    if (ctx->switched_pgdir)
        arch_mmu_switch(ctx->saved_pgdir);
    if (ctx->temp_mm) {
        ctx->proc->mm = ctx->saved_mm;
        mm_destroy(ctx->temp_mm);
    }
    memset(ctx, 0, sizeof(*ctx));
}

static void *user_map_ptr(const struct user_map_ctx *ctx, size_t off) {
    if (!ctx || off >= ctx->len)
        return NULL;
    return (void *)(ctx->base + off);
}

static ssize_t fd_read_until_ready(int fd, void *buf, size_t len,
                                   uint64_t timeout_ns) {
    uint64_t deadline = time_now_ns() + timeout_ns;
    while (time_now_ns() < deadline) {
        ssize_t rd = fd_read_once(fd, buf, len);
        if (rd != -EAGAIN)
            return rd;
        proc_yield();
    }
    return -EAGAIN;
}

static bool wait_pid_exit_bounded(pid_t pid, uint64_t timeout_ns,
                                  int *status_out) {
    int status = 0;
    uint64_t deadline = time_now_ns() + timeout_ns;
    while (time_now_ns() < deadline) {
        pid_t got = proc_wait(pid, &status, WNOHANG);
        if (got == pid) {
            if (status_out)
                *status_out = status;
            return true;
        }
        if (got < 0)
            return false;
        proc_yield();
    }
    return false;
}

static bool inotify_buffer_has_event(const uint8_t *buf, size_t len, int wd,
                                     uint32_t mask, const char *name) {
    if (!buf)
        return false;

    size_t off = 0;
    while (off + sizeof(struct test_linux_inotify_event) <= len) {
        const struct test_linux_inotify_event *ev =
            (const struct test_linux_inotify_event *)(buf + off);
        size_t need = sizeof(*ev) + (size_t)ev->len;
        if (need < sizeof(*ev) || off + need > len)
            break;

        bool wd_ok = (wd < 0) || (ev->wd == wd);
        bool mask_ok = (ev->mask & mask) == mask;
        bool name_ok = true;
        if (name) {
            if (ev->len == 0) {
                name_ok = false;
            } else {
                const char *ev_name = (const char *)(buf + off + sizeof(*ev));
                size_t name_len = strnlen(name, CONFIG_NAME_MAX - 1);
                size_t ev_len = strnlen(ev_name, ev->len);
                name_ok = (ev_len == name_len) &&
                          (memcmp(ev_name, name, name_len) == 0);
            }
        }
        if (wd_ok && mask_ok && name_ok)
            return true;
        off += need;
    }
    return false;
}

static bool inotify_wait_event(int ifd, int wd, uint32_t mask, const char *name,
                               uint64_t timeout_ns) {
    uint8_t buf[512];
    uint64_t deadline = time_now_ns() + timeout_ns;
    while (time_now_ns() < deadline) {
        ssize_t rd = fd_read_once(ifd, buf, sizeof(buf));
        if (rd == -EAGAIN) {
            proc_yield();
            continue;
        }
        if (rd <= 0)
            return false;
        if (inotify_buffer_has_event(buf, (size_t)rd, wd, mask, name))
            return true;
    }
    return false;
}

static void test_monotonic_progress_under_yield(void) {
    uint64_t start = time_now_ns();
    bool progressed = false;
    for (uint32_t i = 0; i < TEST_MONO_PROGRESS_MAX_SPINS; i++) {
        uint64_t now = time_now_ns();
        if (now > start) {
            progressed = true;
            break;
        }
        proc_yield();
    }
    test_check(progressed, "clock monotonic progresses under yield");
}

static int prepare_tmpfs_mount(void) {
    struct stat st;
    int ret = vfs_stat("/tmp", &st);
    if (ret < 0 || !S_ISDIR(st.st_mode))
        return -ENOENT;

    (void)vfs_umount(VFS_IPC_MNT);
    (void)vfs_rmdir(VFS_IPC_MNT);

    ret = vfs_mkdir(VFS_IPC_MNT, 0755);
    if (ret < 0 && ret != -EEXIST)
        return ret;

    ret = vfs_mount(NULL, VFS_IPC_MNT, "tmpfs", 0);
    return ret;
}

static void cleanup_tmpfs_mount(void) {
    (void)vfs_umount(VFS_IPC_MNT);
    (void)vfs_rmdir(VFS_IPC_MNT);
}

static bool epoll_has_event(const struct epoll_event *events, int n,
                            uint64_t data, uint32_t mask) {
    for (int i = 0; i < n; i++) {
        if (events[i].data == data && (events[i].events & mask) == mask)
            return true;
    }
    return false;
}

static void test_tmpfs_vfs_semantics(void) {
    static const char payload[] = "alpha-beta-gamma";
    static const char patched[] = "alpha+++ta-gamma";
    struct file *f = NULL;
    struct stat st;
    char buf[64];
    int ret;

    ret = prepare_tmpfs_mount();
    test_check(ret == 0, "tmpfs mount");
    if (ret < 0)
        return;

    do {
        ret = vfs_mkdir(VFS_IPC_MNT "/a", 0755);
        test_check(ret == 0, "tmpfs mkdir a");
        if (ret < 0)
            break;

        ret = vfs_mkdir(VFS_IPC_MNT "/b", 0755);
        test_check(ret == 0, "tmpfs mkdir b");
        if (ret < 0)
            break;

        ret = vfs_open(VFS_IPC_MNT "/a/file.txt", O_CREAT | O_RDWR | O_TRUNC,
                       0644, &f);
        test_check(ret == 0, "tmpfs open create");
        if (ret < 0)
            break;

        ssize_t wr = vfs_write(f, payload, sizeof(payload) - 1);
        test_check(wr == (ssize_t)(sizeof(payload) - 1), "tmpfs write full");

        off_t off = vfs_seek(f, 0, SEEK_SET);
        test_check(off == 0, "tmpfs seek zero");
        memset(buf, 0, sizeof(buf));
        ssize_t rd = vfs_read(f, buf, sizeof(payload) - 1);
        test_check(rd == (ssize_t)(sizeof(payload) - 1), "tmpfs read back");
        test_check(memcmp(buf, payload, sizeof(payload) - 1) == 0,
                   "tmpfs read matches");

        off = vfs_seek(f, 5, SEEK_SET);
        test_check(off == 5, "tmpfs seek patch");
        wr = vfs_write(f, "+++", 3);
        test_check(wr == 3, "tmpfs patch write");
        close_file_if_open(&f);

        ret = vfs_rename(VFS_IPC_MNT "/a/file.txt", VFS_IPC_MNT "/b/file2.txt");
        test_check(ret == 0, "tmpfs rename cross dir");

        ret = vfs_stat(VFS_IPC_MNT "/a/file.txt", &st);
        test_check(ret == -ENOENT, "tmpfs old path gone");

        ret = vfs_open(VFS_IPC_MNT "/b/file2.txt", O_RDONLY, 0, &f);
        test_check(ret == 0, "tmpfs open renamed");
        if (ret < 0)
            break;
        memset(buf, 0, sizeof(buf));
        rd = vfs_read(f, buf, sizeof(patched) - 1);
        test_check(rd == (ssize_t)(sizeof(patched) - 1), "tmpfs read renamed");
        test_check(memcmp(buf, patched, sizeof(patched) - 1) == 0,
                   "tmpfs patched content");
        close_file_if_open(&f);

        ret = vfs_open(VFS_IPC_MNT "/b/file2.txt", O_WRONLY | O_TRUNC, 0, &f);
        test_check(ret == 0, "tmpfs open trunc");
        close_file_if_open(&f);
        if (ret < 0)
            break;

        ret = vfs_stat(VFS_IPC_MNT "/b/file2.txt", &st);
        test_check(ret == 0, "tmpfs stat truncated");
        if (ret == 0)
            test_check(st.st_size == 0, "tmpfs trunc size zero");

        ret = vfs_unlink(VFS_IPC_MNT "/b/file2.txt");
        test_check(ret == 0, "tmpfs unlink file");
        ret = vfs_stat(VFS_IPC_MNT "/b/file2.txt", &st);
        test_check(ret == -ENOENT, "tmpfs unlinked gone");

        ret = vfs_rmdir(VFS_IPC_MNT "/a");
        test_check(ret == 0, "tmpfs rmdir a");
        ret = vfs_rmdir(VFS_IPC_MNT "/b");
        test_check(ret == 0, "tmpfs rmdir b");
    } while (0);

    close_file_if_open(&f);
    cleanup_tmpfs_mount();
}

static void test_umount2_flag_width_semantics(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int ret = 0;

    (void)vfs_umount(VFS_IPC_UMOUNT_ABI_MNT);
    (void)vfs_rmdir(VFS_IPC_UMOUNT_ABI_MNT);

    ret = vfs_mkdir(VFS_IPC_UMOUNT_ABI_MNT, 0755);
    test_check(ret == 0 || ret == -EEXIST, "umount2 width mkdir");
    if (ret < 0 && ret != -EEXIST)
        return;

    ret = vfs_mount(NULL, VFS_IPC_UMOUNT_ABI_MNT, "tmpfs", 0);
    test_check(ret == 0, "umount2 width mount");
    if (ret < 0)
        goto out;

    ret = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "umount2 width user map");
    if (ret < 0)
        goto out;
    mapped = true;

    char *u_path = (char *)user_map_ptr(&um, 0x0);
    test_check(u_path != NULL, "umount2 width user path ptr");
    if (!u_path)
        goto out;

    ret = copy_to_user(u_path, VFS_IPC_UMOUNT_ABI_MNT,
                       strlen(VFS_IPC_UMOUNT_ABI_MNT) + 1);
    test_check(ret == 0, "umount2 width copy path");
    if (ret < 0)
        goto out;

    int64_t ret64 = sys_umount2((uint64_t)u_path, (1ULL << 32) | 1ULL, 0, 0, 0,
                                0);
    test_check(ret64 == -EOPNOTSUPP, "umount2 width low32 mnt_force");

    ret64 = sys_umount2((uint64_t)u_path, 1ULL << 32, 0, 0, 0, 0);
    test_check(ret64 == 0, "umount2 width high32 ignored");

out:
    if (mapped)
        user_map_end(&um);
    (void)vfs_umount(VFS_IPC_UMOUNT_ABI_MNT);
    (void)vfs_rmdir(VFS_IPC_UMOUNT_ABI_MNT);
}

static void test_openat2_faccessat2_fchmodat2_syscall_semantics(void) {
    const char path[] = VFS_IPC_MNT "/openat2_file.txt";
    struct user_map_ctx um = {0};
    struct stat st;
    bool mounted = false;
    bool mapped = false;
    int fd = -1;

    int ret = prepare_tmpfs_mount();
    test_check(ret == 0, "openat2 mount");
    if (ret < 0)
        return;
    mounted = true;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "openat2 user map");
    if (rc < 0)
        goto out;
    mapped = true;

    struct test_linux_open_how *u_how =
        (struct test_linux_open_how *)user_map_ptr(&um, 0);
    char *u_path = (char *)user_map_ptr(&um, 128);
    char *u_empty = (char *)user_map_ptr(&um, 384);
    test_check(u_how != NULL, "openat2 u_how");
    test_check(u_path != NULL, "openat2 u_path");
    test_check(u_empty != NULL, "openat2 u_empty");
    if (!u_how || !u_path || !u_empty)
        goto out;

    rc = copy_to_user(u_path, path, sizeof(path));
    test_check(rc == 0, "openat2 copy path");
    rc = copy_to_user(u_empty, "", 1);
    test_check(rc == 0, "openat2 copy empty");
    if (rc < 0)
        goto out;

    int64_t ret64 =
        sys_openat2((uint64_t)AT_FDCWD, (uint64_t)u_path, 0,
                    sizeof(struct test_linux_open_how), 0, 0);
    test_check(ret64 == -EFAULT, "openat2 null how efault");

    struct test_linux_open_how how = {
        .flags = O_CREAT | O_RDWR | O_CLOEXEC,
        .mode = 0640,
        .resolve = TEST_RESOLVE_NO_MAGICLINKS,
    };
    rc = copy_to_user(u_how, &how, sizeof(how));
    test_check(rc == 0, "openat2 copy how");
    if (rc < 0)
        goto out;

    ret64 = sys_openat2((uint64_t)AT_FDCWD, (uint64_t)u_path, (uint64_t)u_how,
                        sizeof(struct test_linux_open_how) - 1, 0, 0);
    test_check(ret64 == -EINVAL, "openat2 small size einval");

    how.flags = 1ULL << 33;
    rc = copy_to_user(u_how, &how, sizeof(how));
    test_check(rc == 0, "openat2 copy bad flags");
    if (rc == 0) {
        ret64 = sys_openat2((uint64_t)AT_FDCWD, (uint64_t)u_path,
                            (uint64_t)u_how, sizeof(how), 0, 0);
        test_check(ret64 == -EINVAL, "openat2 flags width einval");
    }

    how.flags = O_RDWR;
    how.mode = 0600;
    how.resolve = 0;
    rc = copy_to_user(u_how, &how, sizeof(how));
    test_check(rc == 0, "openat2 copy mode without create");
    if (rc == 0) {
        ret64 = sys_openat2((uint64_t)AT_FDCWD, (uint64_t)u_path,
                            (uint64_t)u_how, sizeof(how), 0, 0);
        test_check(ret64 == -EINVAL, "openat2 mode without create einval");
    }

    how.flags = O_CREAT | O_RDWR;
    how.mode = 0644;
    how.resolve = TEST_RESOLVE_BENEATH;
    rc = copy_to_user(u_how, &how, sizeof(how));
    test_check(rc == 0, "openat2 copy unsupported resolve");
    if (rc == 0) {
        ret64 = sys_openat2((uint64_t)AT_FDCWD, (uint64_t)u_path,
                            (uint64_t)u_how, sizeof(how), 0, 0);
        test_check(ret64 == -EOPNOTSUPP, "openat2 resolve eopnotsupp");
    }

    how.flags = O_CREAT | O_RDWR;
    how.mode = 0644;
    how.resolve = 1ULL << 31;
    rc = copy_to_user(u_how, &how, sizeof(how));
    test_check(rc == 0, "openat2 copy unknown resolve");
    if (rc == 0) {
        ret64 = sys_openat2((uint64_t)AT_FDCWD, (uint64_t)u_path,
                            (uint64_t)u_how, sizeof(how), 0, 0);
        test_check(ret64 == -EINVAL, "openat2 unknown resolve einval");
    }

    how.flags = O_CREAT | O_RDWR | O_CLOEXEC;
    how.mode = 0640;
    how.resolve = 0;
    rc = copy_to_user(u_how, &how, sizeof(how));
    test_check(rc == 0, "openat2 copy valid");
    if (rc < 0)
        goto out;

    uint8_t one = 1;
    rc = copy_to_user((uint8_t *)u_how + sizeof(how), &one, 1);
    test_check(rc == 0, "openat2 copy nonzero tail");
    if (rc == 0) {
        ret64 = sys_openat2((uint64_t)AT_FDCWD, (uint64_t)u_path,
                            (uint64_t)u_how, sizeof(how) + 1, 0, 0);
        test_check(ret64 == -E2BIG, "openat2 nonzero tail e2big");
    }

    uint8_t zero = 0;
    rc = copy_to_user((uint8_t *)u_how + sizeof(how), &zero, 1);
    test_check(rc == 0, "openat2 clear tail");
    if (rc < 0)
        goto out;

    ret64 = sys_openat2((uint64_t)AT_FDCWD, (uint64_t)u_path, (uint64_t)u_how,
                        sizeof(how) + 1, 0, 0);
    test_check(ret64 >= 0, "openat2 create ok");
    if (ret64 >= 0)
        fd = (int)ret64;
    if (fd < 0)
        goto out;

    test_check(fd_has_cloexec(fd), "openat2 cloexec set");

    ret64 = sys_faccessat2((uint64_t)fd, (uint64_t)u_empty, R_OK,
                           AT_EMPTY_PATH | 0x4U, 0, 0);
    test_check(ret64 == -EINVAL, "faccessat2 bad flags einval");

    ret64 = sys_faccessat2((uint64_t)fd, (uint64_t)u_empty, 0x80U,
                           AT_EMPTY_PATH, 0, 0);
    test_check(ret64 == -EINVAL, "faccessat2 bad mode einval");

    ret64 = sys_faccessat2((uint64_t)fd, (uint64_t)u_empty, R_OK,
                           AT_EMPTY_PATH, 0, 0);
    test_check(ret64 == 0, "faccessat2 empty path ok");

    ret64 = sys_faccessat2((uint64_t)fd, (uint64_t)u_empty, R_OK,
                           (1ULL << 32) | AT_EMPTY_PATH, 0, 0);
    test_check(ret64 == 0, "faccessat2 flags width");

    ret64 = sys_fchmodat2((uint64_t)fd, 0, 0600, AT_EMPTY_PATH, 0, 0);
    test_check(ret64 == -EFAULT, "fchmodat2 null path efault");

    ret64 = sys_fchmodat2((uint64_t)fd, (uint64_t)u_empty, 0600, 0x4U, 0, 0);
    test_check(ret64 == -EINVAL, "fchmodat2 bad flags einval");

    ret64 =
        sys_fchmodat2((uint64_t)fd, (uint64_t)u_empty, 0600, AT_EMPTY_PATH, 0, 0);
    test_check(ret64 == 0, "fchmodat2 empty path ok");
    if (ret64 == 0) {
        ret = vfs_stat(path, &st);
        test_check(ret == 0, "fchmodat2 stat after chmod");
        if (ret == 0)
            test_check((st.st_mode & 0777) == 0600, "fchmodat2 mode 0600");
    }

    ret64 = sys_fchmodat2((uint64_t)fd, (uint64_t)u_empty, 0640,
                          (1ULL << 32) | AT_EMPTY_PATH, 0, 0);
    test_check(ret64 == 0, "fchmodat2 flags width");
    if (ret64 == 0) {
        ret = vfs_stat(path, &st);
        test_check(ret == 0, "fchmodat2 stat after width");
        if (ret == 0)
            test_check((st.st_mode & 0777) == 0640, "fchmodat2 mode 0640");
    }

out:
    close_fd_if_open(&fd);
    if (mapped)
        user_map_end(&um);
    if (mounted)
        cleanup_tmpfs_mount();
}

static void test_preadv2_pwritev2_syscall_semantics(void) {
    const char path[] = VFS_IPC_MNT "/rwv2_file.bin";
    struct user_map_ctx um = {0};
    bool mounted = false;
    bool mapped = false;
    struct file *f = NULL;
    int fd = -1;

    int ret = prepare_tmpfs_mount();
    test_check(ret == 0, "rwv2 mount");
    if (ret < 0)
        return;
    mounted = true;

    ret = vfs_open(path, O_CREAT | O_RDWR | O_TRUNC, 0644, &f);
    test_check(ret == 0, "rwv2 open");
    if (ret < 0)
        goto out;

    fd = fd_alloc(proc_current(), f);
    test_check(fd >= 0, "rwv2 alloc fd");
    if (fd < 0)
        goto out;
    f = NULL;

    ssize_t wr = fd_write_once(fd, "0123456789", 10);
    test_check(wr == 10, "rwv2 seed write");
    test_check(fd_set_offset(fd, 0, SEEK_SET) == 0, "rwv2 seek zero");

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "rwv2 user map");
    if (rc < 0)
        goto out;
    mapped = true;

    struct test_iovec *u_iov = (struct test_iovec *)user_map_ptr(&um, 0);
    char *u_wbuf = (char *)user_map_ptr(&um, 128);
    char *u_rbuf = (char *)user_map_ptr(&um, 256);
    test_check(u_iov != NULL, "rwv2 u_iov");
    test_check(u_wbuf != NULL, "rwv2 u_wbuf");
    test_check(u_rbuf != NULL, "rwv2 u_rbuf");
    if (!u_iov || !u_wbuf || !u_rbuf)
        goto out;

    struct test_iovec iov = {
        .iov_base = u_wbuf,
        .iov_len = 2,
    };
    rc = copy_to_user(u_iov, &iov, sizeof(iov));
    test_check(rc == 0, "rwv2 copy iov write");
    if (rc < 0)
        goto out;
    rc = copy_to_user(u_wbuf, "AB", 2);
    test_check(rc == 0, "rwv2 copy write payload");
    if (rc < 0)
        goto out;

    int64_t ret64 =
        sys_preadv2((uint64_t)fd, (uint64_t)u_iov, 1, 0, 0, TEST_RWF_DSYNC);
    test_check(ret64 == -EOPNOTSUPP, "rwv2 preadv2 unsupported flags");

    ret64 = sys_pwritev2((uint64_t)fd, (uint64_t)u_iov, 1, 0, 0, 0x10U);
    test_check(ret64 == -EOPNOTSUPP, "rwv2 pwritev2 unsupported flags");

    test_check(fd_set_offset(fd, 0, SEEK_SET) == 0, "rwv2 reset offset");
    ret64 = sys_pwritev2((uint64_t)fd, (uint64_t)u_iov, 1, 4, 0,
                         TEST_RWF_DSYNC);
    test_check(ret64 == 2, "rwv2 pwritev2 positional write");
    if (ret64 == 2)
        test_check(fd_get_offset(fd) == 0, "rwv2 positional keep offset");

    struct test_iovec rd_iov = {
        .iov_base = u_rbuf,
        .iov_len = 2,
    };
    rc = copy_to_user(u_iov, &rd_iov, sizeof(rd_iov));
    test_check(rc == 0, "rwv2 copy iov read");
    if (rc < 0)
        goto out;
    rc = copy_to_user(u_rbuf, "\0\0", 2);
    test_check(rc == 0, "rwv2 clear read buf");
    if (rc < 0)
        goto out;

    ret64 = sys_preadv2((uint64_t)fd, (uint64_t)u_iov, 1, 4, 0,
                        TEST_RWF_NOWAIT);
    test_check(ret64 == 2, "rwv2 preadv2 positional read");
    if (ret64 == 2) {
        char got[2] = {0, 0};
        rc = copy_from_user(got, u_rbuf, sizeof(got));
        test_check(rc == 0, "rwv2 copy read payload");
        if (rc == 0)
            test_check(memcmp(got, "AB", 2) == 0, "rwv2 read data AB");
    }

    test_check(fd_set_offset(fd, 0, SEEK_SET) == 0, "rwv2 seek for fallback wr");
    rc = copy_to_user(u_wbuf, "XY", 2);
    test_check(rc == 0, "rwv2 copy fallback write payload");
    if (rc < 0)
        goto out;
    iov.iov_base = u_wbuf;
    iov.iov_len = 2;
    rc = copy_to_user(u_iov, &iov, sizeof(iov));
    test_check(rc == 0, "rwv2 copy fallback write iov");
    if (rc < 0)
        goto out;

    ret64 = sys_pwritev2((uint64_t)fd, (uint64_t)u_iov, 1, 0xffffffffULL,
                         0xffffffffULL, 0);
    test_check(ret64 == 2, "rwv2 pwritev2 minus1 fallback");
    if (ret64 == 2)
        test_check(fd_get_offset(fd) == 2, "rwv2 fallback write advances offset");

    test_check(fd_set_offset(fd, 0, SEEK_SET) == 0, "rwv2 seek for fallback rd");
    rd_iov.iov_base = u_rbuf;
    rd_iov.iov_len = 2;
    rc = copy_to_user(u_iov, &rd_iov, sizeof(rd_iov));
    test_check(rc == 0, "rwv2 copy fallback read iov");
    if (rc < 0)
        goto out;
    rc = copy_to_user(u_rbuf, "\0\0", 2);
    test_check(rc == 0, "rwv2 clear fallback read buf");
    if (rc < 0)
        goto out;

    ret64 = sys_preadv2((uint64_t)fd, (uint64_t)u_iov, 1, 0xffffffffULL,
                        0xffffffffULL, 0);
    test_check(ret64 == 2, "rwv2 preadv2 minus1 fallback");
    if (ret64 == 2) {
        test_check(fd_get_offset(fd) == 2, "rwv2 fallback read advances offset");
        char got[2] = {0, 0};
        rc = copy_from_user(got, u_rbuf, sizeof(got));
        test_check(rc == 0, "rwv2 copy fallback read payload");
        if (rc == 0)
            test_check(memcmp(got, "XY", 2) == 0, "rwv2 fallback read data");
    }

out:
    close_fd_if_open(&fd);
    close_file_if_open(&f);
    if (mapped)
        user_map_end(&um);
    if (mounted)
        cleanup_tmpfs_mount();
}

static void test_close_range_syscall_semantics(void) {
    struct file *f1 = NULL;
    struct file *f2 = NULL;
    struct file *f3 = NULL;
    int fd1 = -1;
    int fd2 = -1;
    int fd3 = -1;
    bool mounted = false;

    int ret = prepare_tmpfs_mount();
    test_check(ret == 0, "close_range mount");
    if (ret < 0)
        return;
    mounted = true;

    ret = vfs_open(VFS_IPC_MNT "/cr1", O_CREAT | O_RDWR | O_TRUNC, 0644, &f1);
    test_check(ret == 0, "close_range open1");
    if (ret < 0)
        goto out;
    ret = vfs_open(VFS_IPC_MNT "/cr2", O_CREAT | O_RDWR | O_TRUNC, 0644, &f2);
    test_check(ret == 0, "close_range open2");
    if (ret < 0)
        goto out;
    ret = vfs_open(VFS_IPC_MNT "/cr3", O_CREAT | O_RDWR | O_TRUNC, 0644, &f3);
    test_check(ret == 0, "close_range open3");
    if (ret < 0)
        goto out;

    fd1 = fd_alloc(proc_current(), f1);
    fd2 = fd_alloc(proc_current(), f2);
    fd3 = fd_alloc(proc_current(), f3);
    test_check(fd1 >= 0, "close_range alloc fd1");
    test_check(fd2 >= 0, "close_range alloc fd2");
    test_check(fd3 >= 0, "close_range alloc fd3");
    if (fd1 < 0 || fd2 < 0 || fd3 < 0)
        goto out;
    f1 = NULL;
    f2 = NULL;
    f3 = NULL;

    int64_t ret64 = sys_close_range((uint64_t)fd2, (uint64_t)fd1, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "close_range first_gt_last einval");

    ret64 = sys_close_range((uint64_t)fd1, (uint64_t)fd3, 1U, 0, 0, 0);
    test_check(ret64 == -EINVAL, "close_range invalid flags einval");

    ret64 = sys_close_range((uint64_t)fd1, (uint64_t)fd2,
                            TEST_CLOSE_RANGE_CLOEXEC, 0, 0, 0);
    test_check(ret64 == 0, "close_range cloexec set");
    if (ret64 == 0) {
        test_check(fd_has_cloexec(fd1), "close_range cloexec fd1");
        test_check(fd_has_cloexec(fd2), "close_range cloexec fd2");
        test_check(!fd_has_cloexec(fd3), "close_range cloexec fd3 untouched");
    }

    ret64 = sys_close_range((1ULL << 32) | (uint64_t)fd3,
                            (1ULL << 32) | (uint64_t)fd3, 0, 0, 0, 0);
    test_check(ret64 == 0, "close_range fd width close");
    if (ret64 == 0) {
        struct file *chk = fd_get(proc_current(), fd3);
        test_check(chk == NULL, "close_range fd3 closed");
        if (chk)
            file_put(chk);
    }

    ret64 = sys_close_range((uint64_t)fd1, (uint64_t)fd2, 0, 0, 0, 0);
    test_check(ret64 == 0, "close_range close range");
    if (ret64 == 0) {
        struct file *chk1 = fd_get(proc_current(), fd1);
        struct file *chk2 = fd_get(proc_current(), fd2);
        test_check(chk1 == NULL, "close_range fd1 closed");
        test_check(chk2 == NULL, "close_range fd2 closed");
        if (chk1)
            file_put(chk1);
        if (chk2)
            file_put(chk2);
    }

    ret64 =
        sys_close_range((uint64_t)CONFIG_MAX_FILES_PER_PROC, UINT64_MAX, 0, 0, 0, 0);
    test_check(ret64 == 0, "close_range first out of range");

out:
    close_fd_if_open(&fd1);
    close_fd_if_open(&fd2);
    close_fd_if_open(&fd3);
    close_file_if_open(&f1);
    close_file_if_open(&f2);
    close_file_if_open(&f3);
    if (mounted)
        cleanup_tmpfs_mount();
}

static void test_statx_syscall_semantics(void) {
    const char path[] = VFS_IPC_MNT "/statx_file.txt";
    const char payload[] = "statx-data";
    struct user_map_ctx um = {0};
    struct file *f = NULL;
    bool mounted = false;
    bool mapped = false;
    int fd = -1;

    int ret = prepare_tmpfs_mount();
    test_check(ret == 0, "statx mount");
    if (ret < 0)
        return;
    mounted = true;

    ret = vfs_open(path, O_CREAT | O_RDWR | O_TRUNC, 0644, &f);
    test_check(ret == 0, "statx open");
    if (ret < 0)
        goto out;

    ssize_t wr = vfs_write(f, payload, sizeof(payload) - 1);
    test_check(wr == (ssize_t)(sizeof(payload) - 1), "statx seed write");

    fd = fd_alloc(proc_current(), f);
    test_check(fd >= 0, "statx alloc fd");
    if (fd < 0)
        goto out;
    f = NULL;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "statx user map");
    if (rc < 0)
        goto out;
    mapped = true;

    char *u_path = (char *)user_map_ptr(&um, 0);
    char *u_empty = (char *)user_map_ptr(&um, 256);
    struct test_linux_statx *u_stx =
        (struct test_linux_statx *)user_map_ptr(&um, 512);
    test_check(u_path != NULL, "statx u_path");
    test_check(u_empty != NULL, "statx u_empty");
    test_check(u_stx != NULL, "statx u_stx");
    if (!u_path || !u_empty || !u_stx)
        goto out;

    rc = copy_to_user(u_path, path, sizeof(path));
    test_check(rc == 0, "statx copy path");
    rc = copy_to_user(u_empty, "", 1);
    test_check(rc == 0, "statx copy empty");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_statx((uint64_t)AT_FDCWD, (uint64_t)u_path, 0,
                              TEST_STATX_BASIC_STATS, 0, 0);
    test_check(ret64 == -EFAULT, "statx null out efault");

    ret64 = sys_statx((uint64_t)AT_FDCWD, (uint64_t)u_path, 0x1U,
                      TEST_STATX_BASIC_STATS, (uint64_t)u_stx, 0);
    test_check(ret64 == -EINVAL, "statx bad flags einval");

    ret64 = sys_statx((uint64_t)AT_FDCWD, (uint64_t)u_path, 0,
                      TEST_STATX__RESERVED, (uint64_t)u_stx, 0);
    test_check(ret64 == -EINVAL, "statx reserved mask einval");

    ret64 = sys_statx((uint64_t)AT_FDCWD, (uint64_t)u_empty, 0,
                      TEST_STATX_BASIC_STATS, (uint64_t)u_stx, 0);
    test_check(ret64 == -ENOENT, "statx empty path enoent");

    ret64 = sys_statx((uint64_t)AT_FDCWD, (uint64_t)u_path,
                      TEST_AT_STATX_SYNC_AS_STAT,
                      TEST_STATX_SIZE | TEST_STATX_MODE, (uint64_t)u_stx, 0);
    test_check(ret64 == 0, "statx basic ok");
    if (ret64 == 0) {
        struct test_linux_statx stx;
        rc = copy_from_user(&stx, u_stx, sizeof(stx));
        test_check(rc == 0, "statx copy out");
        if (rc == 0) {
            test_check((stx.stx_mask & TEST_STATX_BASIC_STATS) ==
                           TEST_STATX_BASIC_STATS,
                       "statx mask basic");
            test_check(stx.stx_size == sizeof(payload) - 1, "statx size match");
        }
    }

    ret64 = sys_statx((uint64_t)fd, (uint64_t)u_empty,
                      (1ULL << 32) | AT_EMPTY_PATH, TEST_STATX_SIZE,
                      (uint64_t)u_stx, 0);
    test_check(ret64 == 0, "statx empty path fd");
    if (ret64 == 0) {
        struct test_linux_statx stx;
        rc = copy_from_user(&stx, u_stx, sizeof(stx));
        test_check(rc == 0, "statx copy out fd");
        if (rc == 0)
            test_check(stx.stx_size == sizeof(payload) - 1, "statx fd size");
    }

out:
    close_fd_if_open(&fd);
    close_file_if_open(&f);
    if (mapped)
        user_map_end(&um);
    if (mounted)
        cleanup_tmpfs_mount();
}

static void test_epoll_pwait2_syscall_semantics(void) {
    struct file *rf = NULL;
    struct file *wf = NULL;
    int rfd = -1;
    int wfd = -1;
    int epfd = -1;
    bool mapped = false;
    struct user_map_ctx um = {0};

    int ret = pipe_create(&rf, &wf);
    test_check(ret == 0, "epoll_pwait2 create pipe");
    if (ret < 0)
        goto out;

    rfd = fd_alloc(proc_current(), rf);
    wfd = fd_alloc(proc_current(), wf);
    test_check(rfd >= 0, "epoll_pwait2 alloc rfd");
    test_check(wfd >= 0, "epoll_pwait2 alloc wfd");
    if (rfd < 0 || wfd < 0)
        goto out;
    rf = NULL;
    wf = NULL;

    int64_t ret64 = sys_epoll_create1(0, 0, 0, 0, 0, 0);
    test_check(ret64 >= 0, "epoll_pwait2 create epoll");
    if (ret64 < 0)
        goto out;
    epfd = (int)ret64;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "epoll_pwait2 user map");
    if (rc < 0)
        goto out;
    mapped = true;

    struct epoll_event *u_add = (struct epoll_event *)user_map_ptr(&um, 0);
    struct epoll_event *u_out = (struct epoll_event *)user_map_ptr(&um, 128);
    struct timespec *u_ts = (struct timespec *)user_map_ptr(&um, 320);
    sigset_t *u_sigmask = (sigset_t *)user_map_ptr(&um, 400);
    test_check(u_add != NULL, "epoll_pwait2 u_add");
    test_check(u_out != NULL, "epoll_pwait2 u_out");
    test_check(u_ts != NULL, "epoll_pwait2 u_ts");
    test_check(u_sigmask != NULL, "epoll_pwait2 u_sigmask");
    if (!u_add || !u_out || !u_ts || !u_sigmask)
        goto out;

    struct epoll_event add = {
        .events = EPOLLIN,
        .data = 0x55,
    };
    rc = copy_to_user(u_add, &add, sizeof(add));
    test_check(rc == 0, "epoll_pwait2 copy add");
    if (rc < 0)
        goto out;

    ret64 = sys_epoll_ctl((uint64_t)epfd, EPOLL_CTL_ADD, (uint64_t)rfd,
                          (uint64_t)u_add, 0, 0);
    test_check(ret64 == 0, "epoll_pwait2 ctl add");
    if (ret64 < 0)
        goto out;

    ret64 = sys_epoll_pwait2((uint64_t)epfd, 0, 1, (uint64_t)u_ts, 0, 0);
    test_check(ret64 == -EFAULT, "epoll_pwait2 null events efault");

    ret64 = sys_epoll_pwait2((uint64_t)epfd, (uint64_t)u_out, 0, (uint64_t)u_ts,
                             0, 0);
    test_check(ret64 == -EINVAL, "epoll_pwait2 maxevents einval");

    struct timespec bad_ts = {
        .tv_sec = 0,
        .tv_nsec = TEST_NS_PER_SEC,
    };
    rc = copy_to_user(u_ts, &bad_ts, sizeof(bad_ts));
    test_check(rc == 0, "epoll_pwait2 copy bad ts");
    if (rc == 0) {
        ret64 = sys_epoll_pwait2((uint64_t)epfd, (uint64_t)u_out, 1,
                                 (uint64_t)u_ts, 0, 0);
        test_check(ret64 == -EINVAL, "epoll_pwait2 bad timeout einval");
    }

    sigset_t zero_mask = 0;
    rc = copy_to_user(u_sigmask, &zero_mask, sizeof(zero_mask));
    test_check(rc == 0, "epoll_pwait2 copy sigmask");
    if (rc == 0) {
        ret64 = sys_epoll_pwait2((uint64_t)epfd, (uint64_t)u_out, 1, 0,
                                 (uint64_t)u_sigmask, sizeof(sigset_t) - 1);
        test_check(ret64 == -EINVAL, "epoll_pwait2 sigsetsize einval");
    }

    struct timespec zero_ts = {
        .tv_sec = 0,
        .tv_nsec = 0,
    };
    rc = copy_to_user(u_ts, &zero_ts, sizeof(zero_ts));
    test_check(rc == 0, "epoll_pwait2 copy zero ts");
    if (rc == 0) {
        ret64 = sys_epoll_pwait2((uint64_t)epfd, (uint64_t)u_out, 1,
                                 (uint64_t)u_ts, 0, 0);
        test_check(ret64 == 0, "epoll_pwait2 timeout zero");
    }

    ssize_t wr = fd_write_once(wfd, "X", 1);
    test_check(wr == 1, "epoll_pwait2 seed readable");
    if (wr == 1) {
        struct timespec one_sec = {
            .tv_sec = 1,
            .tv_nsec = 0,
        };
        rc = copy_to_user(u_ts, &one_sec, sizeof(one_sec));
        test_check(rc == 0, "epoll_pwait2 copy one sec");
        if (rc == 0) {
            ret64 = sys_epoll_pwait2((uint64_t)epfd, (uint64_t)u_out, 1,
                                     (uint64_t)u_ts, 0, 0);
            test_check(ret64 == 1, "epoll_pwait2 ready one");
            if (ret64 == 1) {
                struct epoll_event out_ev = {0};
                rc = copy_from_user(&out_ev, u_out, sizeof(out_ev));
                test_check(rc == 0, "epoll_pwait2 copy out");
                if (rc == 0) {
                    test_check((out_ev.events & EPOLLIN) != 0,
                               "epoll_pwait2 out mask");
                    test_check(out_ev.data == 0x55, "epoll_pwait2 out data");
                }
            }
        }
    }

out:
    close_fd_if_open(&epfd);
    close_fd_if_open(&rfd);
    close_fd_if_open(&wfd);
    close_file_if_open(&rf);
    close_file_if_open(&wf);
    if (mapped)
        user_map_end(&um);
}

static void test_ppoll_pselect6_syscall_semantics(void) {
    struct file *rf = NULL;
    struct file *wf = NULL;
    int rfd = -1;
    int wfd = -1;
    bool mapped = false;
    struct user_map_ctx um = {0};
    struct process *p = proc_current();
    test_check(p != NULL, "pollsel proc current");
    if (!p)
        return;

    int ret = pipe_create(&rf, &wf);
    test_check(ret == 0, "pollsel create pipe");
    if (ret < 0)
        goto out;

    rfd = fd_alloc(proc_current(), rf);
    wfd = fd_alloc(proc_current(), wf);
    test_check(rfd >= 0, "pollsel alloc rfd");
    test_check(wfd >= 0, "pollsel alloc wfd");
    if (rfd < 0 || wfd < 0)
        goto out;
    rf = NULL;
    wf = NULL;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "pollsel user map");
    if (rc < 0)
        goto out;
    mapped = true;

    struct pollfd *u_pfd = (struct pollfd *)user_map_ptr(&um, 0);
    struct timespec *u_ppoll_ts = (struct timespec *)user_map_ptr(&um, 96);
    struct timespec *u_pselect_ts = (struct timespec *)user_map_ptr(&um, 160);
    sigset_t *u_sigmask = (sigset_t *)user_map_ptr(&um, 224);
    struct test_pselect_sigset *u_pss =
        (struct test_pselect_sigset *)user_map_ptr(&um, 288);
    fd_set *u_rfds = (fd_set *)user_map_ptr(&um, 352);
    test_check(u_pfd != NULL, "pollsel u_pfd");
    test_check(u_ppoll_ts != NULL, "pollsel u_ppoll_ts");
    test_check(u_pselect_ts != NULL, "pollsel u_pselect_ts");
    test_check(u_sigmask != NULL, "pollsel u_sigmask");
    test_check(u_pss != NULL, "pollsel u_pss");
    test_check(u_rfds != NULL, "pollsel u_rfds");
    if (!u_pfd || !u_ppoll_ts || !u_pselect_ts || !u_sigmask || !u_pss ||
        !u_rfds)
        goto out;

    struct pollfd pfd = {
        .fd = rfd,
        .events = POLLIN,
        .revents = 0,
    };
    rc = copy_to_user(u_pfd, &pfd, sizeof(pfd));
    test_check(rc == 0, "pollsel copy pfd");
    if (rc < 0)
        goto out;

    sigset_t zero_mask = 0;
    rc = copy_to_user(u_sigmask, &zero_mask, sizeof(zero_mask));
    test_check(rc == 0, "pollsel copy sigmask");
    if (rc == 0) {
        struct timespec ts0 = {
            .tv_sec = 0,
            .tv_nsec = 0,
        };
        rc = copy_to_user(u_ppoll_ts, &ts0, sizeof(ts0));
        test_check(rc == 0, "pollsel copy ppoll ts0");
        if (rc == 0) {
            int64_t ret64 =
                sys_ppoll((uint64_t)u_pfd, 1, (uint64_t)u_ppoll_ts,
                          (uint64_t)u_sigmask, sizeof(sigset_t) - 1, 0);
            test_check(ret64 == -EINVAL, "pollsel ppoll sigsetsize einval");
        }
    }

    struct timespec ts0 = {
        .tv_sec = 0,
        .tv_nsec = 0,
    };
    rc = copy_to_user(u_ppoll_ts, &ts0, sizeof(ts0));
    test_check(rc == 0, "pollsel copy ppoll zero timeout");
    if (rc == 0) {
        int64_t ret64 =
            sys_ppoll((uint64_t)u_pfd, 1, (uint64_t)u_ppoll_ts, 0, 0, 0);
        test_check(ret64 == 0, "pollsel ppoll zero timeout");
    }

    ssize_t wr = fd_write_once(wfd, "P", 1);
    test_check(wr == 1, "pollsel ppoll seed data");
    if (wr == 1) {
        struct timespec one_sec = {
            .tv_sec = 1,
            .tv_nsec = 0,
        };
        rc = copy_to_user(u_ppoll_ts, &one_sec, sizeof(one_sec));
        test_check(rc == 0, "pollsel copy ppoll one sec");
        if (rc == 0) {
            int64_t ret64 =
                sys_ppoll((uint64_t)u_pfd, 1, (uint64_t)u_ppoll_ts, 0, 0, 0);
            test_check(ret64 == 1, "pollsel ppoll ready");
            if (ret64 == 1) {
                struct pollfd out_pfd = {0};
                rc = copy_from_user(&out_pfd, u_pfd, sizeof(out_pfd));
                test_check(rc == 0, "pollsel copy ppoll out");
                if (rc == 0)
                    test_check((out_pfd.revents & POLLIN) != 0,
                               "pollsel ppoll revents in");
            }
        }
    }

    char drain = 0;
    ssize_t rd = fd_read_once(rfd, &drain, 1);
    test_check(rd == 1, "pollsel drain pipe");

    struct test_pselect_sigset pss = {
        .sigmask = (uint64_t)u_sigmask,
        .sigsetsize = sizeof(sigset_t) - 1,
    };
    rc = copy_to_user(u_pss, &pss, sizeof(pss));
    test_check(rc == 0, "pollsel copy pselect bad sigset");
    if (rc == 0) {
        fd_set rfds = {
            .bits = (1ULL << rfd),
        };
        rc = copy_to_user(u_rfds, &rfds, sizeof(rfds));
        test_check(rc == 0, "pollsel copy pselect rfds bad");
        if (rc == 0) {
            rc = copy_to_user(u_pselect_ts, &ts0, sizeof(ts0));
            test_check(rc == 0, "pollsel copy pselect ts0 bad");
            if (rc == 0) {
                int64_t ret64 = sys_pselect6((uint64_t)(rfd + 1),
                                             (uint64_t)u_rfds, 0, 0,
                                             (uint64_t)u_pselect_ts,
                                             (uint64_t)u_pss);
                test_check(ret64 == -EINVAL,
                           "pollsel pselect sigsetsize einval");
            }
        }
    }

    pss.sigsetsize = sizeof(sigset_t);
    rc = copy_to_user(u_pss, &pss, sizeof(pss));
    test_check(rc == 0, "pollsel copy pselect sigset ok");

    fd_set rfds0 = {
        .bits = (1ULL << rfd),
    };
    rc = copy_to_user(u_rfds, &rfds0, sizeof(rfds0));
    test_check(rc == 0, "pollsel copy pselect rfds zero");
    rc = copy_to_user(u_pselect_ts, &ts0, sizeof(ts0));
    test_check(rc == 0, "pollsel copy pselect ts0");
    if (rc == 0) {
        int64_t ret64 = sys_pselect6((uint64_t)(rfd + 1), (uint64_t)u_rfds, 0, 0,
                                     (uint64_t)u_pselect_ts, (uint64_t)u_pss);
        test_check(ret64 == 0, "pollsel pselect zero timeout");
    }

    wr = fd_write_once(wfd, "S", 1);
    test_check(wr == 1, "pollsel pselect seed data");
    if (wr == 1) {
        struct timespec one_sec = {
            .tv_sec = 1,
            .tv_nsec = 0,
        };
        fd_set rfds = {
            .bits = (1ULL << rfd),
        };
        rc = copy_to_user(u_rfds, &rfds, sizeof(rfds));
        test_check(rc == 0, "pollsel copy pselect rfds");
        rc = copy_to_user(u_pselect_ts, &one_sec, sizeof(one_sec));
        test_check(rc == 0, "pollsel copy pselect one sec");
        if (rc == 0) {
            int64_t ret64 = sys_pselect6((uint64_t)(rfd + 1),
                                         (uint64_t)u_rfds, 0, 0,
                                         (uint64_t)u_pselect_ts,
                                         (uint64_t)u_pss);
            test_check(ret64 == 1, "pollsel pselect ready");
            if (ret64 == 1) {
                fd_set out = {0};
                rc = copy_from_user(&out, u_rfds, sizeof(out));
                test_check(rc == 0, "pollsel copy pselect out");
                if (rc == 0)
                    test_check((out.bits & (1ULL << rfd)) != 0,
                               "pollsel pselect rfds set");
            }
        }
    }

    sigset_t usr1_mask = (1ULL << (SIGUSR1 - 1));
    sigset_t saved_blocked = __atomic_load_n(&p->sig_blocked, __ATOMIC_ACQUIRE);
    sigset_t saved_pending = __atomic_load_n(&p->sig_pending, __ATOMIC_ACQUIRE);
    bool had_usr1_pending = (saved_pending & usr1_mask) != 0;
    __atomic_fetch_or(&p->sig_pending, usr1_mask, __ATOMIC_RELEASE);

    struct timespec wait_ts = {
        .tv_sec = 1,
        .tv_nsec = 0,
    };
    sigset_t temp_unblock = saved_blocked & ~usr1_mask;
    rc = copy_to_user(u_sigmask, &temp_unblock, sizeof(temp_unblock));
    test_check(rc == 0, "pollsel copy temp unblock mask");
    rc = copy_to_user(u_ppoll_ts, &wait_ts, sizeof(wait_ts));
    test_check(rc == 0, "pollsel copy ppoll intr timeout");
    if (rc == 0) {
        int64_t ret64 =
            sys_ppoll(0, 0, (uint64_t)u_ppoll_ts, (uint64_t)u_sigmask,
                      sizeof(sigset_t), 0);
        test_check(ret64 == -EINTR, "pollsel ppoll pending intr");
        sigset_t blocked_after =
            __atomic_load_n(&p->sig_blocked, __ATOMIC_ACQUIRE);
        test_check(blocked_after == saved_blocked,
                   "pollsel ppoll restores blocked mask");
    }

    struct test_pselect_sigset pss_intr = {
        .sigmask = (uint64_t)u_sigmask,
        .sigsetsize = sizeof(sigset_t),
    };
    rc = copy_to_user(u_pss, &pss_intr, sizeof(pss_intr));
    test_check(rc == 0, "pollsel copy pselect intr sigset");
    rc = copy_to_user(u_pselect_ts, &wait_ts, sizeof(wait_ts));
    test_check(rc == 0, "pollsel copy pselect intr timeout");
    if (rc == 0) {
        int64_t ret64 =
            sys_pselect6(0, 0, 0, 0, (uint64_t)u_pselect_ts, (uint64_t)u_pss);
        test_check(ret64 == -EINTR, "pollsel pselect pending intr");
        sigset_t blocked_after =
            __atomic_load_n(&p->sig_blocked, __ATOMIC_ACQUIRE);
        test_check(blocked_after == saved_blocked,
                   "pollsel pselect restores blocked mask");
    }

    if (!had_usr1_pending)
        __atomic_fetch_and(&p->sig_pending, ~usr1_mask, __ATOMIC_RELEASE);

out:
    close_fd_if_open(&rfd);
    close_fd_if_open(&wfd);
    close_file_if_open(&rf);
    close_file_if_open(&wf);
    if (mapped)
        user_map_end(&um);
}

static void test_renameat2_syscall_semantics(void) {
    const char src1[] = VFS_IPC_MNT "/ra2_src1";
    const char dst1[] = VFS_IPC_MNT "/ra2_dst1";
    const char src2[] = VFS_IPC_MNT "/ra2_src2";
    const char dst2[] = VFS_IPC_MNT "/ra2_dst2";
    struct user_map_ctx um = {0};
    struct file *f = NULL;
    struct stat st;
    bool mounted = false;
    bool mapped = false;

    int ret = prepare_tmpfs_mount();
    test_check(ret == 0, "renameat2 mount");
    if (ret < 0)
        return;
    mounted = true;

    ret = vfs_open(src1, O_CREAT | O_WRONLY | O_TRUNC, 0644, &f);
    test_check(ret == 0, "renameat2 create src1");
    close_file_if_open(&f);
    if (ret < 0)
        goto out;

    ret = vfs_open(dst1, O_CREAT | O_WRONLY | O_TRUNC, 0644, &f);
    test_check(ret == 0, "renameat2 create dst1");
    close_file_if_open(&f);
    if (ret < 0)
        goto out;

    ret = vfs_open(src2, O_CREAT | O_WRONLY | O_TRUNC, 0644, &f);
    test_check(ret == 0, "renameat2 create src2");
    close_file_if_open(&f);
    if (ret < 0)
        goto out;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "renameat2 user map");
    if (rc < 0)
        goto out;
    mapped = true;

    char *u_src1 = (char *)user_map_ptr(&um, 0);
    char *u_dst1 = (char *)user_map_ptr(&um, 128);
    char *u_src2 = (char *)user_map_ptr(&um, 256);
    char *u_dst2 = (char *)user_map_ptr(&um, 384);
    test_check(u_src1 != NULL, "renameat2 u_src1");
    test_check(u_dst1 != NULL, "renameat2 u_dst1");
    test_check(u_src2 != NULL, "renameat2 u_src2");
    test_check(u_dst2 != NULL, "renameat2 u_dst2");
    if (!u_src1 || !u_dst1 || !u_src2 || !u_dst2)
        goto out;

    rc = copy_to_user(u_src1, src1, sizeof(src1));
    test_check(rc == 0, "renameat2 copy src1");
    rc = copy_to_user(u_dst1, dst1, sizeof(dst1));
    test_check(rc == 0, "renameat2 copy dst1");
    rc = copy_to_user(u_src2, src2, sizeof(src2));
    test_check(rc == 0, "renameat2 copy src2");
    rc = copy_to_user(u_dst2, dst2, sizeof(dst2));
    test_check(rc == 0, "renameat2 copy dst2");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_renameat2((uint64_t)AT_FDCWD, (uint64_t)u_src1,
                                  (uint64_t)AT_FDCWD, (uint64_t)u_dst1,
                                  TEST_RENAME_NOREPLACE, 0);
    test_check(ret64 == -EEXIST, "renameat2 noreplace eexist");

    ret64 = sys_renameat2((uint64_t)AT_FDCWD, (uint64_t)u_src1,
                          (uint64_t)AT_FDCWD, (uint64_t)u_dst1, 0x2U, 0);
    test_check(ret64 == -EINVAL, "renameat2 bad flags einval");

    ret = vfs_unlink(dst1);
    test_check(ret == 0, "renameat2 unlink dst1");
    if (ret == 0) {
        ret64 = sys_renameat2((uint64_t)AT_FDCWD, (uint64_t)u_src1,
                              (uint64_t)AT_FDCWD, (uint64_t)u_dst1, 0, 0);
        test_check(ret64 == 0, "renameat2 flags zero");
        if (ret64 == 0) {
            ret = vfs_stat(src1, &st);
            test_check(ret == -ENOENT, "renameat2 src1 gone");
            ret = vfs_stat(dst1, &st);
            test_check(ret == 0, "renameat2 dst1 exists");
        }
    }

    ret64 = sys_renameat2((uint64_t)AT_FDCWD, (uint64_t)u_src2,
                          (uint64_t)AT_FDCWD, (uint64_t)u_dst2, 1ULL << 32, 0);
    test_check(ret64 == 0, "renameat2 flags width");
    if (ret64 == 0) {
        ret = vfs_stat(src2, &st);
        test_check(ret == -ENOENT, "renameat2 src2 gone");
        ret = vfs_stat(dst2, &st);
        test_check(ret == 0, "renameat2 dst2 exists");
    }

out:
    close_file_if_open(&f);
    if (mapped)
        user_map_end(&um);
    if (mounted)
        cleanup_tmpfs_mount();
}

struct blocking_read_ctx {
    struct file *r;
    volatile int started;
    ssize_t ret;
    char buf[8];
};

static int blocking_pipe_reader(void *arg) {
    struct blocking_read_ctx *ctx = (struct blocking_read_ctx *)arg;
    if (!ctx || !ctx->r) {
        if (ctx)
            ctx->ret = -EIO;
        proc_exit(0);
    }
    ctx->started = 1;
    ctx->ret = vfs_read(ctx->r, ctx->buf, 4);
    proc_exit(0);
}

static void test_pipe_semantics(void) {
    struct file *r = NULL;
    struct file *w = NULL;
    int ret = pipe_create(&r, &w);
    test_check(ret == 0, "pipe create");
    if (ret < 0)
        return;

    do {
        r->flags |= O_NONBLOCK;
        w->flags |= O_NONBLOCK;

        int pe = vfs_poll(r, POLLIN);
        test_check((pe & POLLIN) == 0, "pipe poll empty not readable");

        char wbuf[256];
        memset(wbuf, 'x', sizeof(wbuf));
        size_t total = 0;
        while (1) {
            ssize_t wr = vfs_write(w, wbuf, sizeof(wbuf));
            if (wr > 0) {
                total += (size_t)wr;
                continue;
            }
            test_check(wr == -EAGAIN, "pipe full eagain");
            break;
        }
        test_check(total == 4096, "pipe fill exact");

        pe = vfs_poll(r, POLLIN);
        test_check((pe & POLLIN) != 0, "pipe poll readable after write");

        ssize_t wr = vfs_write(w, "z", 1);
        test_check(wr == -EAGAIN, "pipe write full eagain");

        char rbuf[300];
        ssize_t rd = vfs_read(r, rbuf, sizeof(rbuf));
        test_check(rd == (ssize_t)sizeof(rbuf), "pipe read partial");

        wr = vfs_write(w, wbuf, 128);
        test_check(wr == 128, "pipe write after drain");

        while ((rd = vfs_read(r, rbuf, sizeof(rbuf))) > 0) {
            ;
        }
        test_check(rd == -EAGAIN, "pipe empty eagain while writer alive");

        close_file_if_open(&w);
        rd = vfs_read(r, rbuf, sizeof(rbuf));
        test_check(rd == 0, "pipe eof after writer close");
    } while (0);

    close_file_if_open(&w);
    close_file_if_open(&r);

    ret = pipe_create(&r, &w);
    test_check(ret == 0, "pipe create blocking");
    if (ret < 0)
        return;

    do {
        struct blocking_read_ctx *ctx = kzalloc(sizeof(*ctx));
        test_check(ctx != NULL, "pipe blocking ctx alloc");
        if (!ctx)
            break;
        ctx->r = r;
        ctx->ret = -1;

        struct process *child =
            kthread_create_joinable(blocking_pipe_reader, ctx, "pipeblk");
        test_check(child != NULL, "pipe blocking child create");
        if (!child) {
            kfree(ctx);
            break;
        }
        pid_t expected_pid = child->pid;
        sched_enqueue(child);

        for (int i = 0; i < 2000 && !ctx->started; i++)
            proc_yield();
        test_check(ctx->started != 0, "pipe blocking child started");

        int status = 0;
        pid_t wp = proc_wait(child->pid, &status, WNOHANG);
        test_check(wp == 0, "pipe blocking wait nohang before write");

        ssize_t wr = vfs_write(w, "PING", 4);
        test_check(wr == 4, "pipe blocking write wake");

        wp = proc_wait(child->pid, &status, 0);
        test_check(wp == expected_pid, "pipe blocking child reaped");
        test_check(ctx->ret == 4, "pipe blocking child read len");
        test_check(memcmp(ctx->buf, "PING", 4) == 0,
                   "pipe blocking child read data");
        kfree(ctx);
    } while (0);

    close_file_if_open(&w);
    close_file_if_open(&r);
}

static void test_pipe_fcntl_nonblock_semantics(void) {
    struct file *r = NULL;
    struct file *w = NULL;
    int rfd = -1;
    int wfd = -1;

    int ret = pipe_create(&r, &w);
    test_check(ret == 0, "pipe fcntl create");
    if (ret < 0)
        return;

    rfd = fd_alloc(proc_current(), r);
    test_check(rfd >= 0, "pipe fcntl alloc read fd");
    if (rfd >= 0)
        r = NULL;

    wfd = fd_alloc(proc_current(), w);
    test_check(wfd >= 0, "pipe fcntl alloc write fd");
    if (wfd >= 0)
        w = NULL;

    if (rfd >= 0 && wfd >= 0) {
        int64_t rfl = sys_fcntl((uint64_t)rfd, F_GETFL, 0, 0, 0, 0);
        int64_t wfl = sys_fcntl((uint64_t)wfd, F_GETFL, 0, 0, 0, 0);
        test_check(rfl >= 0, "pipe fcntl getfl read");
        test_check(wfl >= 0, "pipe fcntl getfl write");

        if (rfl >= 0 && wfl >= 0) {
            int64_t ret64 = sys_fcntl((uint64_t)rfd, F_SETFL,
                                      (uint64_t)(((uint32_t)rfl) | O_NONBLOCK),
                                      0, 0, 0);
            test_check(ret64 == 0, "pipe fcntl setfl read nonblock");
            ret64 = sys_fcntl((uint64_t)wfd, F_SETFL,
                              (uint64_t)(((uint32_t)wfl) | O_NONBLOCK), 0, 0,
                              0);
            test_check(ret64 == 0, "pipe fcntl setfl write nonblock");

            char c = 0;
            ssize_t rd = fd_read_once(rfd, &c, 1);
            test_check(rd == -EWOULDBLOCK, "pipe fcntl read ewouldblock");

            char wbuf[256];
            memset(wbuf, 'f', sizeof(wbuf));
            size_t total = 0;
            while (1) {
                ssize_t wr = fd_write_once(wfd, wbuf, sizeof(wbuf));
                if (wr > 0) {
                    total += (size_t)wr;
                    continue;
                }
                test_check(wr == -EWOULDBLOCK,
                           "pipe fcntl write full ewouldblock");
                break;
            }
            test_check(total == 4096, "pipe fcntl fill exact");
        }
    }

    close_fd_if_open(&wfd);
    close_fd_if_open(&rfd);
    close_file_if_open(&w);
    close_file_if_open(&r);
}

static void test_epoll_pipe_semantics(void) {
    struct file *rf = NULL;
    struct file *wf = NULL;
    struct file *epf = NULL;
    int rfd = -1, wfd = -1, epfd = -1;
    int ret = pipe_create(&rf, &wf);
    test_check(ret == 0, "epoll pipe create");
    if (ret < 0)
        return;

    do {
        rfd = fd_alloc(proc_current(), rf);
        test_check(rfd >= 0, "epoll alloc rfd");
        if (rfd < 0)
            break;

        wfd = fd_alloc(proc_current(), wf);
        test_check(wfd >= 0, "epoll alloc wfd");
        if (wfd < 0)
            break;
        rf = NULL;
        wf = NULL;

        ret = epoll_create_file(&epf);
        test_check(ret == 0, "epoll create file");
        if (ret < 0)
            break;
        epfd = fd_alloc(proc_current(), epf);
        test_check(epfd >= 0, "epoll alloc epfd");
        if (epfd < 0)
            break;
        epf = NULL;

        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLHUP,
            .data = 0xA1,
        };
        ret = epoll_ctl_fd(epfd, EPOLL_CTL_ADD, rfd, &ev);
        test_check(ret == 0, "epoll add read end");
        if (ret < 0)
            break;

        struct epoll_event events[8];
        memset(events, 0, sizeof(events));
        int ready = epoll_wait_events(epfd, events, 8, 0);
        test_check(ready == 0, "epoll empty wait");

        ssize_t wr = fd_write_once(wfd, "DATA", 4);
        test_check(wr == 4, "epoll write data");

        memset(events, 0, sizeof(events));
        ready = epoll_wait_events(epfd, events, 8, 50);
        test_check(ready > 0, "epoll read event ready");
        test_check(epoll_has_event(events, ready, 0xA1, EPOLLIN),
                   "epoll read event mask");

        char rbuf[8];
        ssize_t rd = fd_read_once(rfd, rbuf, 4);
        test_check(rd == 4, "epoll read consumed");

        close_fd_if_open(&wfd);
        memset(events, 0, sizeof(events));
        ready = epoll_wait_events(epfd, events, 8, 50);
        test_check(ready > 0, "epoll hup ready");
        test_check(epoll_has_event(events, ready, 0xA1, EPOLLHUP),
                   "epoll hup mask");
    } while (0);

    close_fd_if_open(&epfd);
    close_fd_if_open(&wfd);
    close_fd_if_open(&rfd);
    close_file_if_open(&epf);
    close_file_if_open(&wf);
    close_file_if_open(&rf);

    rf = wf = epf = NULL;
    rfd = wfd = epfd = -1;
    ret = pipe_create(&rf, &wf);
    test_check(ret == 0, "epoll pipe create writable");
    if (ret < 0)
        return;

    do {
        rfd = fd_alloc(proc_current(), rf);
        test_check(rfd >= 0, "epoll writable alloc rfd");
        if (rfd < 0)
            break;
        wfd = fd_alloc(proc_current(), wf);
        test_check(wfd >= 0, "epoll writable alloc wfd");
        if (wfd < 0)
            break;
        rf = NULL;
        wf = NULL;

        ret = epoll_create_file(&epf);
        test_check(ret == 0, "epoll writable create");
        if (ret < 0)
            break;
        epfd = fd_alloc(proc_current(), epf);
        test_check(epfd >= 0, "epoll writable alloc epfd");
        if (epfd < 0)
            break;
        epf = NULL;

        struct epoll_event ev = {
            .events = EPOLLOUT,
            .data = 0xB2,
        };
        ret = epoll_ctl_fd(epfd, EPOLL_CTL_ADD, wfd, &ev);
        test_check(ret == 0, "epoll add write end");
        if (ret < 0)
            break;

        struct epoll_event events[8];
        memset(events, 0, sizeof(events));
        int ready = epoll_wait_events(epfd, events, 8, 0);
        test_check(ready > 0, "epoll writable initial ready");
        test_check(epoll_has_event(events, ready, 0xB2, EPOLLOUT),
                   "epoll writable initial out");

        fd_set_nonblock(wfd, true);
        char wbuf[256];
        memset(wbuf, 'q', sizeof(wbuf));
        while (1) {
            ssize_t wr = fd_write_once(wfd, wbuf, sizeof(wbuf));
            if (wr > 0)
                continue;
            test_check(wr == -EAGAIN, "epoll writable full eagain");
            break;
        }

        memset(events, 0, sizeof(events));
        ready = epoll_wait_events(epfd, events, 8, 0);
        test_check(ready == 0, "epoll writable suppressed when full");

        char rbuf[512];
        ssize_t rd = fd_read_once(rfd, rbuf, sizeof(rbuf));
        test_check(rd > 0, "epoll writable read drain");

        memset(events, 0, sizeof(events));
        ready = epoll_wait_events(epfd, events, 8, 50);
        test_check(ready > 0, "epoll writable restored");
        test_check(epoll_has_event(events, ready, 0xB2, EPOLLOUT),
                   "epoll writable restored out");
    } while (0);

    close_fd_if_open(&epfd);
    close_fd_if_open(&wfd);
    close_fd_if_open(&rfd);
    close_file_if_open(&epf);
    close_file_if_open(&wf);
    close_file_if_open(&rf);
}

static void test_epoll_edge_oneshot_semantics(void) {
    struct file *rf = NULL;
    struct file *wf = NULL;
    struct file *epf = NULL;
    int rfd = -1, wfd = -1, epfd = -1;
    int ret = pipe_create(&rf, &wf);
    test_check(ret == 0, "epoll edge create pipe");
    if (ret < 0)
        return;

    do {
        rfd = fd_alloc(proc_current(), rf);
        test_check(rfd >= 0, "epoll edge alloc rfd");
        if (rfd < 0)
            break;
        wfd = fd_alloc(proc_current(), wf);
        test_check(wfd >= 0, "epoll edge alloc wfd");
        if (wfd < 0)
            break;
        rf = NULL;
        wf = NULL;

        ret = epoll_create_file(&epf);
        test_check(ret == 0, "epoll edge create epf");
        if (ret < 0)
            break;
        epfd = fd_alloc(proc_current(), epf);
        test_check(epfd >= 0, "epoll edge alloc epfd");
        if (epfd < 0)
            break;
        epf = NULL;

        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLET,
            .data = 0xC3,
        };
        ret = epoll_ctl_fd(epfd, EPOLL_CTL_ADD, rfd, &ev);
        test_check(ret == 0, "epoll edge add");
        if (ret < 0)
            break;

        struct epoll_event events[4];
        ssize_t wr = fd_write_once(wfd, "AB", 2);
        test_check(wr == 2, "epoll edge write first");

        memset(events, 0, sizeof(events));
        int ready = epoll_wait_events(epfd, events, 4, 50);
        test_check(ready > 0, "epoll edge first ready");
        test_check(epoll_has_event(events, ready, 0xC3, EPOLLIN),
                   "epoll edge first mask");

        memset(events, 0, sizeof(events));
        ready = epoll_wait_events(epfd, events, 4, 0);
        test_check(ready == 0, "epoll edge no repeat");

        char rbuf[8];
        ssize_t rd = fd_read_once(rfd, rbuf, sizeof(rbuf));
        test_check(rd == 2, "epoll edge read first");

        wr = fd_write_once(wfd, "CD", 2);
        test_check(wr == 2, "epoll edge write second");
        memset(events, 0, sizeof(events));
        ready = epoll_wait_events(epfd, events, 4, 50);
        test_check(ready > 0, "epoll edge second ready");
        test_check(epoll_has_event(events, ready, 0xC3, EPOLLIN),
                   "epoll edge second mask");
        rd = fd_read_once(rfd, rbuf, sizeof(rbuf));
        test_check(rd == 2, "epoll edge read second");
    } while (0);

    close_fd_if_open(&epfd);
    close_fd_if_open(&wfd);
    close_fd_if_open(&rfd);
    close_file_if_open(&epf);
    close_file_if_open(&wf);
    close_file_if_open(&rf);

    rf = wf = epf = NULL;
    rfd = wfd = epfd = -1;
    ret = pipe_create(&rf, &wf);
    test_check(ret == 0, "epoll oneshot create pipe");
    if (ret < 0)
        return;

    do {
        rfd = fd_alloc(proc_current(), rf);
        test_check(rfd >= 0, "epoll oneshot alloc rfd");
        if (rfd < 0)
            break;
        wfd = fd_alloc(proc_current(), wf);
        test_check(wfd >= 0, "epoll oneshot alloc wfd");
        if (wfd < 0)
            break;
        rf = NULL;
        wf = NULL;

        ret = epoll_create_file(&epf);
        test_check(ret == 0, "epoll oneshot create epf");
        if (ret < 0)
            break;
        epfd = fd_alloc(proc_current(), epf);
        test_check(epfd >= 0, "epoll oneshot alloc epfd");
        if (epfd < 0)
            break;
        epf = NULL;

        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLONESHOT,
            .data = 0xD4,
        };
        ret = epoll_ctl_fd(epfd, EPOLL_CTL_ADD, rfd, &ev);
        test_check(ret == 0, "epoll oneshot add");
        if (ret < 0)
            break;

        struct epoll_event events[4];
        ssize_t wr = fd_write_once(wfd, "X", 1);
        test_check(wr == 1, "epoll oneshot write first");

        memset(events, 0, sizeof(events));
        int ready = epoll_wait_events(epfd, events, 4, 50);
        test_check(ready > 0, "epoll oneshot first ready");
        test_check(epoll_has_event(events, ready, 0xD4, EPOLLIN),
                   "epoll oneshot first mask");

        memset(events, 0, sizeof(events));
        ready = epoll_wait_events(epfd, events, 4, 0);
        test_check(ready == 0, "epoll oneshot disarmed");

        char rbuf[8];
        ssize_t rd = fd_read_once(rfd, rbuf, sizeof(rbuf));
        test_check(rd == 1, "epoll oneshot read first");

        wr = fd_write_once(wfd, "Y", 1);
        test_check(wr == 1, "epoll oneshot write second");
        memset(events, 0, sizeof(events));
        ready = epoll_wait_events(epfd, events, 4, 0);
        test_check(ready == 0, "epoll oneshot still disarmed");

        ret = epoll_ctl_fd(epfd, EPOLL_CTL_MOD, rfd, &ev);
        test_check(ret == 0, "epoll oneshot mod rearm");
        if (ret < 0)
            break;

        memset(events, 0, sizeof(events));
        ready = epoll_wait_events(epfd, events, 4, 50);
        test_check(ready > 0, "epoll oneshot rearm ready");
        test_check(epoll_has_event(events, ready, 0xD4, EPOLLIN),
                   "epoll oneshot rearm mask");
        rd = fd_read_once(rfd, rbuf, sizeof(rbuf));
        test_check(rd == 1, "epoll oneshot read second");
    } while (0);

    close_fd_if_open(&epfd);
    close_fd_if_open(&wfd);
    close_fd_if_open(&rfd);
    close_file_if_open(&epf);
    close_file_if_open(&wf);
    close_file_if_open(&rf);
}

static void test_eventfd_syscall_semantics(void) {
    int efd = -1;
    int efd_sem = -1;
    int efd_cloexec = -1;
    int efd_width = -1;

    int64_t ret64 = sys_eventfd2(0, 0x4U, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "eventfd2 invalid flags einval");

    ret64 = sys_eventfd2(0, O_NONBLOCK, 0, 0, 0, 0);
    test_check(ret64 >= 0, "eventfd2 create nonblock");
    if (ret64 < 0)
        return;
    efd = (int)ret64;

    uint64_t counter = 0;
    ssize_t rd = fd_read_once(efd, &counter, sizeof(counter));
    test_check(rd == -EAGAIN, "eventfd2 empty read eagain");

    counter = 2;
    ssize_t wr = fd_write_once(efd, &counter, sizeof(counter));
    test_check(wr == (ssize_t)sizeof(counter), "eventfd2 write");

    counter = 0;
    rd = fd_read_once(efd, &counter, sizeof(counter));
    test_check(rd == (ssize_t)sizeof(counter), "eventfd2 read");
    if (rd == (ssize_t)sizeof(counter))
        test_check(counter == 2, "eventfd2 read value");

    ret64 = sys_eventfd2(2, TEST_EFD_SEMAPHORE | O_NONBLOCK, 0, 0, 0, 0);
    test_check(ret64 >= 0, "eventfd2 semaphore create");
    if (ret64 >= 0) {
        efd_sem = (int)ret64;
        counter = 0;
        rd = fd_read_once(efd_sem, &counter, sizeof(counter));
        test_check(rd == (ssize_t)sizeof(counter), "eventfd2 semaphore read1");
        if (rd == (ssize_t)sizeof(counter))
            test_check(counter == 1, "eventfd2 semaphore value1");
        counter = 0;
        rd = fd_read_once(efd_sem, &counter, sizeof(counter));
        test_check(rd == (ssize_t)sizeof(counter), "eventfd2 semaphore read2");
        if (rd == (ssize_t)sizeof(counter))
            test_check(counter == 1, "eventfd2 semaphore value2");
        rd = fd_read_once(efd_sem, &counter, sizeof(counter));
        test_check(rd == -EAGAIN, "eventfd2 semaphore drained");
    }

    ret64 = sys_eventfd2(0, O_NONBLOCK | O_CLOEXEC, 0, 0, 0, 0);
    test_check(ret64 >= 0, "eventfd2 cloexec create");
    if (ret64 >= 0) {
        efd_cloexec = (int)ret64;
        test_check(fd_has_cloexec(efd_cloexec), "eventfd2 cloexec set");
    }

    ret64 = sys_eventfd2(0, (1ULL << 32) | O_NONBLOCK, 0, 0, 0, 0);
    test_check(ret64 >= 0, "eventfd2 flags width");
    if (ret64 >= 0)
        efd_width = (int)ret64;

    close_fd_if_open(&efd);
    close_fd_if_open(&efd_sem);
    close_fd_if_open(&efd_cloexec);
    close_fd_if_open(&efd_width);
}

static void test_copy_file_range_syscall_semantics(void) {
    static const char src_payload[] = "abcdefghij";
    int srcfd = -1;
    int dstfd = -1;
    int dst2fd = -1;
    int dirfd = -1;
    int prfd = -1;
    int pwfd = -1;
    struct file *srcf = NULL;
    struct file *dstf = NULL;
    struct file *dst2f = NULL;
    struct file *dirf = NULL;
    struct file *pr = NULL;
    struct file *pw = NULL;
    struct user_map_ctx um = {0};
    bool mapped = false;
    bool mounted = false;

    int ret = prepare_tmpfs_mount();
    test_check(ret == 0, "copy_file_range mount");
    if (ret < 0)
        goto out;
    mounted = true;

    ret = vfs_open(VFS_IPC_MNT "/cfr_src.bin", O_CREAT | O_RDWR | O_TRUNC, 0644,
                   &srcf);
    test_check(ret == 0, "copy_file_range open src");
    if (ret < 0)
        goto out;

    ret = vfs_open(VFS_IPC_MNT "/cfr_dst.bin", O_CREAT | O_RDWR | O_TRUNC, 0644,
                   &dstf);
    test_check(ret == 0, "copy_file_range open dst");
    if (ret < 0)
        goto out;

    ret = vfs_open(VFS_IPC_MNT "/cfr_dst2.bin", O_CREAT | O_RDWR | O_TRUNC, 0644,
                   &dst2f);
    test_check(ret == 0, "copy_file_range open dst2");
    if (ret < 0)
        goto out;

    srcfd = fd_alloc(proc_current(), srcf);
    dstfd = fd_alloc(proc_current(), dstf);
    dst2fd = fd_alloc(proc_current(), dst2f);
    test_check(srcfd >= 0, "copy_file_range alloc srcfd");
    test_check(dstfd >= 0, "copy_file_range alloc dstfd");
    test_check(dst2fd >= 0, "copy_file_range alloc dst2fd");
    if (srcfd < 0 || dstfd < 0 || dst2fd < 0)
        goto out;

    srcf = NULL;
    dstf = NULL;
    dst2f = NULL;

    ssize_t wr = fd_write_once(srcfd, src_payload, sizeof(src_payload) - 1);
    test_check(wr == (ssize_t)(sizeof(src_payload) - 1), "copy_file_range write src");
    if (wr < 0)
        goto out;

    struct file *sf = fd_get(proc_current(), srcfd);
    if (sf) {
        (void)vfs_seek(sf, 0, SEEK_SET);
        file_put(sf);
    }

    int64_t ret64 = sys_copy_file_range((uint64_t)srcfd, 0, (uint64_t)dstfd, 0, 0,
                                        0);
    test_check(ret64 == 0, "copy_file_range len0");

    ret64 = sys_copy_file_range((uint64_t)srcfd, 0, (uint64_t)dstfd, 0, 1, 1);
    test_check(ret64 == -EINVAL, "copy_file_range flags_einval");

    ret64 = sys_copy_file_range((uint64_t)(srcfd + 4096), 0, (uint64_t)dstfd, 0,
                                1, 0);
    test_check(ret64 == -EBADF, "copy_file_range badfd_ebadf");

    ret64 = sys_copy_file_range((uint64_t)srcfd, 0, (uint64_t)dstfd, 0, 4, 0);
    test_check(ret64 == 4, "copy_file_range implicit_copy4");
    if (ret64 == 4) {
        off_t src_off = fd_get_offset(srcfd);
        off_t dst_off = fd_get_offset(dstfd);
        test_check(src_off == 4, "copy_file_range implicit_src_off");
        test_check(dst_off == 4, "copy_file_range implicit_dst_off");
    }

    struct file *verify = NULL;
    ret = vfs_open(VFS_IPC_MNT "/cfr_dst.bin", O_RDONLY, 0, &verify);
    test_check(ret == 0, "copy_file_range verify open dst");
    if (ret == 0 && verify) {
        char buf[8] = {0};
        ssize_t rd = vfs_read(verify, buf, 4);
        test_check(rd == 4, "copy_file_range verify dst rd");
        if (rd == 4)
            test_check(memcmp(buf, "abcd", 4) == 0, "copy_file_range verify dst data");
        vfs_close(verify);
    }

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "copy_file_range user_map");
    if (rc < 0)
        goto out;
    mapped = true;

    off_t *u_in_off = (off_t *)user_map_ptr(&um, 0);
    off_t *u_out_off = (off_t *)user_map_ptr(&um, sizeof(off_t));
    test_check(u_in_off != NULL, "copy_file_range u_in_off");
    test_check(u_out_off != NULL, "copy_file_range u_out_off");
    if (!u_in_off || !u_out_off)
        goto out;

    off_t in_off = 2;
    off_t out_off = 0;
    rc = copy_to_user(u_in_off, &in_off, sizeof(in_off));
    test_check(rc == 0, "copy_file_range copy in_off");
    rc = copy_to_user(u_out_off, &out_off, sizeof(out_off));
    test_check(rc == 0, "copy_file_range copy out_off");
    if (rc < 0)
        goto out;

    ret64 = sys_copy_file_range((uint64_t)srcfd, (uint64_t)u_in_off,
                                (uint64_t)dst2fd, (uint64_t)u_out_off, 3, 0);
    test_check(ret64 == 3, "copy_file_range explicit_copy3");
    if (ret64 == 3) {
        rc = copy_from_user(&in_off, u_in_off, sizeof(in_off));
        test_check(rc == 0, "copy_file_range read in_off");
        rc = copy_from_user(&out_off, u_out_off, sizeof(out_off));
        test_check(rc == 0, "copy_file_range read out_off");
        if (rc == 0) {
            test_check(in_off == 5, "copy_file_range explicit_in_off_advance");
            test_check(out_off == 3, "copy_file_range explicit_out_off_advance");
        }
        test_check(fd_get_offset(srcfd) == 4, "copy_file_range explicit_src_off_keep");
        test_check(fd_get_offset(dst2fd) == 0, "copy_file_range explicit_dst_off_keep");
    }

    verify = NULL;
    ret = vfs_open(VFS_IPC_MNT "/cfr_dst2.bin", O_RDONLY, 0, &verify);
    test_check(ret == 0, "copy_file_range verify open dst2");
    if (ret == 0 && verify) {
        char buf[8] = {0};
        ssize_t rd = vfs_read(verify, buf, 3);
        test_check(rd == 3, "copy_file_range verify dst2 rd");
        if (rd == 3)
            test_check(memcmp(buf, "cde", 3) == 0, "copy_file_range verify dst2 data");
        vfs_close(verify);
    }

    ret64 = sys_copy_file_range((uint64_t)srcfd, 0x1000U, (uint64_t)dstfd, 0, 1,
                                0);
    test_check(ret64 == -EFAULT, "copy_file_range bad_off_ptr_efault");

    ret = vfs_open(VFS_IPC_MNT, O_RDONLY, 0, &dirf);
    test_check(ret == 0, "copy_file_range open dir");
    if (ret == 0 && dirf) {
        dirfd = fd_alloc(proc_current(), dirf);
        test_check(dirfd >= 0, "copy_file_range alloc dirfd");
        if (dirfd >= 0) {
            dirf = NULL;
            ret64 = sys_copy_file_range((uint64_t)dirfd, 0, (uint64_t)dstfd, 0, 1,
                                        0);
            test_check(ret64 == -EISDIR, "copy_file_range dir_eisdir");
        }
    }

    ret = pipe_create(&pr, &pw);
    test_check(ret == 0, "copy_file_range create pipe");
    if (ret == 0) {
        prfd = fd_alloc(proc_current(), pr);
        pwfd = fd_alloc(proc_current(), pw);
        test_check(prfd >= 0, "copy_file_range alloc prfd");
        test_check(pwfd >= 0, "copy_file_range alloc pwfd");
        if (prfd >= 0)
            pr = NULL;
        if (pwfd >= 0)
            pw = NULL;
        if (prfd >= 0 && pwfd >= 0) {
            ret64 = sys_copy_file_range((uint64_t)prfd, 0, (uint64_t)dstfd, 0, 1,
                                        0);
            test_check(ret64 == -EINVAL, "copy_file_range src_pipe_einval");
            ret64 = sys_copy_file_range((uint64_t)srcfd, 0, (uint64_t)pwfd, 0, 1,
                                        0);
            test_check(ret64 == -EINVAL, "copy_file_range dst_pipe_einval");
        }
    }

out:
    close_fd_if_open(&pwfd);
    close_fd_if_open(&prfd);
    close_fd_if_open(&dirfd);
    close_fd_if_open(&dst2fd);
    close_fd_if_open(&dstfd);
    close_fd_if_open(&srcfd);
    close_file_if_open(&pw);
    close_file_if_open(&pr);
    close_file_if_open(&dirf);
    close_file_if_open(&dst2f);
    close_file_if_open(&dstf);
    close_file_if_open(&srcf);
    if (mapped)
        user_map_end(&um);
    if (mounted)
        cleanup_tmpfs_mount();
}

static void test_timerfd_syscall_semantics(void) {
    int tfd = -1;

    int64_t ret64 = sys_timerfd_create(CLOCK_MONOTONIC, 0x4U, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "timerfd_create invalid flags einval");

    ret64 = sys_timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK, 0, 0, 0, 0);
    test_check(ret64 >= 0, "timerfd_create nonblock");
    if (ret64 < 0)
        goto out;
    tfd = (int)ret64;

    ret64 = sys_timerfd_gettime((uint64_t)tfd, 0, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "timerfd_gettime null ptr efault");

    ret64 = sys_timerfd_settime((uint64_t)tfd, 0x4U, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "timerfd_settime invalid flags einval");

    ret64 = sys_timerfd_settime((uint64_t)tfd, 0, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "timerfd_settime null ptr efault");

out:
    close_fd_if_open(&tfd);
}

static void test_signalfd_syscall_semantics(void) {
    int64_t ret64 = sys_signalfd4((uint64_t)-1, 0, sizeof(sigset_t), 0, 0, 0);
    test_check(ret64 == -EFAULT, "signalfd4 null mask efault");

    ret64 = sys_signalfd4((uint64_t)-1, 0x1000U, sizeof(sigset_t) - 1, 0, 0, 0);
    test_check(ret64 == -EINVAL, "signalfd4 bad sigsetsize einval");

    ret64 = sys_signalfd4((uint64_t)-1, 0x1000U, sizeof(sigset_t), 0x4U, 0, 0);
    test_check(ret64 == -EINVAL, "signalfd4 invalid flags einval");
}

static void test_inotify_syscall_semantics(void) {
    int ifd = -1;

    int64_t ret64 = sys_inotify_init1(0x4U, 0, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "inotify_init1 invalid flags einval");

    ret64 = sys_inotify_init1(IN_NONBLOCK, 0, 0, 0, 0, 0);
    test_check(ret64 >= 0, "inotify_init1 nonblock");
    if (ret64 < 0)
        goto out;
    ifd = (int)ret64;

    ret64 = sys_inotify_add_watch((uint64_t)ifd, 0, IN_CREATE, 0, 0, 0);
    test_check(ret64 == -EFAULT, "inotify_add_watch null path efault");

    ret64 = sys_inotify_add_watch((uint64_t)ifd, 0x1000U,
                                  IN_MASK_ADD | IN_MASK_CREATE, 0, 0, 0);
    test_check(ret64 == -EINVAL, "inotify_add_watch mask_add_mask_create");

    ret64 = sys_inotify_add_watch((uint64_t)ifd, 0x1000U, IN_ONLYDIR, 0, 0, 0);
    test_check(ret64 == -EINVAL, "inotify_add_watch missing events");

    ret64 = sys_inotify_rm_watch((uint64_t)ifd, 123456U, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "inotify_rm_watch invalid wd");

    ret64 = sys_inotify_rm_watch((uint64_t)(ifd + 1024), 1, 0, 0, 0, 0);
    test_check(ret64 == -EBADF, "inotify_rm_watch badfd");

out:
    close_fd_if_open(&ifd);
}

static void test_timerfd_syscall_functional(void) {
    int tfd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;
    uint8_t *u_base = NULL;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "timerfd func user map");
    if (rc < 0)
        goto out;
    mapped = true;
    u_base = (uint8_t *)user_map_ptr(&um, 0);
    test_check(u_base != NULL, "timerfd func user ptr");
    if (!u_base)
        goto out;

    int64_t ret64 = sys_timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK, 0, 0, 0, 0);
    test_check(ret64 >= 0, "timerfd func create");
    if (ret64 < 0)
        goto out;
    tfd = (int)ret64;

    struct test_linux_itimerspec arm = {
        .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
        .it_value = { .tv_sec = 0, .tv_nsec = 20 * 1000 * 1000 },
    };
    struct test_linux_itimerspec curr = {0};
    struct test_linux_itimerspec disarm = {0};
    void *u_new = u_base;
    void *u_curr = u_base + sizeof(arm);

    rc = copy_to_user(u_new, &arm, sizeof(arm));
    test_check(rc == 0, "timerfd func copy arm");
    if (rc < 0)
        goto out;

    ret64 = sys_timerfd_settime((uint64_t)tfd, 0, (uint64_t)u_new, 0, 0, 0);
    test_check(ret64 == 0, "timerfd func settime");
    if (ret64 < 0)
        goto out;

    ret64 = sys_timerfd_gettime((uint64_t)tfd, (uint64_t)u_curr, 0, 0, 0, 0);
    test_check(ret64 == 0, "timerfd func gettime");
    if (ret64 == 0) {
        rc = copy_from_user(&curr, u_curr, sizeof(curr));
        test_check(rc == 0, "timerfd func copy curr");
        if (rc == 0) {
            bool armed = curr.it_value.tv_sec > 0 || curr.it_value.tv_nsec > 0;
            test_check(armed, "timerfd func gettime armed");
        }
    }

    uint64_t expirations = 0;
    ssize_t rd = fd_read_until_ready(tfd, &expirations, sizeof(expirations),
                                     1000ULL * 1000ULL * 1000ULL);
    test_check(rd == (ssize_t)sizeof(expirations), "timerfd func read expiry");
    if (rd == (ssize_t)sizeof(expirations))
        test_check(expirations >= 1, "timerfd func expiry count");

    rc = copy_to_user(u_new, &disarm, sizeof(disarm));
    test_check(rc == 0, "timerfd func copy disarm");
    if (rc < 0)
        goto out;
    ret64 = sys_timerfd_settime((uint64_t)tfd, 0, (uint64_t)u_new, 0, 0, 0);
    test_check(ret64 == 0, "timerfd func disarm");
    if (ret64 == 0) {
        rd = fd_read_once(tfd, &expirations, sizeof(expirations));
        test_check(rd == -EAGAIN, "timerfd func disarm eagain");
    }

out:
    close_fd_if_open(&tfd);
    if (mapped)
        user_map_end(&um);
}

static void test_timerfd_cancel_on_set_functional(void) {
    int tfd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;
    bool clock_shifted = false;
    const uint64_t shift_ns = 2ULL * TEST_NS_PER_SEC;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "timerfd cancel user map");
    if (rc < 0)
        goto out;
    mapped = true;

    uint8_t *u_base = (uint8_t *)user_map_ptr(&um, 0);
    test_check(u_base != NULL, "timerfd cancel user ptr");
    if (!u_base)
        goto out;

    void *u_new = u_base;
    void *u_clock = u_base + sizeof(struct test_linux_itimerspec);

    int64_t ret64 =
        sys_timerfd_create(CLOCK_REALTIME, O_NONBLOCK | O_CLOEXEC, 0, 0, 0, 0);
    test_check(ret64 >= 0, "timerfd cancel create");
    if (ret64 < 0)
        goto out;
    tfd = (int)ret64;
    test_check(fd_has_cloexec(tfd), "timerfd cancel cloexec");

    uint64_t now_rt_ns = time_realtime_ns();
    struct test_linux_itimerspec abs_arm = {
        .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
        .it_value = {
            .tv_sec = (time_t)((now_rt_ns + TEST_NS_PER_SEC) / TEST_NS_PER_SEC),
            .tv_nsec = (int64_t)((now_rt_ns + TEST_NS_PER_SEC) % TEST_NS_PER_SEC),
        },
    };

    rc = copy_to_user(u_new, &abs_arm, sizeof(abs_arm));
    test_check(rc == 0, "timerfd cancel copy arm");
    if (rc < 0)
        goto out;

    ret64 = sys_timerfd_settime((uint64_t)tfd,
                                TEST_TFD_TIMER_ABSTIME |
                                    TEST_TFD_TIMER_CANCEL_ON_SET,
                                (uint64_t)u_new, 0, 0, 0);
    test_check(ret64 == 0, "timerfd cancel settime");
    if (ret64 < 0)
        goto out;

    uint64_t expirations = 0;
    ssize_t rd = fd_read_once(tfd, &expirations, sizeof(expirations));
    test_check(rd == -EAGAIN, "timerfd cancel pre-change eagain");

    uint64_t changed_ns = now_rt_ns + shift_ns;
    struct timespec ts_changed = {
        .tv_sec = (time_t)(changed_ns / TEST_NS_PER_SEC),
        .tv_nsec = (int64_t)(changed_ns % TEST_NS_PER_SEC),
    };
    rc = copy_to_user(u_clock, &ts_changed, sizeof(ts_changed));
    test_check(rc == 0, "timerfd cancel copy clock");
    if (rc < 0)
        goto out;

    ret64 = sys_clock_settime(CLOCK_REALTIME, (uint64_t)u_clock, 0, 0, 0, 0);
    test_check(ret64 == 0, "timerfd cancel clock_settime");
    if (ret64 == 0)
        clock_shifted = true;
    if (ret64 < 0)
        goto out;

    rd = fd_read_once(tfd, &expirations, sizeof(expirations));
    test_check(rd == -ECANCELED, "timerfd cancel read ecanceled");

    struct test_linux_itimerspec rel_arm = {
        .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
        .it_value = { .tv_sec = 0, .tv_nsec = 20 * 1000 * 1000 },
    };
    rc = copy_to_user(u_new, &rel_arm, sizeof(rel_arm));
    test_check(rc == 0, "timerfd cancel copy rearm");
    if (rc < 0)
        goto out;

    ret64 = sys_timerfd_settime((uint64_t)tfd, 0, (uint64_t)u_new, 0, 0, 0);
    test_check(ret64 == 0, "timerfd cancel rearm");
    if (ret64 == 0) {
        rd = fd_read_until_ready(tfd, &expirations, sizeof(expirations),
                                 1000ULL * 1000ULL * 1000ULL);
        test_check(rd == (ssize_t)sizeof(expirations),
                   "timerfd cancel read after rearm");
        if (rd == (ssize_t)sizeof(expirations))
            test_check(expirations >= 1, "timerfd cancel rearm count");
    }

out:
    if (clock_shifted && mapped && u_clock) {
        uint64_t restore_ns = time_realtime_ns();
        if (restore_ns > shift_ns)
            restore_ns -= shift_ns;
        else
            restore_ns = 0;
        struct timespec ts_restore = {
            .tv_sec = (time_t)(restore_ns / TEST_NS_PER_SEC),
            .tv_nsec = (int64_t)(restore_ns % TEST_NS_PER_SEC),
        };
        if (copy_to_user(u_clock, &ts_restore, sizeof(ts_restore)) == 0)
            (void)sys_clock_settime(CLOCK_REALTIME, (uint64_t)u_clock, 0, 0, 0,
                                    0);
    }
    close_fd_if_open(&tfd);
    if (mapped)
        user_map_end(&um);
}

static void test_clock_tai_settime_functional(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int64_t old_tai_offset_ns = (int64_t)(37ULL * TEST_NS_PER_SEC);
    void *u_rt = NULL;
    void *u_tai = NULL;
    void *u_set = NULL;
    bool restore_needed = false;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "clock_tai user map");
    if (rc < 0)
        goto out;
    mapped = true;

    uint8_t *u_base = (uint8_t *)user_map_ptr(&um, 0);
    test_check(u_base != NULL, "clock_tai user ptr");
    if (!u_base)
        goto out;
    u_rt = u_base;
    u_tai = u_base + sizeof(struct timespec);
    u_set = u_base + 2 * sizeof(struct timespec);

    int64_t ret64 = sys_clock_gettime(CLOCK_REALTIME, (uint64_t)u_rt, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai get realtime before");
    if (ret64 < 0)
        goto out;
    ret64 = sys_clock_gettime(CLOCK_TAI, (uint64_t)u_tai, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai get tai before");
    if (ret64 < 0)
        goto out;

    struct timespec ts_rt_before;
    struct timespec ts_tai_before;
    rc = copy_from_user(&ts_rt_before, u_rt, sizeof(ts_rt_before));
    test_check(rc == 0, "clock_tai copy realtime before");
    if (rc < 0)
        goto out;
    rc = copy_from_user(&ts_tai_before, u_tai, sizeof(ts_tai_before));
    test_check(rc == 0, "clock_tai copy tai before");
    if (rc < 0)
        goto out;

    uint64_t rt_before_ns =
        (uint64_t)ts_rt_before.tv_sec * TEST_NS_PER_SEC + (uint64_t)ts_rt_before.tv_nsec;
    uint64_t tai_before_ns =
        (uint64_t)ts_tai_before.tv_sec * TEST_NS_PER_SEC + (uint64_t)ts_tai_before.tv_nsec;
    old_tai_offset_ns = signed_delta_ns(tai_before_ns, rt_before_ns);

    const uint64_t target_offset_ns = 45ULL * TEST_NS_PER_SEC;
    uint64_t tai_set_ns = rt_before_ns + target_offset_ns;
    if (tai_set_ns < rt_before_ns)
        tai_set_ns = UINT64_MAX;
    struct timespec ts_set = {
        .tv_sec = (time_t)(tai_set_ns / TEST_NS_PER_SEC),
        .tv_nsec = (int64_t)(tai_set_ns % TEST_NS_PER_SEC),
    };
    rc = copy_to_user(u_set, &ts_set, sizeof(ts_set));
    test_check(rc == 0, "clock_tai copy set");
    if (rc < 0)
        goto out;

    ret64 = sys_clock_settime(CLOCK_TAI, (uint64_t)u_set, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai settime");
    if (ret64 < 0)
        goto out;
    restore_needed = true;

    ret64 = sys_clock_gettime(CLOCK_REALTIME, (uint64_t)u_rt, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai get realtime after");
    if (ret64 < 0)
        goto out;
    ret64 = sys_clock_gettime(CLOCK_TAI, (uint64_t)u_tai, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai get tai after");
    if (ret64 < 0)
        goto out;

    struct timespec ts_rt_after;
    struct timespec ts_tai_after;
    rc = copy_from_user(&ts_rt_after, u_rt, sizeof(ts_rt_after));
    test_check(rc == 0, "clock_tai copy realtime after");
    if (rc < 0)
        goto out;
    rc = copy_from_user(&ts_tai_after, u_tai, sizeof(ts_tai_after));
    test_check(rc == 0, "clock_tai copy tai after");
    if (rc < 0)
        goto out;

    uint64_t rt_after_ns =
        (uint64_t)ts_rt_after.tv_sec * TEST_NS_PER_SEC + (uint64_t)ts_rt_after.tv_nsec;
    uint64_t tai_after_ns =
        (uint64_t)ts_tai_after.tv_sec * TEST_NS_PER_SEC + (uint64_t)ts_tai_after.tv_nsec;
    int64_t observed_offset_ns = signed_delta_ns(tai_after_ns, rt_after_ns);
    test_check(observed_offset_ns >= 0, "clock_tai observed offset non-negative");
    if (observed_offset_ns >= 0) {
        uint64_t drift = abs_diff_u64((uint64_t)observed_offset_ns, target_offset_ns);
        test_check(drift <= 500ULL * 1000ULL * 1000ULL,
                   "clock_tai observed offset near target");
    }

out:
    if (restore_needed && mapped && u_set) {
        uint64_t now_rt_ns = time_realtime_ns();
        uint64_t restore_tai_ns = apply_signed_offset(now_rt_ns, old_tai_offset_ns);
        struct timespec ts_restore = {
            .tv_sec = (time_t)(restore_tai_ns / TEST_NS_PER_SEC),
            .tv_nsec = (int64_t)(restore_tai_ns % TEST_NS_PER_SEC),
        };
        if (copy_to_user(u_set, &ts_restore, sizeof(ts_restore)) == 0)
            (void)sys_clock_settime(CLOCK_TAI, (uint64_t)u_set, 0, 0, 0, 0);
    }
    if (mapped)
        user_map_end(&um);
}

static void test_clock_tai_leap_offset_auto_update(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    void *u_rt = NULL;
    void *u_tai = NULL;
    void *u_set = NULL;
    uint64_t restore_rt_ns = 0;
    bool restore_needed = false;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "clock_tai leap user map");
    if (rc < 0)
        goto out;
    mapped = true;

    uint8_t *u_base = (uint8_t *)user_map_ptr(&um, 0);
    test_check(u_base != NULL, "clock_tai leap user ptr");
    if (!u_base)
        goto out;

    u_rt = u_base;
    u_tai = u_base + sizeof(struct timespec);
    u_set = u_base + 2 * sizeof(struct timespec);

    int64_t ret64 = sys_clock_gettime(CLOCK_REALTIME, (uint64_t)u_rt, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai leap get realtime before");
    if (ret64 < 0)
        goto out;

    struct timespec ts_restore_rt;
    rc = copy_from_user(&ts_restore_rt, u_rt, sizeof(ts_restore_rt));
    test_check(rc == 0, "clock_tai leap copy realtime before");
    if (rc < 0)
        goto out;

    restore_rt_ns = (uint64_t)ts_restore_rt.tv_sec * TEST_NS_PER_SEC +
                    (uint64_t)ts_restore_rt.tv_nsec;
    restore_needed = true;

    struct timespec ts_2015 = {
        .tv_sec = (time_t)TEST_UTC_2015_01_01_SEC,
        .tv_nsec = 0,
    };
    rc = copy_to_user(u_set, &ts_2015, sizeof(ts_2015));
    test_check(rc == 0, "clock_tai leap copy realtime 2015");
    if (rc < 0)
        goto out;

    ret64 = sys_clock_settime(CLOCK_REALTIME, (uint64_t)u_set, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai leap set realtime 2015");
    if (ret64 < 0)
        goto out;

    ret64 = sys_clock_gettime(CLOCK_REALTIME, (uint64_t)u_rt, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai leap get realtime 2015");
    if (ret64 < 0)
        goto out;
    ret64 = sys_clock_gettime(CLOCK_TAI, (uint64_t)u_tai, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai leap get tai 2015");
    if (ret64 < 0)
        goto out;

    struct timespec ts_rt_2015;
    struct timespec ts_tai_2015;
    rc = copy_from_user(&ts_rt_2015, u_rt, sizeof(ts_rt_2015));
    test_check(rc == 0, "clock_tai leap copy realtime 2015");
    if (rc < 0)
        goto out;
    rc = copy_from_user(&ts_tai_2015, u_tai, sizeof(ts_tai_2015));
    test_check(rc == 0, "clock_tai leap copy tai 2015");
    if (rc < 0)
        goto out;

    uint64_t rt_2015_ns = (uint64_t)ts_rt_2015.tv_sec * TEST_NS_PER_SEC +
                          (uint64_t)ts_rt_2015.tv_nsec;
    uint64_t tai_2015_ns = (uint64_t)ts_tai_2015.tv_sec * TEST_NS_PER_SEC +
                           (uint64_t)ts_tai_2015.tv_nsec;
    int64_t off_2015_ns = signed_delta_ns(tai_2015_ns, rt_2015_ns);

    struct timespec ts_2017 = {
        .tv_sec = (time_t)TEST_UTC_2017_01_01_SEC,
        .tv_nsec = 0,
    };
    rc = copy_to_user(u_set, &ts_2017, sizeof(ts_2017));
    test_check(rc == 0, "clock_tai leap copy realtime 2017");
    if (rc < 0)
        goto out;

    ret64 = sys_clock_settime(CLOCK_REALTIME, (uint64_t)u_set, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai leap set realtime 2017");
    if (ret64 < 0)
        goto out;

    ret64 = sys_clock_gettime(CLOCK_REALTIME, (uint64_t)u_rt, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai leap get realtime 2017");
    if (ret64 < 0)
        goto out;
    ret64 = sys_clock_gettime(CLOCK_TAI, (uint64_t)u_tai, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock_tai leap get tai 2017");
    if (ret64 < 0)
        goto out;

    struct timespec ts_rt_2017;
    struct timespec ts_tai_2017;
    rc = copy_from_user(&ts_rt_2017, u_rt, sizeof(ts_rt_2017));
    test_check(rc == 0, "clock_tai leap copy realtime 2017");
    if (rc < 0)
        goto out;
    rc = copy_from_user(&ts_tai_2017, u_tai, sizeof(ts_tai_2017));
    test_check(rc == 0, "clock_tai leap copy tai 2017");
    if (rc < 0)
        goto out;

    uint64_t rt_2017_ns = (uint64_t)ts_rt_2017.tv_sec * TEST_NS_PER_SEC +
                          (uint64_t)ts_rt_2017.tv_nsec;
    uint64_t tai_2017_ns = (uint64_t)ts_tai_2017.tv_sec * TEST_NS_PER_SEC +
                           (uint64_t)ts_tai_2017.tv_nsec;
    int64_t off_2017_ns = signed_delta_ns(tai_2017_ns, rt_2017_ns);

    test_check(off_2015_ns >= 0, "clock_tai leap offset 2015 non-negative");
    test_check(off_2017_ns >= 0, "clock_tai leap offset 2017 non-negative");
    if (off_2015_ns >= 0 && off_2017_ns >= 0) {
        uint64_t observed_delta_ns =
            abs_diff_u64((uint64_t)off_2017_ns, (uint64_t)off_2015_ns);
        uint64_t expected_delta_ns = 2ULL * TEST_NS_PER_SEC;
        uint64_t drift = abs_diff_u64(observed_delta_ns, expected_delta_ns);
        test_check(drift <= 500ULL * 1000ULL * 1000ULL,
                   "clock_tai leap auto update across 2015/2017");
    }

out:
    if (restore_needed && mapped && u_set) {
        struct timespec ts_restore = {
            .tv_sec = (time_t)(restore_rt_ns / TEST_NS_PER_SEC),
            .tv_nsec = (int64_t)(restore_rt_ns % TEST_NS_PER_SEC),
        };
        if (copy_to_user(u_set, &ts_restore, sizeof(ts_restore)) == 0)
            (void)sys_clock_settime(CLOCK_REALTIME, (uint64_t)u_set, 0, 0, 0, 0);
    }
    if (mapped)
        user_map_end(&um);
}

static void test_clock_raw_coarse_semantics(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "clock raw/coarse user map");
    if (rc < 0)
        return;
    mapped = true;

    uint8_t *u_base = (uint8_t *)user_map_ptr(&um, 0);
    test_check(u_base != NULL, "clock raw/coarse user ptr");
    if (!u_base)
        goto out;

    struct timespec *u_mono = (struct timespec *)u_base;
    struct timespec *u_raw = (struct timespec *)(u_base + 64);
    struct timespec *u_mono_coarse = (struct timespec *)(u_base + 128);
    struct timespec *u_rt = (struct timespec *)(u_base + 192);
    struct timespec *u_rt_coarse = (struct timespec *)(u_base + 256);
    struct timespec *u_res_mono = (struct timespec *)(u_base + 320);
    struct timespec *u_res_raw = (struct timespec *)(u_base + 384);
    struct timespec *u_res_mono_coarse = (struct timespec *)(u_base + 448);
    struct timespec *u_res_rt_coarse = (struct timespec *)(u_base + 512);

    int64_t ret64 = sys_clock_gettime(CLOCK_MONOTONIC, (uint64_t)u_mono,
                                      0, 0, 0, 0);
    test_check(ret64 == 0, "clock raw/coarse get mono");
    ret64 = sys_clock_gettime(CLOCK_MONOTONIC_RAW, (uint64_t)u_raw,
                              0, 0, 0, 0);
    test_check(ret64 == 0, "clock raw/coarse get raw");
    ret64 = sys_clock_gettime(CLOCK_MONOTONIC_COARSE, (uint64_t)u_mono_coarse,
                              0, 0, 0, 0);
    test_check(ret64 == 0, "clock raw/coarse get mono coarse");
    ret64 = sys_clock_gettime(CLOCK_REALTIME, (uint64_t)u_rt, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock raw/coarse get realtime");
    ret64 = sys_clock_gettime(CLOCK_REALTIME_COARSE, (uint64_t)u_rt_coarse,
                              0, 0, 0, 0);
    test_check(ret64 == 0, "clock raw/coarse get realtime coarse");
    ret64 = sys_clock_getres(CLOCK_MONOTONIC, (uint64_t)u_res_mono, 0, 0, 0, 0);
    test_check(ret64 == 0, "clock raw/coarse getres mono");
    ret64 = sys_clock_getres(CLOCK_MONOTONIC_RAW, (uint64_t)u_res_raw,
                             0, 0, 0, 0);
    test_check(ret64 == 0, "clock raw/coarse getres raw");
    ret64 = sys_clock_getres(CLOCK_MONOTONIC_COARSE, (uint64_t)u_res_mono_coarse,
                             0, 0, 0, 0);
    test_check(ret64 == 0, "clock raw/coarse getres mono coarse");
    ret64 = sys_clock_getres(CLOCK_REALTIME_COARSE, (uint64_t)u_res_rt_coarse,
                             0, 0, 0, 0);
    test_check(ret64 == 0, "clock raw/coarse getres realtime coarse");
    if (ret64 < 0)
        goto out;

    struct timespec ts_mono = {0};
    struct timespec ts_raw = {0};
    struct timespec ts_mono_coarse = {0};
    struct timespec ts_rt = {0};
    struct timespec ts_rt_coarse = {0};
    struct timespec ts_res_mono = {0};
    struct timespec ts_res_raw = {0};
    struct timespec ts_res_mono_coarse = {0};
    struct timespec ts_res_rt_coarse = {0};
    rc = copy_from_user(&ts_mono, u_mono, sizeof(ts_mono));
    test_check(rc == 0, "clock raw/coarse copy mono");
    rc = copy_from_user(&ts_raw, u_raw, sizeof(ts_raw));
    test_check(rc == 0, "clock raw/coarse copy raw");
    rc = copy_from_user(&ts_mono_coarse, u_mono_coarse, sizeof(ts_mono_coarse));
    test_check(rc == 0, "clock raw/coarse copy mono coarse");
    rc = copy_from_user(&ts_rt, u_rt, sizeof(ts_rt));
    test_check(rc == 0, "clock raw/coarse copy realtime");
    rc = copy_from_user(&ts_rt_coarse, u_rt_coarse, sizeof(ts_rt_coarse));
    test_check(rc == 0, "clock raw/coarse copy realtime coarse");
    rc = copy_from_user(&ts_res_mono, u_res_mono, sizeof(ts_res_mono));
    test_check(rc == 0, "clock raw/coarse copyres mono");
    rc = copy_from_user(&ts_res_raw, u_res_raw, sizeof(ts_res_raw));
    test_check(rc == 0, "clock raw/coarse copyres raw");
    rc = copy_from_user(&ts_res_mono_coarse, u_res_mono_coarse,
                        sizeof(ts_res_mono_coarse));
    test_check(rc == 0, "clock raw/coarse copyres mono coarse");
    rc = copy_from_user(&ts_res_rt_coarse, u_res_rt_coarse,
                        sizeof(ts_res_rt_coarse));
    test_check(rc == 0, "clock raw/coarse copyres realtime coarse");

    uint64_t mono_ns = timespec_to_ns_u64(&ts_mono);
    uint64_t raw_ns = timespec_to_ns_u64(&ts_raw);
    uint64_t mono_coarse_ns = timespec_to_ns_u64(&ts_mono_coarse);
    uint64_t rt_ns = timespec_to_ns_u64(&ts_rt);
    uint64_t rt_coarse_ns = timespec_to_ns_u64(&ts_rt_coarse);
    uint64_t res_mono_ns = timespec_to_ns_u64(&ts_res_mono);
    uint64_t res_raw_ns = timespec_to_ns_u64(&ts_res_raw);
    uint64_t res_mono_coarse_ns = timespec_to_ns_u64(&ts_res_mono_coarse);
    uint64_t res_rt_coarse_ns = timespec_to_ns_u64(&ts_res_rt_coarse);

    test_check(res_mono_ns > 0, "clock raw/coarse mono res positive");
    test_check(res_raw_ns > 0, "clock raw/coarse raw res positive");
    test_check(res_mono_coarse_ns > 0,
               "clock raw/coarse mono coarse res positive");
    test_check(res_rt_coarse_ns > 0,
               "clock raw/coarse realtime coarse res positive");
    test_check(res_mono_coarse_ns >= res_mono_ns,
               "clock raw/coarse mono coarse res no finer");
    test_check(res_rt_coarse_ns >= res_mono_ns,
               "clock raw/coarse realtime coarse res no finer");

    uint64_t mono_coarse_diff = (mono_ns >= mono_coarse_ns)
                                    ? (mono_ns - mono_coarse_ns)
                                    : (mono_coarse_ns - mono_ns);
    uint64_t rt_coarse_diff = (rt_ns >= rt_coarse_ns)
                                  ? (rt_ns - rt_coarse_ns)
                                  : (rt_coarse_ns - rt_ns);
    test_check(mono_coarse_ns <= mono_ns, "clock raw/coarse mono coarse <= mono");
    test_check(rt_coarse_ns <= rt_ns, "clock raw/coarse realtime coarse <= rt");
    test_check(mono_coarse_diff <= res_mono_coarse_ns + res_mono_ns,
               "clock raw/coarse mono coarse bounded drift");
    test_check(rt_coarse_diff <= res_rt_coarse_ns + res_mono_ns,
               "clock raw/coarse realtime coarse bounded drift");

    test_check(raw_ns >= mono_coarse_ns, "clock raw/coarse raw sane lower bound");
    uint64_t raw_with_slack = raw_ns;
    if (UINT64_MAX - raw_with_slack < res_raw_ns)
        raw_with_slack = UINT64_MAX;
    else
        raw_with_slack += res_raw_ns;
    if (UINT64_MAX - raw_with_slack < res_mono_ns)
        raw_with_slack = UINT64_MAX;
    else
        raw_with_slack += res_mono_ns;
    test_check(raw_with_slack >= mono_ns, "clock raw/coarse raw close to mono");

out:
    if (mapped)
        user_map_end(&um);
}

static void test_signalfd_syscall_functional(void) {
    int sfd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;
    bool blocked_saved = false;
    sigset_t old_blocked = 0;
    sigset_t test_mask = (1ULL << (SIGUSR1 - 1));
    struct process *p = proc_current();
    test_check(p != NULL, "signalfd func proc current");
    if (!p)
        return;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "signalfd func user map");
    if (rc < 0)
        goto out;
    mapped = true;

    void *u_mask = user_map_ptr(&um, 0);
    test_check(u_mask != NULL, "signalfd func user ptr");
    if (!u_mask)
        goto out;

    rc = copy_to_user(u_mask, &test_mask, sizeof(test_mask));
    test_check(rc == 0, "signalfd func copy mask");
    if (rc < 0)
        goto out;

    old_blocked = __atomic_load_n(&p->sig_blocked, __ATOMIC_ACQUIRE);
    __atomic_store_n(&p->sig_blocked, old_blocked | test_mask, __ATOMIC_RELEASE);
    blocked_saved = true;

    int64_t ret64 =
        sys_signalfd4((uint64_t)-1, (uint64_t)u_mask, sizeof(sigset_t),
                      O_NONBLOCK, 0, 0);
    test_check(ret64 >= 0, "signalfd func create");
    if (ret64 < 0)
        goto out;
    sfd = (int)ret64;

    struct test_linux_signalfd_siginfo info = {0};
    ssize_t rd = fd_read_once(sfd, &info, sizeof(info));
    test_check(rd == -EAGAIN, "signalfd func empty eagain");

    int sret = signal_send(p->pid, SIGUSR1);
    test_check(sret == 0, "signalfd func send sigusr1");
    if (sret == 0) {
        rd = fd_read_until_ready(sfd, &info, sizeof(info),
                                 500ULL * 1000ULL * 1000ULL);
        test_check(rd == (ssize_t)sizeof(info), "signalfd func read siginfo");
        if (rd == (ssize_t)sizeof(info))
            test_check(info.ssi_signo == SIGUSR1, "signalfd func signo");
    }

    rd = fd_read_once(sfd, &info, sizeof(info));
    test_check(rd == -EAGAIN, "signalfd func drained eagain");

out:
    if (blocked_saved)
        __atomic_store_n(&p->sig_blocked, old_blocked, __ATOMIC_RELEASE);
    __atomic_fetch_and(&p->sig_pending, ~test_mask, __ATOMIC_RELEASE);
    close_fd_if_open(&sfd);
    if (mapped)
        user_map_end(&um);
}

static void test_signalfd_syscall_rebind(void) {
    int sfd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;
    bool blocked_saved = false;
    sigset_t old_blocked = 0;
    sigset_t mask_usr1 = (1ULL << (SIGUSR1 - 1));
    sigset_t mask_usr2 = (1ULL << (SIGUSR2 - 1));
    sigset_t clear_mask = mask_usr1 | mask_usr2;
    struct process *p = proc_current();
    test_check(p != NULL, "signalfd rebind proc current");
    if (!p)
        return;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "signalfd rebind user map");
    if (rc < 0)
        goto out;
    mapped = true;

    void *u_mask = user_map_ptr(&um, 0);
    test_check(u_mask != NULL, "signalfd rebind user ptr");
    if (!u_mask)
        goto out;

    old_blocked = __atomic_load_n(&p->sig_blocked, __ATOMIC_ACQUIRE);
    __atomic_store_n(&p->sig_blocked, old_blocked | clear_mask, __ATOMIC_RELEASE);
    blocked_saved = true;
    __atomic_fetch_and(&p->sig_pending, ~clear_mask, __ATOMIC_RELEASE);

    rc = copy_to_user(u_mask, &mask_usr1, sizeof(mask_usr1));
    test_check(rc == 0, "signalfd rebind copy mask1");
    if (rc < 0)
        goto out;

    int64_t ret64 =
        sys_signalfd4((uint64_t)-1, (uint64_t)u_mask, sizeof(sigset_t),
                      O_NONBLOCK | O_CLOEXEC, 0, 0);
    test_check(ret64 >= 0, "signalfd rebind create");
    if (ret64 < 0)
        goto out;
    sfd = (int)ret64;
    test_check(fd_has_cloexec(sfd), "signalfd rebind cloexec");

    int sret = signal_send(p->pid, SIGUSR2);
    test_check(sret == 0, "signalfd rebind send sigusr2");

    struct test_linux_signalfd_siginfo info = {0};
    ssize_t rd = fd_read_once(sfd, &info, sizeof(info));
    test_check(rd == -EAGAIN, "signalfd rebind filtered eagain");

    rc = copy_to_user(u_mask, &mask_usr2, sizeof(mask_usr2));
    test_check(rc == 0, "signalfd rebind copy mask2");
    if (rc < 0)
        goto out;

    ret64 =
        sys_signalfd4((uint64_t)sfd, (uint64_t)u_mask, sizeof(sigset_t), 0, 0, 0);
    test_check(ret64 == sfd, "signalfd rebind update existing");

    rd = fd_read_until_ready(sfd, &info, sizeof(info),
                             500ULL * 1000ULL * 1000ULL);
    test_check(rd == (ssize_t)sizeof(info), "signalfd rebind read sigusr2");
    if (rd == (ssize_t)sizeof(info))
        test_check(info.ssi_signo == SIGUSR2, "signalfd rebind signo sigusr2");

    sret = signal_send(p->pid, SIGUSR1);
    test_check(sret == 0, "signalfd rebind send sigusr1");
    rd = fd_read_once(sfd, &info, sizeof(info));
    test_check(rd == -EAGAIN, "signalfd rebind usr1 filtered");

out:
    if (blocked_saved)
        __atomic_store_n(&p->sig_blocked, old_blocked, __ATOMIC_RELEASE);
    __atomic_fetch_and(&p->sig_pending, ~clear_mask, __ATOMIC_RELEASE);
    close_fd_if_open(&sfd);
    if (mapped)
        user_map_end(&um);
}

struct pidfd_worker_ctx {
    volatile int started;
    volatile int exit_now;
};

static int pidfd_controlled_exit_worker(void *arg) {
    struct pidfd_worker_ctx *ctx = (struct pidfd_worker_ctx *)arg;
    if (!ctx)
        proc_exit(1);
    ctx->started = 1;
    while (!ctx->exit_now)
        proc_yield();
    proc_exit(0);
}

static void test_pidfd_syscall_semantics(void) {
    struct process *self = proc_current();
    test_check(self != NULL, "pidfd proc current");
    if (!self)
        return;

    int pidfd = -1;
    struct user_map_ctx um = {0};
    bool um_active = false;

    int64_t ret64 = sys_pidfd_open(0, 0, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "pidfd_open pid 0 einval");

    ret64 = sys_pidfd_open((uint64_t)(uint32_t)self->pid, 1ULL << 32, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "pidfd_open flags width einval");

    ret64 = sys_pidfd_open((uint64_t)(uint32_t)self->pid, O_CLOEXEC, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "pidfd_open unsupported flags einval");

    ret64 = sys_pidfd_open((uint64_t)(uint32_t)self->pid, O_NONBLOCK, 0, 0, 0, 0);
    test_check(ret64 >= 0, "pidfd_open nonblock");
    if (ret64 < 0)
        goto out;
    pidfd = (int)ret64;
    test_check(fd_has_cloexec(pidfd), "pidfd_open cloexec set");

    ret64 = sys_pidfd_send_signal((uint64_t)pidfd, 0, 0, 1, 0, 0);
    test_check(ret64 == -EINVAL, "pidfd_send_signal bad flags einval");

    ret64 = sys_pidfd_send_signal((uint64_t)pidfd, NSIG + 1U, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "pidfd_send_signal bad sig einval");

    ret64 = sys_pidfd_send_signal((uint64_t)pidfd, 0, 1, 0, 0, 0);
    test_check(ret64 == -EFAULT, "pidfd_send_signal info bad ptr efault");

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "pidfd_send_signal info user_map");
    if (rc == 0) {
        um_active = true;
        siginfo_t info = {0};
        info.si_signo = SIGUSR1;
        siginfo_t *u_info = (siginfo_t *)user_map_ptr(&um, 0);
        rc = copy_to_user(u_info, &info, sizeof(info));
        test_check(rc == 0, "pidfd_send_signal info copy_to_user");
        if (rc == 0) {
            ret64 = sys_pidfd_send_signal((uint64_t)pidfd, 0,
                                          (uint64_t)(uintptr_t)u_info, 0, 0, 0);
            test_check(ret64 == 0, "pidfd_send_signal info accepted");
        }
    }

    ret64 = sys_pidfd_send_signal((uint64_t)-1, 0, 0, 0, 0, 0);
    test_check(ret64 == -EBADF, "pidfd_send_signal bad fd ebadf");

    ret64 = sys_pidfd_send_signal((uint64_t)pidfd, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "pidfd_send_signal sig0 alive");

out:
    if (um_active)
        user_map_end(&um);
    close_fd_if_open(&pidfd);
}

static void test_pidfd_syscall_functional(void) {
    int pidfd = -1;
    bool child_reaped = false;
    struct pidfd_worker_ctx ctx = {0};
    struct process *child =
        kthread_create_joinable(pidfd_controlled_exit_worker, &ctx, "pidfdex");
    test_check(child != NULL, "pidfd func create child");
    if (!child)
        return;

    sched_enqueue(child);
    for (int spins = 0; spins < 2000 && !ctx.started; spins++)
        proc_yield();
    test_check(ctx.started != 0, "pidfd func child started");
    if (!ctx.started)
        goto out;

    int64_t ret64 = sys_pidfd_open((uint64_t)(uint32_t)child->pid, 0, 0, 0, 0, 0);
    test_check(ret64 >= 0, "pidfd func open child");
    if (ret64 < 0) {
        ctx.exit_now = 1;
        goto out;
    }
    pidfd = (int)ret64;

    ret64 = sys_pidfd_send_signal((uint64_t)pidfd, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "pidfd func sig0 before exit");

    struct file *pf = fd_get(proc_current(), pidfd);
    test_check(pf != NULL, "pidfd func fd_get");
    if (pf) {
        int pe = vfs_poll(pf, POLLIN | POLLHUP);
        test_check((pe & (POLLIN | POLLHUP)) == 0, "pidfd func poll before exit");
        file_put(pf);
    }

    ctx.exit_now = 1;
    int status = 0;
    bool reaped = wait_pid_exit_bounded(child->pid, 2ULL * TEST_NS_PER_SEC, &status);
    test_check(reaped, "pidfd func child reaped");
    if (!reaped)
        goto out;
    child_reaped = true;

    pf = fd_get(proc_current(), pidfd);
    test_check(pf != NULL, "pidfd func fd_get after exit");
    if (pf) {
        int pe = vfs_poll(pf, POLLIN | POLLHUP);
        test_check((pe & POLLIN) != 0, "pidfd func pollin after exit");
        file_put(pf);
    }

    ret64 = sys_pidfd_send_signal((uint64_t)pidfd, 0, 0, 0, 0, 0);
    test_check(ret64 == -ESRCH, "pidfd func sig0 after exit esrch");

out:
    close_fd_if_open(&pidfd);
    if (!child_reaped) {
        ctx.exit_now = 1;
        int ignored = 0;
        (void)wait_pid_exit_bounded(child->pid, 2ULL * TEST_NS_PER_SEC, &ignored);
    }
}

static void test_waitid_pidfd_functional(void) {
    enum { P_PIDFD = 3 };
    int pidfd = -1;
    bool child_reaped = false;
    pid_t child_pid = 0;
    struct user_map_ctx um = {0};
    bool um_active = false;
    siginfo_t *u_info = NULL;
    siginfo_t info = {0};
    struct pidfd_worker_ctx ctx = {0};
    struct process *child =
        kthread_create_joinable(pidfd_controlled_exit_worker, &ctx, "pidfdwait");
    test_check(child != NULL, "waitid pidfd create child");
    if (!child)
        return;
    child_pid = child->pid;

    sched_enqueue(child);
    for (int spins = 0; spins < 2000 && !ctx.started; spins++)
        proc_yield();
    test_check(ctx.started != 0, "waitid pidfd child started");
    if (!ctx.started)
        goto out;

    int64_t ret64 = sys_pidfd_open((uint64_t)(uint32_t)child->pid, 0, 0, 0, 0, 0);
    test_check(ret64 >= 0, "waitid pidfd open child");
    if (ret64 < 0) {
        ctx.exit_now = 1;
        goto out;
    }
    pidfd = (int)ret64;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "waitid pidfd user_map");
    if (rc < 0)
        goto out;
    um_active = true;
    u_info = (siginfo_t *)user_map_ptr(&um, 0);

    ret64 = sys_waitid(P_PIDFD, (uint64_t)(uint32_t)pidfd,
                       (uint64_t)(uintptr_t)u_info,
                       WEXITED | WSTOPPED | WCONTINUED | WNOHANG, 0, 0);
    test_check(ret64 == 0, "waitid pidfd wnohang before exit");
    if (ret64 == 0) {
        rc = copy_from_user(&info, u_info, sizeof(info));
        test_check(rc == 0, "waitid pidfd wnohang before exit copy");
        if (rc == 0)
            test_check(info.si_pid == 0, "waitid pidfd wnohang before exit none");
    }

    ret64 = sys_waitid(P_PIDFD, (uint64_t)(uint32_t)pidfd,
                       (uint64_t)(uintptr_t)u_info,
                       WSTOPPED | WCONTINUED | WNOHANG, 0, 0);
    test_check(ret64 == 0, "waitid pidfd stopped continued wnohang");
    if (ret64 == 0) {
        rc = copy_from_user(&info, u_info, sizeof(info));
        test_check(rc == 0, "waitid pidfd stopped continued copy");
        if (rc == 0)
            test_check(info.si_pid == 0, "waitid pidfd stopped continued none");
    }

    ctx.exit_now = 1;

    ret64 = sys_waitid(P_PIDFD, (uint64_t)(uint32_t)pidfd,
                       (uint64_t)(uintptr_t)u_info, WEXITED | WNOWAIT, 0, 0);
    test_check(ret64 == 0, "waitid pidfd wnowait observe child");
    if (ret64 == 0) {
        rc = copy_from_user(&info, u_info, sizeof(info));
        test_check(rc == 0, "waitid pidfd wnowait copy");
        if (rc == 0)
            test_check(info.si_pid == child_pid, "waitid pidfd wnowait pid");
    }

    ret64 = sys_waitid(P_PIDFD, (uint64_t)(uint32_t)pidfd,
                       (uint64_t)(uintptr_t)u_info, WEXITED | WNOHANG, 0, 0);
    test_check(ret64 == 0, "waitid pidfd reap child");
    if (ret64 == 0) {
        rc = copy_from_user(&info, u_info, sizeof(info));
        test_check(rc == 0, "waitid pidfd reap child copy");
        if (rc == 0)
            test_check(info.si_pid == child_pid, "waitid pidfd reap child pid");
        child_reaped = true;
    }

    ret64 = sys_waitid(P_PIDFD, (uint64_t)(uint32_t)pidfd,
                       (uint64_t)(uintptr_t)u_info, WEXITED | WNOHANG, 0, 0);
    test_check(ret64 == -ECHILD, "waitid pidfd after reap echid");

    ret64 = sys_waitid(P_PIDFD, (uint64_t)-1, 0, WEXITED | WNOHANG, 0, 0);
    test_check(ret64 == -EBADF, "waitid pidfd bad fd");

out:
    if (um_active)
        user_map_end(&um);
    close_fd_if_open(&pidfd);
    if (!child_reaped) {
        ctx.exit_now = 1;
        int ignored = 0;
        (void)wait_pid_exit_bounded(child_pid, 2ULL * TEST_NS_PER_SEC, &ignored);
    }
}

static void test_pidfd_getfd_syscall_functional(void) {
    struct process *self = proc_current();
    test_check(self != NULL, "pidfd_getfd proc current");
    if (!self)
        return;

    int pidfd = -1;
    int dupfd = -1;
    int rfd = -1;
    int wfd = -1;
    struct file *rf = NULL;
    struct file *wf = NULL;

    int ret = pipe_create(&rf, &wf);
    test_check(ret == 0, "pidfd_getfd create pipe");
    if (ret < 0)
        goto out;

    rfd = fd_alloc(self, rf);
    wfd = fd_alloc(self, wf);
    test_check(rfd >= 0, "pidfd_getfd alloc rfd");
    test_check(wfd >= 0, "pidfd_getfd alloc wfd");
    if (rfd < 0 || wfd < 0)
        goto out;
    rf = NULL;
    wf = NULL;

    int64_t ret64 = sys_pidfd_open((uint64_t)(uint32_t)self->pid, 0, 0, 0, 0, 0);
    test_check(ret64 >= 0, "pidfd_getfd open self pidfd");
    if (ret64 < 0)
        goto out;
    pidfd = (int)ret64;

    ret64 = sys_pidfd_getfd((uint64_t)pidfd, (uint64_t)(uint32_t)rfd, 1, 0, 0, 0);
    test_check(ret64 == -EINVAL, "pidfd_getfd bad flags einval");

    ret64 = sys_pidfd_getfd((uint64_t)-1, (uint64_t)(uint32_t)rfd, 0, 0, 0, 0);
    test_check(ret64 == -EBADF, "pidfd_getfd bad pidfd ebadf");

    ret64 = sys_pidfd_getfd((uint64_t)(uint32_t)rfd, (uint64_t)(uint32_t)rfd, 0, 0,
                            0, 0);
    test_check(ret64 == -EBADF, "pidfd_getfd nonpidfd ebadf");

    ret64 = sys_pidfd_getfd((uint64_t)pidfd, (uint64_t)-1, 0, 0, 0, 0);
    test_check(ret64 == -EBADF, "pidfd_getfd bad target ebadf");

    ret = fd_limit_rights(self, rfd, FD_RIGHT_READ | FD_RIGHT_DUP, NULL);
    test_check(ret == 0, "pidfd_getfd limit target rights");
    if (ret == 0) {
        uint32_t limited_rights = 0;
        ret = fd_get_rights(self, rfd, &limited_rights);
        test_check(ret == 0, "pidfd_getfd read limited rights");
        if (ret == 0)
            test_check(limited_rights == (FD_RIGHT_READ | FD_RIGHT_DUP),
                       "pidfd_getfd limited rights exact");
    }

    ret64 = sys_pidfd_getfd((uint64_t)pidfd, (uint64_t)(uint32_t)rfd, 0, 0, 0, 0);
    test_check(ret64 >= 0, "pidfd_getfd dup read end");
    if (ret64 < 0)
        goto out;
    dupfd = (int)ret64;
    test_check(fd_has_cloexec(dupfd), "pidfd_getfd cloexec set");
    {
        uint32_t dup_rights = 0;
        ret = fd_get_rights(self, dupfd, &dup_rights);
        test_check(ret == 0, "pidfd_getfd dup rights read");
        if (ret == 0)
            test_check(dup_rights == (FD_RIGHT_READ | FD_RIGHT_DUP),
                       "pidfd_getfd dup rights preserved");
    }

    ret = fd_limit_rights(self, rfd, FD_RIGHT_READ, NULL);
    test_check(ret == 0, "pidfd_getfd drop dup right");
    if (ret == 0) {
        ret64 = sys_pidfd_getfd((uint64_t)pidfd, (uint64_t)(uint32_t)rfd, 0, 0, 0,
                                0);
        test_check(ret64 == -EBADF, "pidfd_getfd without dup right denied");
    }

    ssize_t wr = fd_write_once(wfd, "Z", 1);
    test_check(wr == 1, "pidfd_getfd seed pipe");
    if (wr == 1) {
        char ch = 0;
        ssize_t rd = fd_read_once(dupfd, &ch, 1);
        test_check(rd == 1, "pidfd_getfd read dupfd");
        if (rd == 1)
            test_check(ch == 'Z', "pidfd_getfd payload");
    }

out:
    close_fd_if_open(&dupfd);
    close_fd_if_open(&pidfd);
    close_fd_if_open(&wfd);
    close_fd_if_open(&rfd);
    close_file_if_open(&wf);
    close_file_if_open(&rf);
}

static void test_inotify_syscall_functional(void) {
    int ifd = -1;
    int wd = -1;
    struct file *f = NULL;
    struct user_map_ctx um = {0};
    bool mapped = false;
    bool mounted = false;

    int ret = prepare_tmpfs_mount();
    test_check(ret == 0, "inotify func mount");
    if (ret < 0)
        goto out;
    mounted = true;

    ret = vfs_mkdir(VFS_IPC_MNT "/watch", 0755);
    test_check(ret == 0, "inotify func mkdir watch");
    if (ret < 0)
        goto out;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "inotify func user map");
    if (rc < 0)
        goto out;
    mapped = true;

    char *u_path = (char *)user_map_ptr(&um, 0);
    test_check(u_path != NULL, "inotify func user ptr");
    if (!u_path)
        goto out;

    const char *watch_path = VFS_IPC_MNT "/watch";
    rc = copy_to_user(u_path, watch_path, strlen(watch_path) + 1);
    test_check(rc == 0, "inotify func copy path");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_inotify_init1(IN_NONBLOCK, 0, 0, 0, 0, 0);
    test_check(ret64 >= 0, "inotify func init");
    if (ret64 < 0)
        goto out;
    ifd = (int)ret64;

    ret64 = sys_inotify_add_watch((uint64_t)ifd, (uint64_t)u_path,
                                  IN_CREATE | IN_DELETE, 0, 0, 0);
    test_check(ret64 > 0, "inotify func add watch");
    if (ret64 <= 0)
        goto out;
    wd = (int)ret64;

    ret = vfs_open(VFS_IPC_MNT "/watch/new.txt", O_CREAT | O_WRONLY | O_TRUNC,
                   0644, &f);
    test_check(ret == 0, "inotify func create file");
    close_file_if_open(&f);
    if (ret < 0)
        goto out;

    bool seen = inotify_wait_event(ifd, wd, IN_CREATE, "new.txt",
                                   500ULL * 1000ULL * 1000ULL);
    test_check(seen, "inotify func create event");

    ret = vfs_unlink(VFS_IPC_MNT "/watch/new.txt");
    test_check(ret == 0, "inotify func unlink file");
    if (ret == 0) {
        seen = inotify_wait_event(ifd, wd, IN_DELETE, "new.txt",
                                  500ULL * 1000ULL * 1000ULL);
        test_check(seen, "inotify func delete event");
    }

    ret64 = sys_inotify_rm_watch((uint64_t)ifd, (uint64_t)wd, 0, 0, 0, 0);
    test_check(ret64 == 0, "inotify func rm watch");
    if (ret64 == 0) {
        seen = inotify_wait_event(ifd, wd, IN_IGNORED, NULL,
                                  500ULL * 1000ULL * 1000ULL);
        test_check(seen, "inotify func ignored event");
    }

out:
    close_file_if_open(&f);
    close_fd_if_open(&ifd);
    if (mapped)
        user_map_end(&um);
    if (mounted)
        cleanup_tmpfs_mount();
}

static void test_inotify_mask_update_functional(void) {
    int ifd = -1;
    int wd = -1;
    struct file *f = NULL;
    struct user_map_ctx um = {0};
    bool mapped = false;
    bool mounted = false;

    int ret = prepare_tmpfs_mount();
    test_check(ret == 0, "inotify mask mount");
    if (ret < 0)
        goto out;
    mounted = true;

    ret = vfs_mkdir(VFS_IPC_MNT "/watch2", 0755);
    test_check(ret == 0, "inotify mask mkdir watch2");
    if (ret < 0)
        goto out;

    ret = vfs_open(VFS_IPC_MNT "/regular.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644,
                   &f);
    test_check(ret == 0, "inotify mask create regular");
    close_file_if_open(&f);
    if (ret < 0)
        goto out;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "inotify mask user map");
    if (rc < 0)
        goto out;
    mapped = true;

    char *u_dir_path = (char *)user_map_ptr(&um, 0);
    char *u_file_path = (char *)user_map_ptr(&um, 256);
    test_check(u_dir_path != NULL, "inotify mask u dir path");
    test_check(u_file_path != NULL, "inotify mask u file path");
    if (!u_dir_path || !u_file_path)
        goto out;

    const char *dir_path = VFS_IPC_MNT "/watch2";
    const char *file_path = VFS_IPC_MNT "/regular.txt";
    rc = copy_to_user(u_dir_path, dir_path, strlen(dir_path) + 1);
    test_check(rc == 0, "inotify mask copy dir path");
    rc = copy_to_user(u_file_path, file_path, strlen(file_path) + 1);
    test_check(rc == 0, "inotify mask copy file path");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_inotify_init1(IN_NONBLOCK | IN_CLOEXEC, 0, 0, 0, 0, 0);
    test_check(ret64 >= 0, "inotify mask init");
    if (ret64 < 0)
        goto out;
    ifd = (int)ret64;
    test_check(fd_has_cloexec(ifd), "inotify mask cloexec");

    ret64 = sys_inotify_add_watch((uint64_t)ifd, (uint64_t)u_dir_path, IN_CREATE,
                                  0, 0, 0);
    test_check(ret64 > 0, "inotify mask add create");
    if (ret64 <= 0)
        goto out;
    wd = (int)ret64;

    ret64 = sys_inotify_add_watch((uint64_t)ifd, (uint64_t)u_dir_path,
                                  IN_MASK_ADD | IN_DELETE, 0, 0, 0);
    test_check(ret64 == wd, "inotify mask add merge");

    ret64 = sys_inotify_add_watch((uint64_t)ifd, (uint64_t)u_dir_path,
                                  IN_MASK_CREATE | IN_CREATE, 0, 0, 0);
    test_check(ret64 == -EEXIST, "inotify mask create eexist");

    ret64 = sys_inotify_add_watch((uint64_t)ifd, (uint64_t)u_file_path,
                                  IN_ONLYDIR | IN_MODIFY, 0, 0, 0);
    test_check(ret64 == -ENOTDIR, "inotify onlydir enotdir");

    ret = vfs_open(VFS_IPC_MNT "/watch2/new2.txt", O_CREAT | O_WRONLY | O_TRUNC,
                   0644, &f);
    test_check(ret == 0, "inotify mask create file");
    close_file_if_open(&f);
    if (ret < 0)
        goto out;

    bool seen = inotify_wait_event(ifd, wd, IN_CREATE, "new2.txt",
                                   500ULL * 1000ULL * 1000ULL);
    test_check(seen, "inotify mask saw create");

    ret = vfs_unlink(VFS_IPC_MNT "/watch2/new2.txt");
    test_check(ret == 0, "inotify mask unlink file");
    if (ret == 0) {
        seen = inotify_wait_event(ifd, wd, IN_DELETE, "new2.txt",
                                  500ULL * 1000ULL * 1000ULL);
        test_check(seen, "inotify mask saw delete");
    }

out:
    close_file_if_open(&f);
    close_fd_if_open(&ifd);
    if (mapped)
        user_map_end(&um);
    if (mounted)
        cleanup_tmpfs_mount();
}

static void test_sysfs_ipc_visibility(void) {
    struct kobj *ch0 = NULL;
    struct kobj *ch1 = NULL;
    struct file *f = NULL;
    char buf[512] = {0};

    int rc = kchannel_create_pair(&ch0, &ch1);
    test_check(rc == 0, "sysfs_ipc create channel pair");
    if (rc < 0)
        return;

    rc = vfs_open("/sys/ipc/objects", O_RDONLY, 0, &f);
    test_check(rc == 0, "sysfs_ipc open objects");
    if (rc == 0) {
        ssize_t n = vfs_read(f, buf, sizeof(buf) - 1);
        test_check(n > 0, "sysfs_ipc read objects");
        if (n > 0) {
            buf[n] = '\0';
            test_check(strstr(buf, "id type refcount") != NULL,
                       "sysfs_ipc objects header");
            test_check(strstr(buf, "channel") != NULL,
                       "sysfs_ipc objects include channel");
        }
    }
    close_file_if_open(&f);

    memset(buf, 0, sizeof(buf));
    rc = vfs_open("/sys/ipc/channels", O_RDONLY, 0, &f);
    test_check(rc == 0, "sysfs_ipc open channels");
    if (rc == 0) {
        ssize_t n = vfs_read(f, buf, sizeof(buf) - 1);
        test_check(n > 0, "sysfs_ipc read channels");
        if (n > 0) {
            buf[n] = '\0';
            test_check(strstr(buf, "id refcount handle_refs") != NULL,
                       "sysfs_ipc channels header");
        }
    }
    close_file_if_open(&f);

    kobj_put(ch1);
    kobj_put(ch0);
}

int run_vfs_ipc_tests(void) {
    tests_failed = 0;
    pr_info("\n=== VFS/IPC Tests ===\n");

    test_tmpfs_vfs_semantics();
    test_umount2_flag_width_semantics();
    test_openat2_faccessat2_fchmodat2_syscall_semantics();
    test_preadv2_pwritev2_syscall_semantics();
    test_close_range_syscall_semantics();
    test_statx_syscall_semantics();
    test_pipe_semantics();
    test_pipe_fcntl_nonblock_semantics();
    test_epoll_pipe_semantics();
    test_epoll_edge_oneshot_semantics();
    test_epoll_pwait2_syscall_semantics();
    test_ppoll_pselect6_syscall_semantics();
    test_renameat2_syscall_semantics();
    test_eventfd_syscall_semantics();
    test_copy_file_range_syscall_semantics();
    test_timerfd_syscall_semantics();
    test_monotonic_progress_under_yield();
    test_timerfd_syscall_functional();
    test_timerfd_cancel_on_set_functional();
    test_clock_tai_settime_functional();
    test_clock_tai_leap_offset_auto_update();
    test_clock_raw_coarse_semantics();
    test_signalfd_syscall_semantics();
    test_signalfd_syscall_functional();
    test_signalfd_syscall_rebind();
    test_pidfd_syscall_semantics();
    test_pidfd_syscall_functional();
    test_waitid_pidfd_functional();
    test_pidfd_getfd_syscall_functional();
    test_inotify_syscall_semantics();
    test_inotify_syscall_functional();
    test_inotify_mask_update_functional();
    test_sysfs_ipc_visibility();

    if (tests_failed == 0)
        pr_info("vfs/ipc tests: all passed\n");
    else
        pr_err("vfs/ipc tests: %d failures\n", tests_failed);
    return tests_failed;
}

#else

int run_vfs_ipc_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
