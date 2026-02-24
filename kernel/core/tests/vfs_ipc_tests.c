/**
 * kernel/core/tests/vfs_ipc_tests.c - VFS/tmpfs/pipe/epoll semantic tests
 */

#include <kairos/epoll.h>
#include <kairos/epoll_internal.h>
#include <kairos/inotify.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/pipe.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
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
    test_check(ret64 == -EINVAL, "umount2 width low32 invalid");

    ret64 = sys_umount2((uint64_t)u_path, 1ULL << 32, 0, 0, 0, 0);
    test_check(ret64 == 0, "umount2 width high32 ignored");

out:
    if (mapped)
        user_map_end(&um);
    (void)vfs_umount(VFS_IPC_UMOUNT_ABI_MNT);
    (void)vfs_rmdir(VFS_IPC_UMOUNT_ABI_MNT);
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

int run_vfs_ipc_tests(void) {
    tests_failed = 0;
    pr_info("\n=== VFS/IPC Tests ===\n");

    test_tmpfs_vfs_semantics();
    test_umount2_flag_width_semantics();
    test_pipe_semantics();
    test_epoll_pipe_semantics();
    test_epoll_edge_oneshot_semantics();
    test_eventfd_syscall_semantics();
    test_copy_file_range_syscall_semantics();
    test_timerfd_syscall_semantics();
    test_timerfd_syscall_functional();
    test_timerfd_cancel_on_set_functional();
    test_signalfd_syscall_semantics();
    test_signalfd_syscall_functional();
    test_signalfd_syscall_rebind();
    test_inotify_syscall_semantics();
    test_inotify_syscall_functional();
    test_inotify_mask_update_functional();

    if (tests_failed == 0)
        pr_info("vfs/ipc tests: all passed\n");
    else
        pr_err("vfs/ipc tests: %d failures\n", tests_failed);
    return tests_failed;
}

#else

int run_vfs_ipc_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
