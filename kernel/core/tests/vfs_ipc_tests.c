/**
 * kernel/core/tests/vfs_ipc_tests.c - VFS/tmpfs/pipe/epoll semantic tests
 */

#include <kairos/epoll.h>
#include <kairos/epoll_internal.h>
#include <kairos/pipe.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/vfs.h>

#if CONFIG_KERNEL_TESTS

#define VFS_IPC_MNT "/tmp/.kairos_vfs_ipc"

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

struct blocking_read_ctx {
    struct file *r;
    volatile int started;
    ssize_t ret;
    char buf[8];
};

static int blocking_pipe_reader(void *arg) {
    struct blocking_read_ctx *ctx = (struct blocking_read_ctx *)arg;
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
        struct blocking_read_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.r = r;
        ctx.ret = -1;

        struct process *child =
            kthread_create_joinable(blocking_pipe_reader, &ctx, "pipeblk");
        test_check(child != NULL, "pipe blocking child create");
        if (!child)
            break;
        sched_enqueue(child);

        for (int i = 0; i < 2000 && !ctx.started; i++)
            proc_yield();
        test_check(ctx.started != 0, "pipe blocking child started");

        int status = 0;
        pid_t wp = proc_wait(child->pid, &status, WNOHANG);
        test_check(wp == 0, "pipe blocking wait nohang before write");

        ssize_t wr = vfs_write(w, "PING", 4);
        test_check(wr == 4, "pipe blocking write wake");

        wp = proc_wait(child->pid, &status, 0);
        test_check(wp == child->pid, "pipe blocking child reaped");
        test_check(ctx.ret == 4, "pipe blocking child read len");
        test_check(memcmp(ctx.buf, "PING", 4) == 0, "pipe blocking child read data");
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
        ssize_t rd = fd_read_once(rfd, rbuf, sizeof(rbuf));
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

int run_vfs_ipc_tests(void) {
    tests_failed = 0;
    pr_info("\n=== VFS/IPC Tests ===\n");

    test_tmpfs_vfs_semantics();
    test_pipe_semantics();
    test_epoll_pipe_semantics();

    if (tests_failed == 0)
        pr_info("vfs/ipc tests: all passed\n");
    else
        pr_err("vfs/ipc tests: %d failures\n", tests_failed);
    return tests_failed;
}

#else

int run_vfs_ipc_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
