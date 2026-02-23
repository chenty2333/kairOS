/**
 * kernel/core/tests/tty_tests.c - TTY core/n_tty/pty semantic tests
 */

#include <kairos/ioctl.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/string.h>
#include <kairos/vfs.h>

#if CONFIG_KERNEL_TESTS

static int tests_failed;

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("tty_tests: %s failed\n", name);
        tests_failed++;
    }
}

static void close_file_if_open(struct file **f) {
    if (f && *f) {
        vfs_close(*f);
        *f = NULL;
    }
}

static void set_nonblock(struct file *f, bool enabled) {
    if (!f)
        return;
    mutex_lock(&f->lock);
    if (enabled)
        f->flags |= O_NONBLOCK;
    else
        f->flags &= ~O_NONBLOCK;
    mutex_unlock(&f->lock);
}

static ssize_t read_collect(struct file *f, uint8_t *buf, size_t want, int spins) {
    size_t got = 0;
    while (got < want && spins-- > 0) {
        ssize_t rd = vfs_read(f, buf + got, want - got);
        if (rd > 0) {
            got += (size_t)rd;
            continue;
        }
        if (rd == 0)
            return (ssize_t)got;
        if (rd == -EAGAIN) {
            proc_yield();
            continue;
        }
        return (got > 0) ? (ssize_t)got : rd;
    }
    return (ssize_t)got;
}

static void drain_nonblock(struct file *f) {
    if (!f)
        return;
    uint8_t buf[64];
    for (int i = 0; i < 32; i++) {
        ssize_t rd = vfs_read(f, buf, sizeof(buf));
        if (rd <= 0)
            break;
    }
}

static bool sig_pending_has(struct process *p, int sig) {
    if (!p || sig <= 0 || sig > 63)
        return false;
    uint64_t mask = 1ULL << (sig - 1);
    return (__atomic_load_n(&p->sig_pending, __ATOMIC_ACQUIRE) & mask) != 0;
}

static void sig_pending_clear(struct process *p, int sig) {
    if (!p || sig <= 0 || sig > 63)
        return;
    uint64_t mask = 1ULL << (sig - 1);
    __atomic_fetch_and(&p->sig_pending, ~mask, __ATOMIC_RELEASE);
}

static int open_pty_pair(struct file **master, struct file **slave) {
    if (!master || !slave)
        return -EINVAL;

    *master = NULL;
    *slave = NULL;

    int ret = -ENOENT;
    static const char *ptmx_paths[] = {
        "/dev/ptmx",
        "/ptmx",
    };
    for (size_t pi = 0; pi < sizeof(ptmx_paths) / sizeof(ptmx_paths[0]); pi++) {
        ret = vfs_open(ptmx_paths[pi], O_RDWR, 0, master);
        if (ret == 0 && *master)
            break;
    }
    if (!*master)
        return (ret < 0) ? ret : -ENOENT;

    for (int i = 0; i < 64; i++) {
        static const char *pts_prefixes[] = {
            "/dev/pts/",
            "/pts/",
            "/dev/",
            "/",
        };
        for (size_t pj = 0; pj < sizeof(pts_prefixes) / sizeof(pts_prefixes[0]);
             pj++) {
            char path[32];
            snprintf(path, sizeof(path), "%s%d", pts_prefixes[pj], i);

            ret = vfs_open(path, O_RDWR, 0, slave);
            if (ret < 0 || !*slave)
                continue;
            return 0;
        }
    }

    close_file_if_open(master);
    return -ENXIO;
}

static int open_dev_tty(struct file **fp) {
    if (!fp)
        return -EINVAL;
    *fp = NULL;

    static const char *paths[] = {
        "/dev/tty",
        "/tty",
    };
    int ret = -ENOENT;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        ret = vfs_open(paths[i], O_RDWR, 0, fp);
        if (ret == 0 && *fp)
            return 0;
    }
    return ret;
}

struct tty_blocking_read_ctx {
    struct file *f;
    volatile int started;
    ssize_t ret;
    uint8_t buf[16];
    size_t len;
};

static int tty_blocking_reader(void *arg) {
    struct tty_blocking_read_ctx *ctx = (struct tty_blocking_read_ctx *)arg;
    ctx->started = 1;
    ctx->ret = vfs_read(ctx->f, ctx->buf, ctx->len);
    return 0;
}

static void test_pty_open_read_write_ioctl(void) {
    struct file *master = NULL;
    struct file *slave = NULL;
    uint8_t buf[64];
    int ret = open_pty_pair(&master, &slave);
    test_check(ret == 0, "pty_pair open");
    if (ret < 0)
        return;

    set_nonblock(master, true);
    set_nonblock(slave, true);
    drain_nonblock(master);
    drain_nonblock(slave);

    int pe = vfs_poll(master, POLLIN | POLLOUT);
    test_check((pe & POLLOUT) != 0, "pty master poll writable");
    pe = vfs_poll(slave, POLLIN | POLLOUT);
    test_check((pe & POLLOUT) != 0, "pty slave poll writable");

    static const uint8_t slave_msg[] = "OUT";
    ssize_t wr = vfs_write(slave, slave_msg, sizeof(slave_msg) - 1);
    test_check(wr == (ssize_t)(sizeof(slave_msg) - 1), "pty slave write");
    memset(buf, 0, sizeof(buf));
    ssize_t rd = read_collect(master, buf, sizeof(slave_msg) - 1, 128);
    test_check(rd == (ssize_t)(sizeof(slave_msg) - 1), "pty master read");
    if (rd == (ssize_t)(sizeof(slave_msg) - 1)) {
        test_check(memcmp(buf, slave_msg, sizeof(slave_msg) - 1) == 0,
                   "pty master read data");
    }

    wr = vfs_write(master, "in", 2);
    test_check(wr == 2, "pty master write partial line");
    rd = vfs_read(slave, buf, sizeof(buf));
    test_check(rd == -EAGAIN, "pty slave read eagain before newline");

    wr = vfs_write(master, "\n", 1);
    test_check(wr == 1, "pty master write newline");
    memset(buf, 0, sizeof(buf));
    rd = read_collect(slave, buf, 3, 128);
    test_check(rd == 3, "pty slave read committed line");
    if (rd == 3) {
        test_check(memcmp(buf, "in\n", 3) == 0, "pty slave line data");
    }

    ret = vfs_ioctl(slave, TCSBRK, 0);
    test_check(ret == 0, "pty ioctl tcsbrk");
    ret = vfs_ioctl(slave, TCSBRKP, 0);
    test_check(ret == 0, "pty ioctl tcsbrkp");
    ret = vfs_ioctl(slave, TCGETS, 0);
    test_check(ret == -EFAULT, "pty ioctl tcgets efault");
    ret = vfs_ioctl(slave, TIOCGPGRP, 0);
    test_check(ret == -EFAULT, "pty ioctl tiocgpgrp efault");
    ret = vfs_ioctl(slave, TIOCSPGRP, 0);
    test_check(ret == -EFAULT, "pty ioctl tiocspgrp efault");
    ret = vfs_ioctl(slave, TIOCGSID, 0);
    test_check(ret == -EFAULT, "pty ioctl tiocgsid efault");
    ret = vfs_ioctl(slave, TIOCGWINSZ, 0);
    test_check(ret == -EFAULT, "pty ioctl tiocgwinsz efault");
    ret = vfs_ioctl(slave, TIOCSWINSZ, 0);
    test_check(ret == -EFAULT, "pty ioctl tiocswinsz efault");
    ret = vfs_ioctl(slave, 0x5a5aU, 0);
    test_check(ret == -ENOTTY, "pty ioctl unknown enotty");

    wr = vfs_write(master, "zz\n", 3);
    test_check(wr == 3, "pty master write for flush");
    ret = vfs_ioctl(slave, TCFLSH, 0);
    test_check(ret == 0, "pty ioctl tcflsh");
    rd = vfs_read(slave, buf, sizeof(buf));
    test_check(rd == -EAGAIN, "pty tcflsh cleared input");

    drain_nonblock(master);
    close_file_if_open(&slave);

    rd = vfs_read(master, buf, sizeof(buf));
    test_check(rd == 0, "pty master eof after slave close");

    close_file_if_open(&master);
}

static void test_n_tty_canonical_echo(void) {
    struct file *master = NULL;
    struct file *slave = NULL;
    int ret = open_pty_pair(&master, &slave);
    test_check(ret == 0, "n_tty open pty pair");
    if (ret < 0)
        return;

    set_nonblock(master, true);
    set_nonblock(slave, true);
    drain_nonblock(master);
    drain_nonblock(slave);

    uint8_t buf[64];

    ssize_t wr = vfs_write(master, "abc", 3);
    test_check(wr == 3, "n_tty write abc");

    memset(buf, 0, sizeof(buf));
    ssize_t rd = read_collect(master, buf, 3, 128);
    test_check(rd == 3, "n_tty echo abc");
    if (rd == 3)
        test_check(memcmp(buf, "abc", 3) == 0, "n_tty echo abc data");

    rd = vfs_read(slave, buf, sizeof(buf));
    test_check(rd == -EAGAIN, "n_tty canon no newline eagain");

    wr = vfs_write(master, "\n", 1);
    test_check(wr == 1, "n_tty write newline");

    memset(buf, 0, sizeof(buf));
    rd = read_collect(master, buf, 2, 128);
    test_check(rd == 2, "n_tty echo newline crlf");
    if (rd == 2)
        test_check(memcmp(buf, "\r\n", 2) == 0, "n_tty echo newline data");

    memset(buf, 0, sizeof(buf));
    rd = read_collect(slave, buf, 4, 128);
    test_check(rd == 4, "n_tty canonical line read");
    if (rd == 4)
        test_check(memcmp(buf, "abc\n", 4) == 0, "n_tty canonical line data");

    uint8_t eof = 4;
    wr = vfs_write(master, &eof, 1);
    test_check(wr == 1, "n_tty write veof");
    rd = vfs_read(slave, buf, sizeof(buf));
    test_check(rd == 0, "n_tty veof returns eof");

    static const uint8_t edit_seq[] = { 'x', 'y', 0x7f, 'z', '\n' };
    wr = vfs_write(master, edit_seq, sizeof(edit_seq));
    test_check(wr == (ssize_t)sizeof(edit_seq), "n_tty write edit sequence");

    memset(buf, 0, sizeof(buf));
    rd = read_collect(master, buf, 8, 128);
    test_check(rd == 8, "n_tty echo erase sequence");
    if (rd == 8)
        test_check(memcmp(buf, "xy\b \bz\r\n", 8) == 0,
                   "n_tty erase echo data");

    memset(buf, 0, sizeof(buf));
    rd = read_collect(slave, buf, 3, 128);
    test_check(rd == 3, "n_tty erase line read");
    if (rd == 3)
        test_check(memcmp(buf, "xz\n", 3) == 0, "n_tty erase line data");

    close_file_if_open(&slave);
    close_file_if_open(&master);
}

static void test_n_tty_isig_behavior(void) {
    struct file *master = NULL;
    struct file *slave = NULL;
    int ret = open_pty_pair(&master, &slave);
    test_check(ret == 0, "n_tty isig open pty pair");
    if (ret < 0)
        return;

    set_nonblock(master, true);
    set_nonblock(slave, true);
    drain_nonblock(master);
    drain_nonblock(slave);

    struct process *cur = proc_current();
    test_check(cur != NULL, "n_tty isig current proc");
    if (!cur) {
        close_file_if_open(&slave);
        close_file_if_open(&master);
        return;
    }

    sig_pending_clear(cur, SIGINT);

    uint8_t intr = 3;
    ssize_t wr = vfs_write(master, &intr, 1);
    test_check(wr == 1, "n_tty isig write intr");

    uint8_t echo[8];
    memset(echo, 0, sizeof(echo));
    ssize_t rd = read_collect(master, echo, 4, 128);
    test_check(rd == 4, "n_tty isig echo len");
    if (rd == 4)
        test_check(memcmp(echo, "^C\r\n", 4) == 0, "n_tty isig echo data");

    rd = vfs_read(slave, echo, sizeof(echo));
    test_check(rd == -EAGAIN, "n_tty isig no canonical data queued");
    test_check(sig_pending_has(cur, SIGINT), "n_tty isig pending set");
    sig_pending_clear(cur, SIGINT);

    close_file_if_open(&slave);
    close_file_if_open(&master);
}

static void test_n_tty_blocking_read_paths(void) {
    struct file *master = NULL;
    struct file *slave = NULL;
    int ret = open_pty_pair(&master, &slave);
    test_check(ret == 0, "n_tty blocking open pty pair");
    if (ret < 0)
        return;

    set_nonblock(master, true);
    set_nonblock(slave, true);
    drain_nonblock(master);
    drain_nonblock(slave);
    set_nonblock(master, false);
    set_nonblock(slave, false);

    do {
        struct tty_blocking_read_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.f = slave;
        ctx.ret = -1;
        ctx.len = 8;

        struct process *child =
            kthread_create_joinable(tty_blocking_reader, &ctx, "ttyblk");
        test_check(child != NULL, "n_tty blocking wake child create");
        if (!child)
            break;
        pid_t cpid = child->pid;
        sched_enqueue(child);

        for (int i = 0; i < 2000 && !ctx.started; i++)
            proc_yield();
        test_check(ctx.started != 0, "n_tty blocking wake child started");

        int status = 0;
        pid_t wp = proc_wait(cpid, &status, WNOHANG);
        test_check(wp == 0, "n_tty blocking wake child blocked");

        ssize_t wr = vfs_write(master, "wake\n", 5);
        test_check(wr == 5, "n_tty blocking wake write");

        wp = proc_wait(cpid, &status, 0);
        test_check(wp == cpid, "n_tty blocking wake child reaped");
        if (wp == cpid) {
            test_check(status == 0, "n_tty blocking wake child exit");
            test_check(ctx.ret == 5, "n_tty blocking wake read len");
            if (ctx.ret == 5)
                test_check(memcmp(ctx.buf, "wake\n", 5) == 0,
                           "n_tty blocking wake read data");
        }
    } while (0);

    do {
        struct tty_blocking_read_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.f = slave;
        ctx.ret = -1;
        ctx.len = 8;

        struct process *child =
            kthread_create_joinable(tty_blocking_reader, &ctx, "ttyeintr");
        test_check(child != NULL, "n_tty blocking eintr child create");
        if (!child)
            break;
        pid_t cpid = child->pid;
        sched_enqueue(child);

        for (int i = 0; i < 2000 && !ctx.started; i++)
            proc_yield();
        test_check(ctx.started != 0, "n_tty blocking eintr child started");

        int status = 0;
        pid_t wp = proc_wait(cpid, &status, WNOHANG);
        test_check(wp == 0, "n_tty blocking eintr child blocked");

        int sret = signal_send(cpid, SIGUSR1);
        test_check(sret == 0, "n_tty blocking eintr send signal");

        wp = proc_wait(cpid, &status, 0);
        test_check(wp == cpid, "n_tty blocking eintr child reaped");
        if (wp == cpid) {
            test_check(status == 0, "n_tty blocking eintr child exit");
            test_check(ctx.ret == -EINTR, "n_tty blocking eintr read ret");
        }
    } while (0);

    close_file_if_open(&slave);
    close_file_if_open(&master);
}

static void test_ctty_dev_tty_lifecycle(void) {
    struct file *master = NULL;
    struct file *slave = NULL;
    struct file *devtty = NULL;
    uint8_t buf[16];

    int ret = open_pty_pair(&master, &slave);
    test_check(ret == 0, "ctty open pty pair");
    if (ret < 0)
        return;

    set_nonblock(master, true);
    set_nonblock(slave, true);
    drain_nonblock(master);
    drain_nonblock(slave);

    ret = vfs_ioctl(slave, TIOCNOTTY, 0);
    test_check(ret == -ENOTTY, "ctty tiocnotty before attach");

    ret = vfs_ioctl(slave, TIOCSCTTY, 0);
    test_check(ret == 0, "ctty tiocsctty attach");

    ret = vfs_ioctl(slave, TIOCSCTTY, 0);
    test_check(ret == 0, "ctty tiocsctty idempotent");

    ret = open_dev_tty(&devtty);
    test_check(ret == 0, "ctty open /dev/tty attached");
    if (ret == 0 && devtty) {
        set_nonblock(devtty, true);
        ssize_t wr = vfs_write(devtty, "D\n", 2);
        test_check(wr == 2, "ctty /dev/tty write");
        memset(buf, 0, sizeof(buf));
        ssize_t rd = read_collect(master, buf, 3, 128);
        test_check(rd == 3, "ctty master sees /dev/tty write");
        if (rd == 3)
            test_check(memcmp(buf, "D\r\n", 3) == 0, "ctty /dev/tty write data");
    }

    ret = vfs_ioctl(devtty, TIOCNOTTY, 0);
    test_check(ret == 0, "ctty tiocnotty detach via /dev/tty");

    close_file_if_open(&devtty);
    ret = open_dev_tty(&devtty);
    test_check(ret == 0, "ctty open /dev/tty detached");
    if (ret == 0 && devtty) {
        ret = vfs_write(devtty, "x", 1);
        test_check(ret == -ENXIO, "ctty /dev/tty write after detach enxio");
    }
    close_file_if_open(&devtty);

    ret = vfs_ioctl(slave, TIOCNOTTY, 0);
    test_check(ret == -ENOTTY, "ctty tiocnotty on detached slave");

    close_file_if_open(&slave);
    close_file_if_open(&master);
}

static void test_pty_reopen_stability(void) {
    for (int i = 0; i < 96; i++) {
        struct file *master = NULL;
        struct file *slave = NULL;
        int ret = open_pty_pair(&master, &slave);
        test_check(ret == 0, "pty reopen pair");
        if (ret < 0) {
            close_file_if_open(&slave);
            close_file_if_open(&master);
            break;
        }

        set_nonblock(master, true);
        set_nonblock(slave, true);
        drain_nonblock(master);
        drain_nonblock(slave);

        ssize_t wr = vfs_write(master, "r\n", 2);
        test_check(wr == 2, "pty reopen write");
        uint8_t buf[4];
        memset(buf, 0, sizeof(buf));
        ssize_t rd = read_collect(slave, buf, 2, 128);
        test_check(rd == 2, "pty reopen read");

        close_file_if_open(&slave);
        close_file_if_open(&master);
    }
}

int run_tty_tests(void) {
    tests_failed = 0;
    pr_info("Running tty tests...\n");

    test_pty_open_read_write_ioctl();
    test_n_tty_canonical_echo();
    test_n_tty_isig_behavior();
    test_n_tty_blocking_read_paths();
    test_ctty_dev_tty_lifecycle();
    test_pty_reopen_stability();

    if (tests_failed == 0)
        pr_info("tty tests: all passed\n");
    else
        pr_err("tty tests: %d failures\n", tests_failed);

    return tests_failed;
}

#else

int run_tty_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
