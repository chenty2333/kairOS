/**
 * kernel/core/tests/tty_tests.c - TTY core/n_tty/pty semantic tests
 */

#include <kairos/ioctl.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
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

int run_tty_tests(void) {
    tests_failed = 0;
    pr_info("Running tty tests...\n");

    test_pty_open_read_write_ioctl();
    test_n_tty_canonical_echo();

    if (tests_failed == 0)
        pr_info("tty tests: all passed\n");
    else
        pr_err("tty tests: %d failures\n", tests_failed);

    return tests_failed;
}

#else

int run_tty_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
