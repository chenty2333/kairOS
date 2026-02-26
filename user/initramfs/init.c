/*
 * user/initramfs/init.c - Early init for initramfs
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static void log_msg(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n > (int)sizeof(buf))
            n = (int)sizeof(buf);
        write(1, buf, (size_t)n);
    }
}

static void setup_stdio(void) {
    int fd = open("/dev/console", O_RDWR);
    if (fd < 0)
        fd = open("/console", O_RDWR);
    if (fd < 0)
        return;
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    if (fd > 2)
        close(fd);
}

static int read_cmdline(char *buf, size_t bufsz) {
    int fd = open("/proc/cmdline", O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return 0;
}

static bool get_arg_value(const char *cmdline, const char *key,
                          char *out, size_t outsz) {
    size_t klen = strlen(key);
    const char *p = cmdline;
    while (*p) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        const char *end = p;
        while (*end && *end != ' ')
            end++;
        if ((size_t)(end - p) > klen + 1 && strncmp(p, key, klen) == 0 &&
            p[klen] == '=') {
            size_t vlen = (size_t)(end - (p + klen + 1));
            if (vlen >= outsz)
                vlen = outsz - 1;
            memcpy(out, p + klen + 1, vlen);
            out[vlen] = '\0';
            return true;
        }
        p = end;
    }
    return false;
}

static void normalize_root(char *root) {
    const char *prefix = "/dev/";
    size_t plen = strlen(prefix);
    if (strncmp(root, prefix, plen) == 0) {
        memmove(root, root + plen, strlen(root + plen) + 1);
    }
}

static int do_mount(const char *src, const char *tgt, const char *fstype,
                    unsigned long flags) {
    return (int)syscall(SYS_mount, src, tgt, fstype, flags, 0, 0);
}

static int do_pivot_root(const char *new_root, const char *put_old) {
    return (int)syscall(SYS_pivot_root, new_root, put_old, 0, 0, 0, 0);
}

static int do_umount(const char *target) {
    return (int)syscall(SYS_umount2, target, 0, 0, 0, 0, 0);
}

static bool candidate_exists(char candidates[][64], size_t count,
                             const char *name) {
    size_t i;
    for (i = 0; i < count; ++i) {
        if (strcmp(candidates[i], name) == 0)
            return true;
    }
    return false;
}

static void candidate_add(char candidates[][64], size_t *count,
                          size_t max_count, const char *name) {
    if (!name || !name[0] || *count >= max_count)
        return;
    if (candidate_exists(candidates, *count, name))
        return;
    snprintf(candidates[*count], sizeof(candidates[*count]), "%s", name);
    (*count)++;
}

static void exec_shell(void) {
    char *const envp[] = {
        "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
        "TERM=vt100",
        "HOME=/root",
        "PS1=kairos$ ",
        NULL,
    };
    char *const argv_sh[] = {"-sh", NULL};
    char *const argv_busybox[] = {"busybox", "sh", "-l", NULL};

    execve("/bin/sh", argv_sh, envp);
    execve("/bin/busybox", argv_busybox, envp);
}

static void exec_init(const char *path) {
    char *const envp[] = {
        "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
        "TERM=vt100",
        "HOME=/root",
        "PS1=kairos$ ",
        NULL,
    };
    char *argv[] = {(char *)path, NULL};
    execve(path, argv, envp);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    setup_stdio();

    char cmdline[512] = {0};
    if (read_cmdline(cmdline, sizeof(cmdline)) < 0)
        cmdline[0] = '\0';

    char root_dev[64] = {0};
    char root_fstype[32] = "ext2";
    char init_path[128] = {0};
    bool root_from_cmdline = false;

    if (cmdline[0]) {
        root_from_cmdline =
            get_arg_value(cmdline, "root", root_dev, sizeof(root_dev));
        get_arg_value(cmdline, "rootfstype", root_fstype,
                      sizeof(root_fstype));
        get_arg_value(cmdline, "init", init_path, sizeof(init_path));
        normalize_root(root_dev);
    }

    if (mkdir("/newroot", 0755) < 0 && errno != EEXIST) {
        int mkerr = errno;
        if (mkerr == EBADF) {
            (void)chdir("/");
            if (mkdir("/newroot", 0755) == 0 || errno == EEXIST) {
                mkerr = 0;
            } else {
                mkerr = errno;
            }
        }
        if (mkerr != 0) {
            char cwd[128];
            if (getcwd(cwd, sizeof(cwd))) {
                log_msg("initramfs: mkdir /newroot failed (%d), cwd=%s\n",
                        mkerr, cwd);
            } else {
                log_msg("initramfs: mkdir /newroot failed (%d)\n", mkerr);
            }
        }
    }

    char root_path[96] = {0};
    int last_err = 0;
    bool mounted = false;
    char candidates[8][64];
    size_t candidate_count = 0;
    const char *fallbacks[] = {"vda", "vdb", "vdc", "vdd"};
    size_t i;

    if (root_from_cmdline)
        candidate_add(candidates, &candidate_count,
                      sizeof(candidates) / sizeof(candidates[0]), root_dev);
    for (i = 0; i < sizeof(fallbacks) / sizeof(fallbacks[0]); ++i) {
        candidate_add(candidates, &candidate_count,
                      sizeof(candidates) / sizeof(candidates[0]), fallbacks[i]);
    }

    for (i = 0; i < candidate_count; ++i) {
        snprintf(root_path, sizeof(root_path), "%s", candidates[i]);
        if (do_mount(root_path, "/newroot", root_fstype, 0) == 0) {
            mounted = true;
            break;
        }
        last_err = errno;
        log_msg("initramfs: mount try root=%s type=%s failed (%d)\n", root_path,
                root_fstype, last_err);
    }

    if (!mounted) {
        log_msg("initramfs: mount root %s type %s failed (%d)\n",
                root_path, root_fstype, last_err);
        exec_shell();
        log_msg("initramfs: no shell available, halting\n");
        for (;;)
            pause();
    }

    if (mkdir("/newroot/oldroot", 0755) < 0 && errno != EEXIST) {
        log_msg("initramfs: mkdir /newroot/oldroot failed (%d)\n", errno);
    }

    if (do_pivot_root("/newroot", "/newroot/oldroot") < 0) {
        log_msg("initramfs: pivot_root failed (%d)\n", errno);
        exec_shell();
        for (;;)
            pause();
    }

    if (chdir("/") < 0) {
        log_msg("initramfs: chdir / failed (%d)\n", errno);
    }

    (void)mkdir("/dev", 0755);
    (void)mkdir("/proc", 0555);
    do_mount(NULL, "/dev", "devfs", 0);
    do_mount(NULL, "/proc", "procfs", 0);
    do_umount("/oldroot");

    if (init_path[0])
        exec_init(init_path);
    exec_init("/sbin/init");
    exec_init("/init");
    exec_init("/bin/init");

    exec_shell();

    log_msg("initramfs: exec init failed\n");
    _exit(127);
}
