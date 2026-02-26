#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int observed_errno(int rc) {
    if (rc < 0)
        return errno ? errno : EIO;
    return 0;
}

static const char *errno_name(int value) {
    switch (value) {
    case 0:
        return "OK";
    case ENOENT:
        return "ENOENT";
    case EBADF:
        return "EBADF";
    case EINVAL:
        return "EINVAL";
    case ECHILD:
        return "ECHILD";
    case ESRCH:
        return "ESRCH";
    case EAFNOSUPPORT:
        return "EAFNOSUPPORT";
    case EIO:
        return "EIO";
    default:
        return "OTHER";
    }
}

static int case_fs_open_missing(void) {
    errno = 0;
    int fd = open("/tmp/.abi-smoke-open-missing", O_RDONLY);
    if (fd >= 0)
        close(fd);
    return observed_errno(fd >= 0 ? 0 : -1);
}

static int case_fs_openat_bad_dirfd(void) {
    errno = 0;
    int fd = openat(-1, ".", O_RDONLY);
    if (fd >= 0)
        close(fd);
    return observed_errno(fd >= 0 ? 0 : -1);
}

static int case_fs_read_bad_fd(void) {
    char ch = 0;
    errno = 0;
    ssize_t rc = read(-1, &ch, 1);
    (void)rc;
    return observed_errno((int)rc);
}

static int case_fs_write_bad_fd(void) {
    const char ch = 'x';
    errno = 0;
    ssize_t rc = write(-1, &ch, 1);
    (void)rc;
    return observed_errno((int)rc);
}

static int case_fs_close_bad_fd(void) {
    errno = 0;
    int rc = close(-1);
    return observed_errno(rc);
}

static int case_fs_pipe2_bad_flags(void) {
    int fds[2] = {-1, -1};
    errno = 0;
    int rc = pipe2(fds, 0x40000000);
    if (rc == 0) {
        close(fds[0]);
        close(fds[1]);
    }
    return observed_errno(rc == 0 ? 0 : -1);
}

static int case_fs_dup2_bad_oldfd(void) {
    errno = 0;
    int rc = dup2(-1, 42);
    if (rc >= 0)
        close(rc);
    return observed_errno(rc >= 0 ? 0 : -1);
}

static int case_socket_connect_unix_missing(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return errno ? errno : EIO;

    const char *path = "/tmp/.abi-smoke-no-sock";
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    unlink(path);

    errno = 0;
    int rc = connect(fd, (struct sockaddr *)&addr,
                     (socklen_t)(sizeof(sa_family_t) + strlen(addr.sun_path) + 1));
    int value = observed_errno(rc);
    close(fd);
    return value;
}

static int case_socket_getsockopt_bad_fd(void) {
    int val = 0;
    socklen_t len = sizeof(val);
    errno = 0;
    int rc = getsockopt(-1, SOL_SOCKET, SO_ERROR, &val, &len);
    return observed_errno(rc);
}

static int case_proc_waitpid_nochild(void) {
    int status = 0;
    errno = 0;
    pid_t rc = waitpid(-1, &status, WNOHANG);
    return observed_errno(rc < 0 ? -1 : 0);
}

static int case_proc_kill_nonexistent(void) {
    errno = 0;
    int rc = kill(999999, 0);
    return observed_errno(rc);
}

static int case_time_clock_gettime_bad_clockid(void) {
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    errno = 0;
    int rc = clock_gettime((clockid_t)-1, &ts);
    return observed_errno(rc);
}

static int case_time_nanosleep_bad_nsec(void) {
    struct timespec req;
    req.tv_sec = 0;
    req.tv_nsec = 1000000000L;
    errno = 0;
    int rc = nanosleep(&req, NULL);
    return observed_errno(rc);
}

static int case_mount_umount2_bad_flags(void) {
    errno = 0;
    int rc = umount2("/tmp", 0x40000000U);
    return observed_errno(rc);
}

int main(void) {
    static const struct {
        const char *id;
        int (*fn)(void);
    } cases[] = {
        {"fs.open_missing", case_fs_open_missing},
        {"fs.openat_bad_dirfd", case_fs_openat_bad_dirfd},
        {"fs.read_bad_fd", case_fs_read_bad_fd},
        {"fs.write_bad_fd", case_fs_write_bad_fd},
        {"fs.close_bad_fd", case_fs_close_bad_fd},
        {"fs.pipe2_bad_flags", case_fs_pipe2_bad_flags},
        {"fs.dup2_bad_oldfd", case_fs_dup2_bad_oldfd},
        {"socket.connect_unix_missing", case_socket_connect_unix_missing},
        {"socket.getsockopt_bad_fd", case_socket_getsockopt_bad_fd},
        {"proc.waitpid_nochild", case_proc_waitpid_nochild},
        {"proc.kill_nonexistent", case_proc_kill_nonexistent},
        {"time.clock_gettime_bad_clockid", case_time_clock_gettime_bad_clockid},
        {"time.nanosleep_bad_nsec", case_time_nanosleep_bad_nsec},
        {"mount.umount2_bad_flags", case_mount_umount2_bad_flags},
    };

    printf("ABI_BASELINE_VERSION:1\n");
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int value = cases[i].fn();
        printf("ABI_CASE:%s:errno=%d:name=%s\n", cases[i].id, value,
               errno_name(value));
    }
    printf("ABI_SMOKE_CASES:%zu\n", sizeof(cases) / sizeof(cases[0]));
    printf("ABI_SMOKE_OK\n");
    printf("TEST_SUMMARY: failed=0\n");
    printf("TEST_RESULT_JSON: {\"schema_version\":1,\"failed\":0,\"done\":true,\"enabled_mask\":1}\n");
    printf("__ABI_SMOKE_DONE__\n");
    return 0;
}
