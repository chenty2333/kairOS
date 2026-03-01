#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_failed = 0;

static void mark_failed(const char *reason) {
    g_failed = 1;
    if (reason && reason[0])
        printf("SMOKE_FAIL:%s\n", reason);
}

static int write_file_raw(const char *path, const char *data) {
    size_t len = strlen(data);
    long fd = syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("SMOKE_FAIL:openat_%s_errno_%d\n", path, errno);
        return -1;
    }

    size_t off = 0;
    while (off < len) {
        long wr = syscall(SYS_write, (int)fd, data + off, len - off);
        if (wr < 0) {
            printf("SMOKE_FAIL:write_%s_errno_%d\n", path, errno);
            syscall(SYS_close, (int)fd);
            return -1;
        }
        off += (size_t)wr;
    }
    syscall(SYS_close, (int)fd);
    return 0;
}

static int wait_child_status(pid_t pid, const char *tag, int timeout_sec) {
    int status = 0;
    int loops = 0;
    for (;;) {
        long ret = syscall(SYS_wait4, pid, &status, WNOHANG, 0);
        if (ret == pid)
            break;
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return 127;
        }
        if (loops >= timeout_sec * 10) {
            if (tag && tag[0])
                printf("SMOKE_FAIL:%s_timeout\n", tag);
            kill(pid, SIGKILL);
            for (;;) {
                ret = waitpid(pid, &status, 0);
                if (ret == pid)
                    break;
                if (ret < 0 && errno == EINTR)
                    continue;
                break;
            }
            return 124;
        }
        usleep(100000);
        loops++;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 127;
}

static int run_cmd(char *const argv[], const char *tag) {
    if (tag && tag[0])
        printf("STEP:%s:start\n", tag);
    pid_t pid = fork();
    if (pid < 0)
        return 127;
    if (pid == 0) {
        char *const empty_env[] = {NULL};
        execve(argv[0], argv, empty_env);
        _exit(127);
    }
    int rc = wait_child_status(pid, tag, 40);
    if (tag && tag[0])
        printf("STEP:%s:rc=%d\n", tag, rc);
    return rc;
}

static int run_cmd_capture(char *const argv[], char *buf, size_t cap,
                           const char *tag) {
    if (buf && cap > 0)
        buf[0] = '\0';
    if (tag && tag[0])
        printf("STEP:%s:start\n", tag);

    int pipefd[2] = {-1, -1};
    if (syscall(SYS_pipe2, pipefd, 0) < 0) {
        if (tag && tag[0])
            printf("STEP:%s:pipe_errno=%d\n", tag, errno);
        return 127;
    }
    pid_t pid = fork();
    if (pid < 0) {
        if (tag && tag[0])
            printf("STEP:%s:fork_errno=%d\n", tag, errno);
        close(pipefd[0]);
        close(pipefd[1]);
        return 127;
    }
    if (pid == 0) {
        if (syscall(SYS_dup3, pipefd[1], STDOUT_FILENO, 0) < 0)
            _exit(126);
        if (syscall(SYS_dup3, pipefd[1], STDERR_FILENO, 0) < 0)
            _exit(126);
        close(pipefd[0]);
        close(pipefd[1]);
        char *const empty_env[] = {NULL};
        execve(argv[0], argv, empty_env);
        _exit(127);
    }

    close(pipefd[1]);
    size_t off = 0;
    while (off + 1 < cap) {
        ssize_t n = read(pipefd[0], buf + off, cap - off - 1);
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        off += (size_t)n;
    }
    buf[off] = '\0';
    close(pipefd[0]);
    int rc = wait_child_status(pid, tag, 40);
    if (tag && tag[0])
        printf("STEP:%s:rc=%d\n", tag, rc);
    return rc;
}

static void probe_path(const char *path) {
    errno = 0;
    int ar = access(path, F_OK);
    int aerr = errno;

    errno = 0;
    struct stat st;
    int sr = stat(path, &st);
    int serr = errno;

    errno = 0;
    int fd = open(path, O_RDONLY);
    int ferr = errno;
    if (fd >= 0)
        close(fd);

    printf("PROBE:%s access=%d errno=%d stat=%d errno=%d open=%d errno=%d\n",
           path, ar, aerr, sr, serr, fd, ferr);
}

static void probe_mounts(void) {
    char buf[512];
    long fd = syscall(SYS_openat, AT_FDCWD, "/proc/mounts", O_RDONLY, 0);
    if (fd < 0) {
        printf("PROBE:mounts_open_errno=%d\n", errno);
        return;
    }

    long nr = syscall(SYS_read, (int)fd, buf, sizeof(buf) - 1);
    int rerr = errno;
    syscall(SYS_close, (int)fd);
    if (nr < 0) {
        printf("PROBE:mounts_read_errno=%d\n", rerr);
        return;
    }

    buf[(size_t)nr] = '\0';
    for (long i = 0; i < nr; ++i) {
        if (buf[i] == '\r' || buf[i] == '\n')
            buf[i] = ' ';
    }
    printf("PROBE:mounts_head=%s\n", buf);
}

int main(void) {
    printf("init: starting shell\n");
    char cwd[256];
    if (getcwd(cwd, sizeof(cwd)))
        printf("PROBE:cwd=%s\n", cwd);
    else
        printf("PROBE:cwd_err=%d\n", errno);
    probe_mounts();

    if (write_file_raw(
            "/tmp/tcc_smoke_exec.c",
            "static long ksys(long n,long a0,long a1,long a2){long r;"
            "asm volatile(\"int $0x80\":\"=a\"(r):\"a\"(n),\"D\"(a0),\"S\"(a1),\"d\"(a2):\"rcx\",\"r11\",\"memory\");"
            "return r;}\n"
            "void _start(void){ksys(60,0,0,0);for(;;){}}\n") < 0)
        mark_failed("write_static_src_failed");
    probe_path("/tmp/tcc_smoke_exec.c");
    probe_path("/usr/bin/tcc");
    probe_path("/usr/lib/crt1.o");
    probe_path("/usr/lib/crti.o");
    probe_path("/usr/lib/crtn.o");
    probe_path("/usr/lib/libc.a");
    probe_path("/lib/ld-musl-x86_64.so.1");
    probe_path("/lib/libc.so");

    char *const tcc_static[] = {
        "/usr/bin/tcc",
        "-nostdlib",
        "-static",
        "/tmp/tcc_smoke_exec.c",
        "-o",
        "/tmp/tcc_smoke_static",
        NULL,
    };
    if (run_cmd(tcc_static, "compile_static") != 0)
        mark_failed("static_compile_failed");

    char *const run_static[] = {"/tmp/tcc_smoke_static", NULL};
    int rc_static = run_cmd(run_static, "run_static");
    printf("RC_STATIC:%d\n", rc_static);
    if (rc_static != 0)
        mark_failed("static_exec_failed");

    char *const tcc_dyn[] = {
        "/usr/bin/tcc",
        "-nostdlib",
        "/tmp/tcc_smoke_exec.c",
        "-o",
        "/tmp/tcc_smoke_dyn",
        NULL,
    };
    if (run_cmd(tcc_dyn, "compile_dyn") != 0)
        mark_failed("dyn_compile_failed");

    char *const run_dyn[] = {"/tmp/tcc_smoke_dyn", NULL};
    int rc_dyn = run_cmd(run_dyn, "run_dyn");
    printf("RC_DYN:%d\n", rc_dyn);
    if (rc_dyn != 0)
        mark_failed("dyn_exec_failed");

    if (write_file_raw("/tmp/hello.c",
                       "static long ksys(long n,long a0,long a1,long a2){long r;"
                       "asm volatile(\"int $0x80\":\"=a\"(r):\"a\"(n),\"D\"(a0),\"S\"(a1),\"d\"(a2):\"rcx\",\"r11\",\"memory\");"
                       "return r;}\n"
                       "void _start(void){const char m[]=\"hello world\\n\";"
                       "ksys(1,1,(long)m,sizeof(m)-1);ksys(60,0,0,0);for(;;){}}\n") < 0) {
        mark_failed("write_hello_src_failed");
    }

    char *const tcc_hello[] = {
        "/usr/bin/tcc",
        "-nostdlib",
        "/tmp/hello.c",
        "-o",
        "/tmp/hello_dyn",
        NULL,
    };
    if (run_cmd(tcc_hello, "compile_hello_dyn") != 0)
        mark_failed("dyn_hello_compile_failed");

    char hello_out[512];
    char *const run_hello[] = {"/tmp/hello_dyn", NULL};
    int rc_hello =
        run_cmd_capture(run_hello, hello_out, sizeof(hello_out), "run_hello_dyn");
    printf("RC_DYN_HELLO:%d\n", rc_hello);
    printf("HELLO_OUT:%s\n", hello_out);
    if (rc_hello != 0)
        mark_failed("dyn_hello_exec_failed");
    if (strstr(hello_out, "hello world"))
        printf("HELLO_DYN_OK\n");
    else
        mark_failed("dyn_hello_output_mismatch");

    printf("TEST_SUMMARY: failed=%d\n", g_failed);
    printf("TEST_RESULT_JSON: {\"schema_version\":1,\"failed\":%d,\"done\":true,\"enabled_mask\":1}\n",
           g_failed);
    printf("__TCC_SMOKE_DONE__\n");

    for (;;)
        pause();
}
