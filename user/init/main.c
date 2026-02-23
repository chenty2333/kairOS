/*
 * user/init/main.c - User-space init for Kairos
 */

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHELL_RESTART_DELAY_MIN 1U
#define SHELL_RESTART_DELAY_MAX 16U

static void setup_stdio(void) {
    int fd = open("/dev/console", O_RDWR);
    if (fd < 0) {
        fd = open("/console", O_RDWR);
    }
    if (fd < 0) {
        return;
    }
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    if (fd > 2) {
        close(fd);
    }
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

static int wait_shell(pid_t pid, int *status) {
    for (;;) {
        pid_t ret = waitpid(pid, status, 0);
        if (ret == pid) {
            return 0;
        }
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
}

static unsigned int next_restart_delay(unsigned int delay) {
    if (delay >= SHELL_RESTART_DELAY_MAX) {
        return SHELL_RESTART_DELAY_MAX;
    }
    delay <<= 1;
    if (delay > SHELL_RESTART_DELAY_MAX) {
        delay = SHELL_RESTART_DELAY_MAX;
    }
    return delay;
}

static unsigned int report_shell_exit(int status, unsigned int delay) {
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        dprintf(2, "init: shell exited (code=%d)\n", code);
        if (code == 0) {
            return SHELL_RESTART_DELAY_MIN;
        }
        return next_restart_delay(delay);
    }
    if (WIFSIGNALED(status)) {
        dprintf(2, "init: shell killed by signal %d\n", WTERMSIG(status));
        return next_restart_delay(delay);
    }
    if (WIFSTOPPED(status)) {
        dprintf(2, "init: shell stopped by signal %d\n", WSTOPSIG(status));
        return next_restart_delay(delay);
    }
    dprintf(2, "init: shell exited (status=0x%x)\n", status);
    return next_restart_delay(delay);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    unsigned int restart_delay = SHELL_RESTART_DELAY_MIN;
    setup_stdio();
    for (;;) {
        const char start_msg[] = "init: starting shell\n";
        write(1, start_msg, sizeof(start_msg) - 1);

        pid_t pid = fork();
        if (pid < 0) {
            dprintf(2, "init: fork failed (errno=%d), retrying in %u seconds\n",
                    errno, restart_delay);
            sleep(restart_delay);
            restart_delay = next_restart_delay(restart_delay);
            continue;
        }

        if (pid == 0) {
            exec_shell();
            const char msg[] = "init: exec /bin/sh failed\n";
            write(2, msg, sizeof(msg) - 1);
            _exit(127);
        }

        int status = 0;
        if (wait_shell(pid, &status) < 0) {
            dprintf(2, "init: waitpid failed (errno=%d), retrying in %u seconds\n",
                    errno, restart_delay);
            sleep(restart_delay);
            restart_delay = next_restart_delay(restart_delay);
            continue;
        } else {
            restart_delay = report_shell_exit(status, restart_delay);
        }
        dprintf(2, "init: restarting shell in %u seconds\n", restart_delay);
        sleep(restart_delay);
    }
}
