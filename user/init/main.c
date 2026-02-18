/*
 * user/init/main.c - User-space init for Kairos
 */

#include <fcntl.h>
#include <unistd.h>

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

    const char msg[] = "init: starting shell\n";
    write(1, msg, sizeof(msg) - 1);

    execve("/bin/sh", argv_sh, envp);
    execve("/bin/busybox", argv_busybox, envp);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    setup_stdio();
    exec_shell();

    const char msg[] = "init: exec /bin/sh failed\n";
    write(2, msg, sizeof(msg) - 1);
    _exit(127);
}
