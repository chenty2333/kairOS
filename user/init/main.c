/*
 * user/init/main.c - User-space init for Kairos
 */

#include <fcntl.h>
#include <unistd.h>

static void setup_stdio(void) {
    int fd = open("/dev/console", O_RDWR);
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
        "PATH=/bin:/sbin",
        "TERM=vt100",
        "HOME=/",
        NULL,
    };
    char *const argv_sh[] = {"sh", NULL};
    char *const argv_busybox[] = {"busybox", "sh", NULL};

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
