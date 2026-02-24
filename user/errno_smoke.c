#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int write_file_exact(const char *path, const char *data, mode_t mode) {
    size_t len = strlen(data);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
        return errno ? errno : EIO;
    ssize_t wr = write(fd, data, len);
    int saved = errno;
    close(fd);
    if (wr < 0 || (size_t)wr != len)
        return saved ? saved : EIO;
    return 0;
}

static int check_enoent(void) {
    errno = 0;
    int fd = open("/tmp/.errno-smoke.missing", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 1001;
    }
    return (errno == ENOENT) ? 0 : (errno ? errno : 1002);
}

static int check_eacces(void) {
    const char *path = "/tmp";
    char *const argv[] = {(char *)path, NULL};
    char *const envp[] = {NULL};
    errno = 0;
    execve(path, argv, envp);
    return (errno == EACCES) ? 0 : (errno ? errno : 1101);
}

static int check_enoexec(void) {
    const char *path = "/tmp/errno_enoexec.bin";
    int wret = write_file_exact(path, "not-an-elf\n", 0755);
    if (wret != 0)
        return wret;
    char *const argv[] = {(char *)path, NULL};
    char *const envp[] = {NULL};
    errno = 0;
    execve(path, argv, envp);
    return (errno == ENOEXEC) ? 0 : (errno ? errno : 1201);
}

static int check_enomem(void) {
    size_t huge_len = (size_t)0x3ff0000000ULL;
    errno = 0;
    void *p = mmap(NULL, huge_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        (void)munmap(p, huge_len);
        return 1301;
    }
    return (errno == ENOMEM) ? 0 : (errno ? errno : 1302);
}

static int check_enametoolong(void) {
    char path[5000];
    path[0] = '/';
    memset(path + 1, 'a', sizeof(path) - 2);
    path[sizeof(path) - 1] = '\0';
    errno = 0;
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 1401;
    }
    return (errno == ENAMETOOLONG) ? 0 : (errno ? errno : 1402);
}

static int report_case(const char *name, int rc) {
    if (rc == 0) {
        printf("ERRNO_CASE:%s:OK\n", name);
        return 0;
    }
    printf("ERRNO_CASE:%s:FAIL:%d\n", name, rc);
    printf("SMOKE_FAIL:%s\n", name);
    return 1;
}

int main(void) {
    int failed = 0;
    failed += report_case("ENOENT", check_enoent());
    failed += report_case("EACCES", check_eacces());
    failed += report_case("ENOEXEC", check_enoexec());
    failed += report_case("ENOMEM", check_enomem());
    failed += report_case("ENAMETOOLONG", check_enametoolong());
    if (failed == 0)
        printf("ERRNO_SMOKE_OK\n");
    printf("TEST_SUMMARY: failed=%d\n", failed);
    printf("TEST_RESULT_JSON: {\"schema_version\":1,\"failed\":%d,\"done\":true,\"enabled_mask\":1}\n",
           failed);
    printf("__ERRNO_SMOKE_DONE__\n");
    return failed ? 1 : 0;
}
