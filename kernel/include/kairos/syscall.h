/**
 * kairos/syscall.h - System call definitions
 */

#ifndef _KAIROS_SYSCALL_H
#define _KAIROS_SYSCALL_H

#include <kairos/types.h>

/*
 * System Call Numbers
 *
 * We use our own numbering (not Linux compatible).
 * This keeps implementation simple while providing a clean API.
 */

/* Process */
#define SYS_exit            1
#define SYS_fork            2
#define SYS_exec            3
#define SYS_wait            4
#define SYS_getpid          5
#define SYS_getppid         6
#define SYS_yield           7
#define SYS_clone           8

/* File I/O */
#define SYS_open            10
#define SYS_close           11
#define SYS_read            12
#define SYS_write           13
#define SYS_lseek           14
#define SYS_stat            15
#define SYS_fstat           16
#define SYS_readdir         17
#define SYS_dup             18
#define SYS_dup2            19
#define SYS_fcntl           20
#define SYS_ioctl           21
#define SYS_access          22
#define SYS_unlink          23

/* Directory */
#define SYS_mkdir           30
#define SYS_rmdir           31
#define SYS_chdir           32
#define SYS_getcwd          33

/* Memory */
#define SYS_brk             40
#define SYS_mmap            41
#define SYS_munmap          42
#define SYS_mprotect        43

/* IPC */
#define SYS_pipe            50
#define SYS_pipe2           51

/* Signals */
#define SYS_kill            60
#define SYS_signal          61
#define SYS_sigaction       62
#define SYS_sigprocmask     63
#define SYS_sigreturn       64
#define SYS_pause           65
#define SYS_sigsuspend      66

/* Time */
#define SYS_time            70
#define SYS_gettimeofday    71
#define SYS_nanosleep       72
#define SYS_clock_gettime   73

/* I/O Multiplexing */
#define SYS_poll            80
#define SYS_select          81

/* User/Group (simplified) */
#define SYS_getuid          90
#define SYS_getgid          91
#define SYS_setuid          92
#define SYS_setgid          93

/* Misc */
#define SYS_uname           100
#define SYS_reboot          101

#define SYS_MAX             128

/*
 * Syscall handler type
 */
typedef int64_t (*syscall_fn_t)(uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t);

/*
 * Syscall table
 */
extern syscall_fn_t syscall_table[SYS_MAX];

/*
 * Syscall dispatch (called from trap handler)
 */
int64_t syscall_dispatch(uint64_t num,
                         uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5);

/*
 * Initialize syscall table
 */
void syscall_init(void);

/*
 * Individual syscall implementations (defined in syscall/*.c)
 */

/* Process */
noreturn void sys_exit(int status);
pid_t sys_fork(void);
int sys_exec(const char *path, char *const argv[], char *const envp[]);
pid_t sys_wait(pid_t pid, int *status, int options);
pid_t sys_getpid(void);
pid_t sys_getppid(void);
int sys_yield(void);

/* File I/O */
int sys_open(const char *path, int flags, mode_t mode);
int sys_close(int fd);
ssize_t sys_read(int fd, void *buf, size_t count);
ssize_t sys_write(int fd, const void *buf, size_t count);
off_t sys_lseek(int fd, off_t offset, int whence);
int sys_stat(const char *path, struct stat *st);
int sys_fstat(int fd, struct stat *st);
int sys_dup(int fd);
int sys_dup2(int oldfd, int newfd);
int sys_unlink(const char *path);

/* Directory */
int sys_mkdir(const char *path, mode_t mode);
int sys_rmdir(const char *path);
int sys_chdir(const char *path);
int sys_getcwd(char *buf, size_t size);

/* Memory */
void *sys_brk(void *addr);
void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int sys_munmap(void *addr, size_t len);

/* IPC */
int sys_pipe(int pipefd[2]);
int sys_pipe2(int pipefd[2], int flags);

/* Signals */
int sys_kill(pid_t pid, int sig);
void *sys_signal(int sig, void *handler);
int sys_sigaction(int sig, const struct sigaction *act, struct sigaction *old);
int sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sys_sigreturn(void);
int sys_pause(void);

/* Time */
time_t sys_time(time_t *t);
int sys_nanosleep(const struct timespec *req, struct timespec *rem);

/* I/O Multiplexing */
int sys_poll(struct pollfd *fds, size_t nfds, int timeout);

/* Misc */
int sys_uname(struct utsname *buf);
int sys_reboot(int cmd);

#endif /* _KAIROS_SYSCALL_H */
