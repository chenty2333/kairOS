/**
 * kernel/include/kairos/syscall.h - System call definitions
 */

#ifndef _KAIROS_SYSCALL_H
#define _KAIROS_SYSCALL_H

#include <kairos/types.h>

struct stat;
struct sigaction;
struct timespec;
struct pollfd;
typedef uint64_t sigset_t;

/* Linux riscv64 syscall numbers (from asm-generic/unistd.h) */
#define LINUX_NR_getcwd 17
#define LINUX_NR_epoll_create1 20
#define LINUX_NR_epoll_ctl 21
#define LINUX_NR_epoll_pwait 22
#define LINUX_NR_dup 23
#define LINUX_NR_dup3 24
#define LINUX_NR_fcntl 25
#define LINUX_NR_ioctl 29
#define LINUX_NR_openat 56
#define LINUX_NR_close 57
#define LINUX_NR_pipe2 59
#define LINUX_NR_getdents64 61
#define LINUX_NR_lseek 62
#define LINUX_NR_read 63
#define LINUX_NR_write 64
#define LINUX_NR_newfstatat 79
#define LINUX_NR_fstat 80
#define LINUX_NR_exit 93
#define LINUX_NR_exit_group 94
#define LINUX_NR_futex 98
#define LINUX_NR_nanosleep 101
#define LINUX_NR_clock_gettime 113
#define LINUX_NR_ppoll 73
#define LINUX_NR_pselect6 72
#define LINUX_NR_kill 129
#define LINUX_NR_rt_sigaction 134
#define LINUX_NR_rt_sigprocmask 135
#define LINUX_NR_rt_sigreturn 139
#define LINUX_NR_setgid 144
#define LINUX_NR_setuid 146
#define LINUX_NR_uname 160
#define LINUX_NR_getpid 172
#define LINUX_NR_getppid 173
#define LINUX_NR_getuid 174
#define LINUX_NR_getgid 176
#define LINUX_NR_brk 214
#define LINUX_NR_munmap 215
#define LINUX_NR_clone 220
#define LINUX_NR_mmap 222
#define LINUX_NR_mprotect 226
#define LINUX_NR_wait4 260

#define AT_FDCWD (-100)
#define O_CLOEXEC 02000000

#define SYS_exit 1
#define SYS_fork 2
#define SYS_exec 3
#define SYS_wait 4
#define SYS_getpid 5
#define SYS_getppid 6
#define SYS_yield 7
#define SYS_clone 8

#define SYS_open 10
#define SYS_close 11
#define SYS_read 12
#define SYS_write 13
#define SYS_lseek 14
#define SYS_stat 15
#define SYS_fstat 16
#define SYS_readdir 17
#define SYS_dup 18
#define SYS_dup2 19
#define SYS_fcntl 20
#define SYS_ioctl 21
#define SYS_access 22
#define SYS_unlink 23

#define SYS_mkdir 30
#define SYS_rmdir 31
#define SYS_chdir 32
#define SYS_getcwd 33

#define SYS_brk 40
#define SYS_mmap 41
#define SYS_munmap 42
#define SYS_mprotect 43

#define SYS_pipe 50
#define SYS_pipe2 51

#define SYS_kill 60
#define SYS_signal 61
#define SYS_sigaction 62
#define SYS_sigprocmask 63
#define SYS_sigreturn 64
#define SYS_pause 65
#define SYS_sigsuspend 66

#define SYS_time 70
#define SYS_gettimeofday 71
#define SYS_nanosleep 72
#define SYS_clock_gettime 73

#define SYS_poll 80
#define SYS_select 81
#define SYS_epoll_create1 82
#define SYS_epoll_ctl 83
#define SYS_epoll_wait 84

#define SYS_getuid 90
#define SYS_getgid 91
#define SYS_setuid 92
#define SYS_setgid 93

#define SYS_uname 100
#define SYS_reboot 101

#define SYS_sem_init 110
#define SYS_sem_wait 111
#define SYS_sem_post 112

#define SYS_MAX 128

/* Standard syscall handler type */
typedef int64_t (*syscall_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t);

extern syscall_fn_t syscall_table[SYS_MAX];

int64_t syscall_dispatch(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5);

void syscall_init(void);

/* Syscall Kernel Implementations */
int64_t sys_exit(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fork(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_write(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_openat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_lseek(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getdents64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mmap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_munmap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mprotect(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_clock_gettime(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_nanosleep(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_uname(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getppid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_exit_group(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_futex(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fcntl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pipe2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_kill(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sigaction(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sigprocmask(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sigreturn(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_poll(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_select(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_epoll_create1(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_epoll_ctl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_epoll_wait(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

#endif
