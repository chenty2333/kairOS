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

/* Linux riscv64 syscall numbers (subset from asm-generic/unistd.h) */
#define X(nr, name, handler) enum { LINUX_NR_##name = nr };
#include <kairos/linux_syscalls.def>
#undef X

#define AT_FDCWD (-100)
#define O_CLOEXEC 02000000
#define FD_CLOEXEC 1
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR 0x200
#define AT_EACCESS 0x200
#define AT_SYMLINK_FOLLOW 0x400
#define AT_EMPTY_PATH 0x1000
#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

/* mount flags */
#define MS_RDONLY 0x1
#define MS_NOSUID 0x2
#define MS_NODEV 0x4
#define MS_NOEXEC 0x8
#define MS_SYNCHRONOUS 0x10
#define MS_REMOUNT 0x20
#define MS_DIRSYNC 0x80
#define MS_NOATIME 0x400
#define MS_NODIRATIME 0x800
#define MS_BIND 0x1000
#define MS_REC 0x4000
#define MS_SILENT 0x8000
#define MS_POSIXACL 0x10000
#define MS_UNBINDABLE 0x20000
#define MS_PRIVATE 0x40000
#define MS_SLAVE 0x80000
#define MS_SHARED 0x100000
#define MS_RELATIME 0x200000
#define MS_STRICTATIME 0x1000000
#define MS_LAZYTIME 0x2000000

/* umount2 flags */
#define MNT_FORCE 0x1
#define MNT_DETACH 0x2
#define MNT_EXPIRE 0x4
#define UMOUNT_NOFOLLOW 0x8

#define SYS_exit 1
#define SYS_fork 2
#define SYS_exec 3
#define SYS_wait 4
#define SYS_getpid 5
#define SYS_getppid 6
#define SYS_yield 7
#define SYS_clone 8

int64_t sys_chroot(uint64_t path, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5);
int64_t sys_pivot_root(uint64_t new_root, uint64_t put_old, uint64_t a2,
                       uint64_t a3, uint64_t a4, uint64_t a5);
int64_t sys_mount(uint64_t source, uint64_t target, uint64_t fstype,
                  uint64_t flags, uint64_t data, uint64_t a5);
int64_t sys_umount2(uint64_t target, uint64_t flags, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5);

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
int64_t sys_exec(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_execve(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getpid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_gettid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_set_tid_address(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
int64_t sys_tgkill(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_write(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_read(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_writev(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_readv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pread64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pwrite64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_preadv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pwritev(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_preadv2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pwritev2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_copy_file_range(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
int64_t sys_close(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_open(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_openat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_openat2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_lseek(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_stat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fstat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_newfstatat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                       uint64_t);
int64_t sys_statx(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getdents64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_dup(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_dup2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_dup3(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pipe(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fsync(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fdatasync(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fchmod(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_close_range(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mmap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_munmap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mprotect(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mremap(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_clock_gettime(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_clock_getres(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_clock_settime(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_nanosleep(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_clock_nanosleep(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
int64_t sys_gettimeofday(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_times(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getitimer(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setitimer(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_timerfd_create(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                           uint64_t);
int64_t sys_timerfd_settime(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
int64_t sys_timerfd_gettime(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
int64_t sys_getrusage(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sysinfo(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_syslog(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_uname(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sethostname(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setdomainname(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                          uint64_t);
int64_t sys_getppid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_wait(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_wait4(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_waitid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_clone(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_brk(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_exit_group(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_prlimit64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                      uint64_t);
int64_t sys_execveat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                     uint64_t);
int64_t sys_futex(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_futex_waitv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t);
int64_t sys_eventfd2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_inotify_init1(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                          uint64_t);
int64_t sys_inotify_add_watch(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t);
int64_t sys_inotify_rm_watch(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                             uint64_t);
int64_t sys_fcntl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_ioctl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pipe2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sem_init(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sem_wait(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sem_post(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_set_robust_list(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
int64_t sys_get_robust_list(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
int64_t sys_getcwd(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getuid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_geteuid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getegid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getgroups(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getpriority(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t);
int64_t sys_getresuid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                      uint64_t);
int64_t sys_getresgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                      uint64_t);
int64_t sys_setuid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setpriority(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t);
int64_t sys_setreuid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                     uint64_t);
int64_t sys_setregid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                     uint64_t);
int64_t sys_socket(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_socketpair(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                       uint64_t);
int64_t sys_bind(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_listen(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_accept(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_accept4(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_connect(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_getsockname(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t);
int64_t sys_getpeername(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t);
int64_t sys_sendto(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_recvfrom(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                     uint64_t);
int64_t sys_sendmsg(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_recvmsg(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sendmmsg(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_recvmmsg(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setsockopt(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                       uint64_t);
int64_t sys_getsockopt(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                       uint64_t);
int64_t sys_shutdown(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                     uint64_t);
int64_t sys_setresuid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                      uint64_t);
int64_t sys_setresgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                      uint64_t);
int64_t sys_setpgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                    uint64_t);
int64_t sys_getpgid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                    uint64_t);
int64_t sys_getsid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                   uint64_t);
int64_t sys_setsid(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                   uint64_t);
int64_t sys_getrlimit(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_setrlimit(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sched_getaffinity(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t);
int64_t sys_sched_setaffinity(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t);
int64_t sys_sched_setparam(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                           uint64_t);
int64_t sys_sched_setscheduler(uint64_t, uint64_t, uint64_t, uint64_t,
                               uint64_t, uint64_t);
int64_t sys_sched_getscheduler(uint64_t, uint64_t, uint64_t, uint64_t,
                               uint64_t, uint64_t);
int64_t sys_sched_getparam(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                           uint64_t);
int64_t sys_sched_yield(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t);
int64_t sys_chdir(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fchdir(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fchmodat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fchmodat2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fchownat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_utimensat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_unlinkat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mknodat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mkdirat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_renameat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_renameat2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_readlinkat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                       uint64_t);
int64_t sys_symlinkat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_linkat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_faccessat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_faccessat2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                       uint64_t);
int64_t sys_umask(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_unlink(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_mkdir(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_rmdir(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_access(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_statfs(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fstatfs(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_truncate(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                     uint64_t);
int64_t sys_ftruncate(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                      uint64_t);
int64_t sys_sync(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_acct(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_fchown(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_kill(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_tkill(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sigaction(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sigprocmask(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sigreturn(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_sigaltstack(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t);
int64_t sys_rt_sigpending(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                          uint64_t);
int64_t sys_rt_sigsuspend(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                          uint64_t);
int64_t sys_rt_sigtimedwait(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
int64_t sys_rt_sigqueueinfo(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
int64_t sys_signalfd4(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                      uint64_t);
int64_t sys_poll(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_select(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_ppoll(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_pselect6(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                     uint64_t);
int64_t sys_epoll_pwait2(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                         uint64_t);
int64_t sys_epoll_create1(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_epoll_ctl(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_epoll_wait(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t sys_kairos_handle_close(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t);
int64_t sys_kairos_handle_duplicate(uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t);
int64_t sys_kairos_channel_create(uint64_t, uint64_t, uint64_t, uint64_t,
                                  uint64_t, uint64_t);
int64_t sys_kairos_channel_send(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t);
int64_t sys_kairos_channel_recv(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t);
int64_t sys_kairos_port_create(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                               uint64_t);
int64_t sys_kairos_port_bind(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                             uint64_t);
int64_t sys_kairos_port_wait(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                             uint64_t);
int64_t sys_kairos_cap_rights_get(uint64_t, uint64_t, uint64_t, uint64_t,
                                  uint64_t, uint64_t);
int64_t sys_kairos_cap_rights_limit(uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t);

#endif
