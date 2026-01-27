/**
 * kernel/core/syscall/abi_linux.c - Linux syscall dispatch
 */

#include <kairos/syscall.h>

int64_t linux_syscall_dispatch(uint64_t num, uint64_t a0, uint64_t a1,
                               uint64_t a2, uint64_t a3, uint64_t a4,
                               uint64_t a5) {
    switch (num) {
    case LINUX_NR_getcwd:
        return sys_getcwd(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_mkdirat:
        return sys_mkdirat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_unlinkat:
        return sys_unlinkat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_symlinkat:
        return sys_symlinkat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_renameat:
        return sys_renameat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_faccessat:
        return sys_faccessat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_chdir:
        return sys_chdir(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_fchdir:
        return sys_fchdir(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_epoll_create1:
        return sys_epoll_create1(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_epoll_ctl:
        return sys_epoll_ctl(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_epoll_pwait:
        return sys_epoll_wait(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_dup:
        return sys_dup(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_dup3:
        return sys_dup3(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_fcntl:
        return sys_fcntl(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_ioctl:
        return sys_ioctl(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_openat:
        return sys_openat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_close:
        return sys_close(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_pipe2:
        return sys_pipe2(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getdents64:
        return sys_getdents64(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_lseek:
        return sys_lseek(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_read:
        return sys_read(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_write:
        return sys_write(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_ppoll:
        return sys_ppoll(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_pselect6:
        return sys_pselect6(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_newfstatat:
        return sys_newfstatat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_fstat:
        return sys_fstat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_readlinkat:
        return sys_readlinkat(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_exit:
        return sys_exit(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_exit_group:
        return sys_exit_group(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_set_tid_address:
        return sys_set_tid_address(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_futex:
        return sys_futex(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_nanosleep:
        return sys_nanosleep(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_clock_gettime:
        return sys_clock_gettime(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_clock_nanosleep:
        return sys_clock_nanosleep(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_kill:
        return sys_kill(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_tgkill:
        return sys_tgkill(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_rt_sigaction:
        return sys_sigaction(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_rt_sigprocmask:
        return sys_sigprocmask(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_rt_sigreturn:
        return sys_sigreturn(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_setgid:
        return sys_setgid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_setuid:
        return sys_setuid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_uname:
        return sys_uname(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_umask:
        return sys_umask(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_gettimeofday:
        return sys_gettimeofday(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getpid:
        return sys_getpid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getppid:
        return sys_getppid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getuid:
        return sys_getuid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_getgid:
        return sys_getgid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_gettid:
        return sys_gettid(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_brk:
        return sys_brk(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_munmap:
        return sys_munmap(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_clone:
        return sys_clone(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_execve:
        return sys_execve(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_mmap:
        return sys_mmap(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_mprotect:
        return sys_mprotect(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_wait4:
        return sys_wait4(a0, a1, a2, a3, a4, a5);
    case LINUX_NR_prlimit64:
        return sys_prlimit64(a0, a1, a2, a3, a4, a5);
    default:
        return -ENOSYS;
    }
}
