/**
 * kernel/core/syscall/syscall.c - Syscall dispatch
 */

#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/syscall.h>

extern int64_t linux_syscall_dispatch(uint64_t num, uint64_t a0, uint64_t a1,
                                      uint64_t a2, uint64_t a3, uint64_t a4,
                                      uint64_t a5);

syscall_fn_t syscall_table[SYS_MAX] = {
    [SYS_exit]    = sys_exit,
    [SYS_fork]    = sys_fork,
    [SYS_exec]    = sys_exec,
    [SYS_getpid]  = sys_getpid,
    [SYS_getppid] = sys_getppid,
    [SYS_wait]    = sys_wait,
    [SYS_brk]     = sys_brk,
    [SYS_open]    = sys_open,
    [SYS_read]    = sys_read,
    [SYS_write]   = sys_write,
    [SYS_close]   = sys_close,
    [SYS_lseek]   = sys_lseek,
    [SYS_stat]    = sys_stat,
    [SYS_fstat]   = sys_fstat,
    [SYS_getcwd]  = sys_getcwd,
    [SYS_chdir]   = sys_chdir,
    [SYS_mkdir]   = sys_mkdir,
    [SYS_rmdir]   = sys_rmdir,
    [SYS_unlink]  = sys_unlink,
    [SYS_access]  = sys_access,
    [SYS_dup2]    = sys_dup2,
    [SYS_fcntl]   = sys_fcntl,
    [SYS_pipe]    = sys_pipe,
    [SYS_pipe2]   = sys_pipe2,
    [SYS_sem_init] = sys_sem_init,
    [SYS_sem_wait] = sys_sem_wait,
    [SYS_sem_post] = sys_sem_post,
    [SYS_poll]    = sys_poll,
    [SYS_select]  = sys_select,
    [SYS_epoll_create1] = sys_epoll_create1,
    [SYS_epoll_ctl] = sys_epoll_ctl,
    [SYS_epoll_wait] = sys_epoll_wait,
    [SYS_getuid]  = sys_getuid,
    [SYS_getgid]  = sys_getgid,
    [SYS_setuid]  = sys_setuid,
    [SYS_setgid]  = sys_setgid,
    [SYS_uname]   = sys_uname,
    [SYS_clock_gettime] = sys_clock_gettime,
    [SYS_nanosleep] = sys_nanosleep,
    [SYS_gettimeofday] = sys_gettimeofday,
    [SYS_kill]    = sys_kill,
    [SYS_sigaction] = sys_sigaction,
    [SYS_sigprocmask] = sys_sigprocmask,
    [SYS_sigreturn] = sys_sigreturn,
};

int64_t syscall_dispatch(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5) {
    struct process *p = proc_current();
    if (!p || p->syscall_abi == SYSCALL_ABI_LINUX)
        return linux_syscall_dispatch(num, a0, a1, a2, a3, a4, a5);

    if (num >= SYS_MAX || !syscall_table[num])
        return -ENOSYS;
    return syscall_table[num](a0, a1, a2, a3, a4, a5);
}

void syscall_init(void) {
    pr_info("Syscall: initialized\n");
}
