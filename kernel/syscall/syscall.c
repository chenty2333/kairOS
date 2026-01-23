/**
 * syscall.c - System Call Implementation
 *
 * Implements the syscall dispatch table and basic syscalls.
 * More syscalls will be added in later phases.
 */

#include <kairos/types.h>
#include <kairos/syscall.h>
#include <kairos/printk.h>
#include <kairos/arch.h>
#include <kairos/process.h>
#include <kairos/sched.h>

/* Syscall table */
syscall_fn_t syscall_table[SYS_MAX];

/**
 * sys_nosys - Handler for unimplemented syscalls
 */
static int64_t sys_nosys(uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return -ENOSYS;
}

/**
 * sys_write - Write to a file descriptor
 *
 * For now, only supports fd 1 (stdout) and 2 (stderr),
 * writing directly to the console.
 */
ssize_t sys_write(int fd, const void *buf, size_t count)
{
    if (fd != 1 && fd != 2) {
        return -EBADF;  /* Only stdout/stderr for now */
    }

    if (!buf) {
        return -EFAULT;
    }

    const char *p = buf;
    for (size_t i = 0; i < count; i++) {
        arch_early_putchar(p[i]);
    }

    return (ssize_t)count;
}

/**
 * sys_exit - Exit the current process
 */
noreturn void sys_exit(int status)
{
    proc_exit(status);
    /* Never reached */
}

/**
 * sys_getpid - Get current process ID
 */
pid_t sys_getpid(void)
{
    struct process *p = proc_current();
    return p ? p->pid : 0;
}

/**
 * sys_getppid - Get parent process ID
 */
pid_t sys_getppid(void)
{
    struct process *p = proc_current();
    return p ? p->ppid : 0;
}

/**
 * sys_yield - Yield the CPU
 */
int sys_yield(void)
{
    proc_yield();
    return 0;
}

/**
 * sys_fork - Fork the current process
 *
 * Returns child PID to parent, 0 to child, -1 on error.
 */
pid_t sys_fork(void)
{
    struct process *child = proc_fork();
    if (!child) {
        return -ENOMEM;
    }

    /* Add child to scheduler run queue */
    sched_enqueue(child);

    /* Return child PID to parent */
    return child->pid;
}

/**
 * sys_wait - Wait for child process
 *
 * @pid: Child PID to wait for (-1 = any child)
 * @status: Pointer to store exit status
 * @options: Wait options (ignored for now)
 */
pid_t sys_wait(pid_t pid, int *status, int options)
{
    return proc_wait(pid, status, options);
}

/**
 * sys_exec - Replace current process image with new program
 *
 * Note: Since we don't have a filesystem yet, this is a simplified version
 * that takes a path but can only execute embedded test programs.
 *
 * @path: Path to executable (ignored for now)
 * @argv: Argument vector (ignored for now)
 * @envp: Environment vector (ignored for now)
 *
 * Returns: -ENOSYS for now (not fully implemented without filesystem)
 */
int sys_exec(const char *path, char *const argv[], char *const envp[])
{
    (void)path;
    (void)argv;
    (void)envp;

    /* Without a filesystem, we can't load executables from path */
    /* This will be implemented properly when we have VFS */
    pr_warn("sys_exec: filesystem not available yet\n");
    return -ENOSYS;
}

/**
 * sys_uname - Get system information
 */
int sys_uname(struct utsname *buf)
{
    if (!buf) {
        return -EFAULT;
    }

    /* Simple implementation - just copy strings */
    /* In a real kernel, we'd use copy_to_user */
    const char *sysname = "Kairos";
    const char *nodename = "kairos";
    const char *release = "0.1.0";
    const char *version = "Phase 2";
    const char *machine = "riscv64";

    /* Copy each field (simplified - no bounds checking) */
    char *dst = (char *)buf;
    const char *srcs[] = {sysname, nodename, release, version, machine};

    for (int i = 0; i < 5; i++) {
        const char *src = srcs[i];
        while (*src) {
            *dst++ = *src++;
        }
        *dst++ = '\0';
        /* Pad to 65 bytes (standard utsname field size) */
        while ((dst - (char *)buf) % 65 != 0) {
            *dst++ = '\0';
        }
    }

    return 0;
}

/**
 * Wrapper functions to match syscall_fn_t signature
 */
static int64_t sys_write_wrapper(uint64_t fd, uint64_t buf, uint64_t count,
                                  uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a3; (void)a4; (void)a5;
    return sys_write((int)fd, (const void *)buf, (size_t)count);
}

static int64_t sys_exit_wrapper(uint64_t status, uint64_t a1, uint64_t a2,
                                 uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    sys_exit((int)status);
    /* Never reached */
    return 0;
}

static int64_t sys_getpid_wrapper(uint64_t a0, uint64_t a1, uint64_t a2,
                                   uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_getpid();
}

static int64_t sys_yield_wrapper(uint64_t a0, uint64_t a1, uint64_t a2,
                                  uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_yield();
}

static int64_t sys_uname_wrapper(uint64_t buf, uint64_t a1, uint64_t a2,
                                  uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_uname((struct utsname *)buf);
}

static int64_t sys_getppid_wrapper(uint64_t a0, uint64_t a1, uint64_t a2,
                                    uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_getppid();
}

static int64_t sys_fork_wrapper(uint64_t a0, uint64_t a1, uint64_t a2,
                                 uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_fork();
}

static int64_t sys_wait_wrapper(uint64_t pid, uint64_t status, uint64_t options,
                                 uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a3; (void)a4; (void)a5;
    return sys_wait((pid_t)pid, (int *)status, (int)options);
}

static int64_t sys_exec_wrapper(uint64_t path, uint64_t argv, uint64_t envp,
                                 uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a3; (void)a4; (void)a5;
    return sys_exec((const char *)path, (char *const *)argv, (char *const *)envp);
}

/**
 * syscall_init - Initialize syscall table
 */
void syscall_init(void)
{
    /* Initialize all entries to nosys */
    for (int i = 0; i < SYS_MAX; i++) {
        syscall_table[i] = sys_nosys;
    }

    /* Register implemented syscalls */
    syscall_table[SYS_exit] = sys_exit_wrapper;
    syscall_table[SYS_fork] = sys_fork_wrapper;
    syscall_table[SYS_exec] = sys_exec_wrapper;
    syscall_table[SYS_wait] = sys_wait_wrapper;
    syscall_table[SYS_getpid] = sys_getpid_wrapper;
    syscall_table[SYS_getppid] = sys_getppid_wrapper;
    syscall_table[SYS_yield] = sys_yield_wrapper;
    syscall_table[SYS_write] = sys_write_wrapper;
    syscall_table[SYS_uname] = sys_uname_wrapper;

    pr_info("Syscall: initialized %d syscalls\n", SYS_MAX);
}

/**
 * syscall_dispatch - Dispatch a system call
 *
 * Called from trap handler with syscall number and arguments.
 */
int64_t syscall_dispatch(uint64_t num,
                         uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5)
{
    if (num >= SYS_MAX) {
        pr_warn("Invalid syscall number: %lu\n", num);
        return -ENOSYS;
    }

    syscall_fn_t fn = syscall_table[num];
    return fn(a0, a1, a2, a3, a4, a5);
}
