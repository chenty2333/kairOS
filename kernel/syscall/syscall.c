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
 *
 * For now, just prints a message and halts.
 * Real implementation will come in Phase 3.
 */
noreturn void sys_exit(int status)
{
    pr_info("Process exited with status %d\n", status);

    /* TODO: Clean up process resources in Phase 3 */

    /* For now, just halt */
    while (1) {
        arch_cpu_halt();
    }
}

/**
 * sys_getpid - Get current process ID
 *
 * Returns 1 for now (init process).
 */
pid_t sys_getpid(void)
{
    /* TODO: Return actual PID in Phase 3 */
    return 1;
}

/**
 * sys_yield - Yield the CPU
 *
 * For now, just returns. Real implementation in Phase 4.
 */
int sys_yield(void)
{
    /* TODO: Call scheduler in Phase 4 */
    return 0;
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
    syscall_table[SYS_getpid] = sys_getpid_wrapper;
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
