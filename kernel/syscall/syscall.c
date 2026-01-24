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
#include <kairos/vfs.h>
#include <kairos/elf.h>
#include <kairos/mm.h>
#include <kairos/uaccess.h>
#include <kairos/config.h>
#include <kairos/string.h>

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
 * sys_open - Open a file
 */
int sys_open(const char *path, int flags, mode_t mode)
{
    struct process *p = proc_current();
    struct file *file;
    char kpath[CONFIG_PATH_MAX];
    int fd;
    int ret;
    long len;

    if (!p || !path) {
        return -EINVAL;
    }

    /* Copy path from user space */
    len = strncpy_from_user(kpath, path, CONFIG_PATH_MAX);
    if (len < 0) return len;
    if (len >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
    kpath[len] = '\0';

    /* Open file through VFS */
    ret = vfs_open(kpath, flags, mode, &file);
    if (ret < 0) {
        return ret;
    }

    /* Allocate file descriptor */
    fd = fd_alloc(p, file);
    if (fd < 0) {
        vfs_close(file);
        return fd;
    }

    return fd;
}

/**
 * sys_close - Close a file descriptor
 */
int sys_close(int fd)
{
    struct process *p = proc_current();
    if (!p) {
        return -EINVAL;
    }

    return fd_close(p, fd);
}

/**
 * sys_read - Read from a file descriptor
 */
ssize_t sys_read(int fd, void *buf, size_t count)
{
    struct process *p = proc_current();
    struct file *file;
    char kbuf[512];
    ssize_t total_read = 0;

    if (!p || !buf) {
        return -EINVAL;
    }

    file = fd_get(p, fd);
    if (!file) {
        return -EBADF;
    }

    while (count > 0) {
        size_t chunk = (count > sizeof(kbuf)) ? sizeof(kbuf) : count;
        ssize_t n = vfs_read(file, kbuf, chunk);
        
        if (n < 0) {
            return (total_read > 0) ? total_read : n;
        }
        if (n == 0) {
            break; /* EOF */
        }
        
        if (copy_to_user((char *)buf + total_read, kbuf, n) < 0) {
            return -EFAULT;
        }
        
        total_read += n;
        count -= n;
        
        if ((size_t)n < chunk) {
            break; /* Short read */
        }
    }

    return total_read;
}

/**
 * sys_write - Write to a file descriptor
 */
ssize_t sys_write(int fd, const void *buf, size_t count)
{
    struct process *p = proc_current();
    struct file *file;
    char kbuf[512];
    ssize_t total_written = 0;

    if (!p || !buf) {
        return -EINVAL;
    }

    /* If no VFS file table yet, use legacy console output */
    file = fd_get(p, fd);
    if (!file) {
        /* Legacy: stdout/stderr to console */
        if (fd == 1 || fd == 2) {
            while (count > 0) {
                size_t chunk = (count > sizeof(kbuf)) ? sizeof(kbuf) : count;
                if (copy_from_user(kbuf, (const char *)buf + total_written, chunk) < 0) {
                    return -EFAULT;
                }
                
                for (size_t i = 0; i < chunk; i++) {
                    arch_early_putchar(kbuf[i]);
                }
                
                total_written += chunk;
                count -= chunk;
            }
            return total_written;
        }
        return -EBADF;
    }

    /* Write to file */
    while (count > 0) {
        size_t chunk = (count > sizeof(kbuf)) ? sizeof(kbuf) : count;
        
        if (copy_from_user(kbuf, (const char *)buf + total_written, chunk) < 0) {
            return -EFAULT;
        }

        ssize_t n = vfs_write(file, kbuf, chunk);
        if (n < 0) {
            return (total_written > 0) ? total_written : n;
        }
        
        total_written += n;
        count -= n;
        
        if ((size_t)n < chunk) {
            break; /* Short write */
        }
    }

    return total_written;
}

/**
 * sys_lseek - Seek in a file
 */
off_t sys_lseek(int fd, off_t offset, int whence)
{
    struct process *p = proc_current();
    struct file *file;

    if (!p) {
        return -EINVAL;
    }

    file = fd_get(p, fd);
    if (!file) {
        return -EBADF;
    }

    return vfs_seek(file, offset, whence);
}

/**
 * sys_stat - Get file status
 */
int sys_stat(const char *path, struct stat *st)
{
    char kpath[CONFIG_PATH_MAX];
    struct stat kst;
    long len;
    int ret;

    if (!path || !st) {
        return -EINVAL;
    }

    len = strncpy_from_user(kpath, path, CONFIG_PATH_MAX);
    if (len < 0) return len;
    if (len >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
    kpath[len] = '\0';

    ret = vfs_stat(kpath, &kst);
    if (ret < 0) {
        return ret;
    }

    if (copy_to_user(st, &kst, sizeof(kst)) < 0) {
        return -EFAULT;
    }

    return 0;
}

/**
 * sys_fstat - Get file status by fd
 */
int sys_fstat(int fd, struct stat *st)
{
    struct process *p = proc_current();
    struct file *file;
    struct stat kst;
    int ret;

    if (!p || !st) {
        return -EINVAL;
    }

    file = fd_get(p, fd);
    if (!file) {
        return -EBADF;
    }

    ret = vfs_fstat(file, &kst);
    if (ret < 0) {
        return ret;
    }

    if (copy_to_user(st, &kst, sizeof(kst)) < 0) {
        return -EFAULT;
    }

    return 0;
}

/**
 * sys_dup - Duplicate file descriptor
 */
int sys_dup(int fd)
{
    struct process *p = proc_current();
    if (!p) {
        return -EINVAL;
    }

    return fd_dup(p, fd);
}

/**
 * sys_dup2 - Duplicate file descriptor to specific number
 */
int sys_dup2(int oldfd, int newfd)
{
    struct process *p = proc_current();
    if (!p) {
        return -EINVAL;
    }

    return fd_dup2(p, oldfd, newfd);
}

/**
 * sys_mkdir - Create a directory
 */
int sys_mkdir(const char *path, mode_t mode)
{
    char kpath[CONFIG_PATH_MAX];
    long len;

    if (!path) {
        return -EINVAL;
    }

    len = strncpy_from_user(kpath, path, CONFIG_PATH_MAX);
    if (len < 0) return len;
    if (len >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
    kpath[len] = '\0';

    return vfs_mkdir(kpath, mode);
}

/**
 * sys_rmdir - Remove a directory
 */
int sys_rmdir(const char *path)
{
    char kpath[CONFIG_PATH_MAX];
    long len;

    if (!path) {
        return -EINVAL;
    }

    len = strncpy_from_user(kpath, path, CONFIG_PATH_MAX);
    if (len < 0) return len;
    if (len >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
    kpath[len] = '\0';

    return vfs_rmdir(kpath);
}

/**
 * sys_unlink - Delete a file
 */
int sys_unlink(const char *path)
{
    char kpath[CONFIG_PATH_MAX];
    long len;

    if (!path) {
        return -EINVAL;
    }

    len = strncpy_from_user(kpath, path, CONFIG_PATH_MAX);
    if (len < 0) return len;
    if (len >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
    kpath[len] = '\0';

    return vfs_unlink(kpath);
}

/**
 * sys_chdir - Change current working directory
 */
int sys_chdir(const char *path)
{
    struct process *p = proc_current();
    struct vnode *vn;
    char kpath[CONFIG_PATH_MAX];
    char normalized[CONFIG_PATH_MAX];
    long len;

    if (!p || !path) {
        return -EINVAL;
    }

    /* Copy path from user space */
    len = strncpy_from_user(kpath, path, CONFIG_PATH_MAX);
    if (len < 0) return len;
    if (len >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
    kpath[len] = '\0';

    /* Normalize path */
    const char *cwd = p->cwd;
    if (vfs_normalize_path(cwd, kpath, normalized) < 0) {
        return -EINVAL;
    }

    /* Verify directory exists */
    vn = vfs_lookup(normalized);
    if (!vn) {
        return -ENOENT;
    }

    if (vn->type != VNODE_DIR) {
        vnode_put(vn);
        return -ENOTDIR;
    }
    vnode_put(vn);

    /* Update process CWD */
    char *dest = p->cwd;
    const char *src = normalized;
    while ((*dest++ = *src++));

    return 0;
}

/**
 * sys_getcwd - Get current working directory
 */
int sys_getcwd(char *buf, size_t size)
{
    struct process *p = proc_current();
    const char *cwd;
    size_t len;

    if (!p || !buf || size == 0) {
        return -EINVAL;
    }

    cwd = p->cwd;
    len = strlen(cwd);

    if (size < len + 1) {
        return -ERANGE;
    }

    if (copy_to_user(buf, cwd, len + 1) < 0) {
        return -EFAULT;
    }

    return 0;
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
    pr_debug("sys_fork: entering\n");
    struct process *child = proc_fork();
    if (!child) {
        return -ENOMEM;
    }

    pr_debug("sys_fork: child created %d, enqueuing\n", child->pid);

    /* Add child to scheduler run queue */
    sched_enqueue(child);

    pr_debug("sys_fork: child enqueued, returning\n");

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
 * Loads an ELF executable from the filesystem and replaces the current
 * process image with it.
 *
 * @path: Path to executable
 * @argv: Argument vector (ignored for now)
 * @envp: Environment vector (ignored for now)
 *
 * Returns: -errno on failure, does not return on success
 */
int sys_exec(const char *path, char *const argv[], char *const envp[])
{
    struct process *p = proc_current();
    struct file *file;
    struct vnode *vn;
    char kpath[CONFIG_PATH_MAX];
    long len;
    int ret;

    (void)argv;  /* TODO: Pass to new process */
    (void)envp;  /* TODO: Pass to new process */

    if (!path) {
        return -EFAULT;
    }

    /* Copy path from user space */
    len = strncpy_from_user(kpath, path, CONFIG_PATH_MAX);
    if (len < 0) return len;
    if (len >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
    kpath[len] = '\0';

    pr_debug("sys_exec: loading %s\n", kpath);

    /* Open the executable file */
    ret = vfs_open(kpath, O_RDONLY, 0, &file);
    if (ret < 0) {
        pr_err("sys_exec: failed to open %s: %d\n", kpath, ret);
        return ret;
    }

    vn = file->vnode;
    if (!vn || vn->type != VNODE_FILE) {
        vfs_close(file);
        return -EACCES;
    }

    /* Read entire file into memory */
    size_t size = vn->size;
    if (size == 0 || size > 16 * 1024 * 1024) {  /* Max 16MB executable */
        vfs_close(file);
        return -ENOEXEC;
    }

    void *elf_data = kmalloc(size);
    if (!elf_data) {
        vfs_close(file);
        return -ENOMEM;
    }

    /* Ensure we read from the beginning */
    vfs_seek(file, 0, SEEK_SET);

    ssize_t nread = vfs_read(file, elf_data, size);
    if (nread < 0) {
        kfree(elf_data);
        vfs_close(file);
        return nread;
    }

    if ((size_t)nread != size) {
        pr_err("sys_exec: incomplete read: %zd/%zu\n", nread, size);
        kfree(elf_data);
        vfs_close(file);
        return -EIO;
    }

    /* Close file (we have the data in memory now) */
    vfs_close(file);

    /* Load ELF binary into process */
    vaddr_t entry;
    ret = elf_load(p->mm, elf_data, size, &entry);
    kfree(elf_data);

    if (ret < 0) {
        pr_err("sys_exec: elf_load failed: %d\n", ret);
        /* Process is in invalid state, kill it */
        proc_exit(-1);
        return ret;  /* Never reached */
    }

    /* Update process context for new program */
    vaddr_t user_stack_top = 0x80000000UL;  /* User stack top */
    arch_context_init(p->context, entry, user_stack_top - 16, false);

    pr_info("sys_exec: loaded %s, entry=%p\n", path, (void *)entry);

    /* Return to user mode at new entry point */
    /* The arch_context_switch will restore context with new pc/sp */
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

/*
 * Syscall wrapper macros - generate wrapper functions for syscall table
 * Each wrapper casts arguments from uint64_t to proper types and calls
 * the actual syscall implementation.
 */
#define SYSCALL_WRAP0(name) \
    static int64_t sys_##name##_wrapper(uint64_t a0, uint64_t a1, uint64_t a2, \
                                        uint64_t a3, uint64_t a4, uint64_t a5) \
    { \
        (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; \
        return sys_##name(); \
    }

#define SYSCALL_WRAP1(name, t0) \
    static int64_t sys_##name##_wrapper(uint64_t a0, uint64_t a1, uint64_t a2, \
                                        uint64_t a3, uint64_t a4, uint64_t a5) \
    { \
        (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; \
        return sys_##name((t0)a0); \
    }

#define SYSCALL_WRAP2(name, t0, t1) \
    static int64_t sys_##name##_wrapper(uint64_t a0, uint64_t a1, uint64_t a2, \
                                        uint64_t a3, uint64_t a4, uint64_t a5) \
    { \
        (void)a2; (void)a3; (void)a4; (void)a5; \
        return sys_##name((t0)a0, (t1)a1); \
    }

#define SYSCALL_WRAP3(name, t0, t1, t2) \
    static int64_t sys_##name##_wrapper(uint64_t a0, uint64_t a1, uint64_t a2, \
                                        uint64_t a3, uint64_t a4, uint64_t a5) \
    { \
        (void)a3; (void)a4; (void)a5; \
        return sys_##name((t0)a0, (t1)a1, (t2)a2); \
    }

/* Generate wrapper functions using the macros */
SYSCALL_WRAP0(getpid)
SYSCALL_WRAP0(getppid)
SYSCALL_WRAP0(yield)
SYSCALL_WRAP0(fork)

SYSCALL_WRAP1(close, int)
SYSCALL_WRAP1(dup, int)
SYSCALL_WRAP1(rmdir, const char *)
SYSCALL_WRAP1(unlink, const char *)
SYSCALL_WRAP1(chdir, const char *)
SYSCALL_WRAP1(uname, struct utsname *)

SYSCALL_WRAP2(stat, const char *, struct stat *)
SYSCALL_WRAP2(fstat, int, struct stat *)
SYSCALL_WRAP2(dup2, int, int)
SYSCALL_WRAP2(mkdir, const char *, mode_t)
SYSCALL_WRAP2(getcwd, char *, size_t)

SYSCALL_WRAP3(open, const char *, int, mode_t)
SYSCALL_WRAP3(read, int, void *, size_t)
SYSCALL_WRAP3(write, int, const void *, size_t)
SYSCALL_WRAP3(lseek, int, off_t, int)
SYSCALL_WRAP3(wait, pid_t, int *, int)
SYSCALL_WRAP3(exec, const char *, char *const *, char *const *)

/* sys_exit is special - noreturn */
static int64_t sys_exit_wrapper(uint64_t a0, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    sys_exit((int)a0);
    return 0;  /* Never reached */
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

    /* File I/O syscalls */
    syscall_table[SYS_open] = sys_open_wrapper;
    syscall_table[SYS_close] = sys_close_wrapper;
    syscall_table[SYS_read] = sys_read_wrapper;
    syscall_table[SYS_write] = sys_write_wrapper;
    syscall_table[SYS_lseek] = sys_lseek_wrapper;
    syscall_table[SYS_stat] = sys_stat_wrapper;
    syscall_table[SYS_fstat] = sys_fstat_wrapper;
    syscall_table[SYS_dup] = sys_dup_wrapper;
    syscall_table[SYS_dup2] = sys_dup2_wrapper;
    syscall_table[SYS_unlink] = sys_unlink_wrapper;

    /* Directory syscalls */
    syscall_table[SYS_mkdir] = sys_mkdir_wrapper;
    syscall_table[SYS_rmdir] = sys_rmdir_wrapper;
    syscall_table[SYS_chdir] = sys_chdir_wrapper;
    syscall_table[SYS_getcwd] = sys_getcwd_wrapper;

    /* Misc */
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
