/**
 * kernel/core/syscall/syscall.c - Optimized System Call Dispatch
 */

#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sync.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>
#include <kairos/string.h>

/* Forward declarations for internal implementations */
extern int do_sem_init(int count);
extern int do_sem_wait(int sem_id);
extern int do_sem_post(int sem_id);

/* --- Process Handlers --- */

int64_t sys_exit(uint64_t status, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    proc_exit((int)status);
}

int64_t sys_fork(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_fork();
    return p ? (int64_t)p->pid : -1;
}

int64_t sys_exec(uint64_t path, uint64_t argv, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0) return -EFAULT;
    
    /* Simplified argv handling for now */
    return (int64_t)proc_exec(kpath, (char *const *)argv);
}

int64_t sys_getpid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)proc_current()->pid;
}

int64_t sys_wait(uint64_t pid, uint64_t status_ptr, uint64_t options, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int status = 0;
    pid_t ret = proc_wait((pid_t)pid, &status, (int)options);
    if (ret >= 0 && status_ptr) {
        if (copy_to_user((void *)status_ptr, &status, sizeof(status)) < 0) return -EFAULT;
    }
    return (int64_t)ret;
}

int64_t sys_brk(uint64_t addr, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)mm_brk(proc_current()->mm, (vaddr_t)addr);
}

/* --- File/IO Handlers --- */

int64_t sys_open(uint64_t path, uint64_t flags, uint64_t mode, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    struct file *f;
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0) return -EFAULT;
    
    int ret = vfs_open(kpath, (int)flags, (mode_t)mode, &f);
    if (ret < 0) return ret;
    
    int fd = fd_alloc(proc_current(), f);
    if (fd < 0) { vfs_close(f); return -EMFILE; }
    return fd;
}

static int64_t sys_read_write(uint64_t fd, uint64_t buf, uint64_t count, bool is_write) {
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f) return -EBADF;

    uint8_t kbuf[512]; 
    size_t chunk = (count > sizeof(kbuf)) ? sizeof(kbuf) : count;
    
    if (is_write) {
        if (copy_from_user(kbuf, (const void *)buf, chunk) < 0) return -EFAULT;
        return (int64_t)vfs_write(f, kbuf, chunk);
    } else {
        ssize_t n = vfs_read(f, kbuf, chunk);
        if (n > 0 && copy_to_user((void *)buf, kbuf, (size_t)n) < 0) return -EFAULT;
        return (int64_t)n;
    }
}

int64_t sys_read(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, false);
}

int64_t sys_write(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, true);
}

int64_t sys_close(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_close(proc_current(), (int)fd);
}

int64_t sys_pipe(uint64_t fd_array, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct file *rf, *wf;
    int fds[2], ret;
    extern int pipe_create(struct file **read_pipe, struct file **write_pipe);

    if ((ret = pipe_create(&rf, &wf)) < 0) return ret;
    if ((fds[0] = fd_alloc(proc_current(), rf)) < 0 || (fds[1] = fd_alloc(proc_current(), wf)) < 0) return -EMFILE;
    if (copy_to_user((void *)fd_array, fds, sizeof(fds)) < 0) return -EFAULT;
    return 0;
}

/* --- Semaphore Handlers (Matching syscall_fn_t) --- */

int64_t sys_sem_init(uint64_t count, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_init((int)count);
}

int64_t sys_sem_wait(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_wait((int)sem_id);
}

int64_t sys_sem_post(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_post((int)sem_id);
}

/* --- Table & Dispatch --- */

syscall_fn_t syscall_table[SYS_MAX] = {
    [SYS_exit]    = sys_exit,
    [SYS_fork]    = sys_fork,
    [SYS_exec]    = sys_exec,
    [SYS_getpid]  = sys_getpid,
    [SYS_wait]    = sys_wait,
    [SYS_brk]     = sys_brk,
    [SYS_open]    = sys_open,
    [SYS_read]    = sys_read,
    [SYS_write]   = sys_write,
    [SYS_close]   = sys_close,
    [SYS_pipe]    = sys_pipe,
    [SYS_sem_init] = sys_sem_init,
    [SYS_sem_wait] = sys_sem_wait,
    [SYS_sem_post] = sys_sem_post,
};

int64_t syscall_dispatch(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    if (num >= SYS_MAX || !syscall_table[num]) return -ENOSYS;
    return syscall_table[num](a0, a1, a2, a3, a4, a5);
}

void syscall_init(void) {
    pr_info("Syscall: initialized\n");
}