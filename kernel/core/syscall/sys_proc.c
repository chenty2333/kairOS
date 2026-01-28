/**
 * kernel/core/syscall/sys_proc.c - Process-related syscalls
 */

#include <kairos/config.h>
#include <kairos/process.h>
#include <kairos/signal.h>
#include <kairos/string.h>
#include <kairos/uaccess.h>

int64_t sys_exit(uint64_t status, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    proc_exit((int)status);
}

int64_t sys_fork(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_fork();
    return p ? (int64_t)p->pid : -ENOMEM;
}

int64_t sys_exec(uint64_t path, uint64_t argv, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0) {
        return -EFAULT;
    }
    return (int64_t)proc_exec(kpath, (char *const *)argv, NULL);
}

int64_t sys_execve(uint64_t path, uint64_t argv, uint64_t envp, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0) {
        return -EFAULT;
    }
    return (int64_t)proc_exec(kpath, (char *const *)argv, (char *const *)envp);
}

int64_t sys_getpid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)proc_current()->pid;
}

int64_t sys_gettid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    return (int64_t)(p ? p->pid : 0);
}

int64_t sys_set_tid_address(uint64_t tidptr, uint64_t a1, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    p->tid_address = tidptr;
    return (int64_t)p->pid;
}

int64_t sys_tgkill(uint64_t tgid, uint64_t tid, uint64_t sig, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if ((int64_t)tgid <= 0 || (int64_t)tid <= 0)
        return -EINVAL;
    if (tgid != tid)
        return -ESRCH;
    return (int64_t)signal_send((pid_t)tid, (int)sig);
}

int64_t sys_getppid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    return (int64_t)(p ? p->ppid : 0);
}

int64_t sys_getuid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    return (int64_t)(p ? p->uid : 0);
}

int64_t sys_getgid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    return (int64_t)(p ? p->gid : 0);
}

int64_t sys_setuid(uint64_t uid, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    p->uid = (uid_t)uid;
    return 0;
}

int64_t sys_setgid(uint64_t gid, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    p->gid = (gid_t)gid;
    return 0;
}

int64_t sys_wait(uint64_t pid, uint64_t status_ptr, uint64_t options,
                 uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int status = 0;
    pid_t ret = proc_wait((pid_t)pid, &status, (int)options);
    if (ret >= 0 && status_ptr) {
        if (copy_to_user((void *)status_ptr, &status, sizeof(status)) < 0)
            return -EFAULT;
    }
    return (int64_t)ret;
}

int64_t sys_wait4(uint64_t pid, uint64_t status_ptr, uint64_t options,
                  uint64_t rusage_ptr, uint64_t a4, uint64_t a5) {
    (void)rusage_ptr; (void)a4; (void)a5;
    return sys_wait(pid, status_ptr, options, 0, 0, 0);
}

int64_t sys_clone(uint64_t flags, uint64_t newsp, uint64_t parent_tid,
                  uint64_t child_tid, uint64_t tls, uint64_t a5) {
    (void)a5;

    /* Linux clone flag subset */
    enum {
        CLONE_VM             = 0x00000100,
        CLONE_VFORK          = 0x00004000,
        CLONE_SETTLS         = 0x00080000,
        CLONE_PARENT_SETTID  = 0x00100000,
        CLONE_CHILD_CLEARTID = 0x00200000,
        CLONE_CHILD_SETTID   = 0x01000000,
    };

    uint64_t kflags = flags & ~0xFFULL;
    uint64_t supported = CLONE_VM | CLONE_VFORK | CLONE_SETTLS |
                         CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID |
                         CLONE_CHILD_SETTID;

    if (kflags & ~supported)
        return -ENOSYS;
    if ((flags & CLONE_VM) && !(flags & CLONE_VFORK))
        return -ENOSYS;
    if (newsp) {
        if (!access_ok((void *)(newsp - 1), 1))
            return -EFAULT;
    }
    if (tls && !(flags & CLONE_SETTLS))
        return -EINVAL;

    struct proc_fork_opts opts = {0};
    if (newsp)
        opts.child_stack = newsp;
    if ((flags & CLONE_CHILD_SETTID) || (flags & CLONE_CHILD_CLEARTID)) {
        if (!child_tid)
            return -EINVAL;
        if (!access_ok((void *)child_tid, sizeof(pid_t)))
            return -EFAULT;
        if (flags & CLONE_CHILD_SETTID)
            opts.tid_set_address = child_tid;
        if (flags & CLONE_CHILD_CLEARTID)
            opts.tid_clear_address = child_tid;
    }
    if (flags & CLONE_VFORK)
        opts.vfork_parent = proc_current();

    struct process *p = proc_fork_ex(&opts);
    if (!p)
        return -ENOMEM;

    if (flags & CLONE_PARENT_SETTID) {
        if (!parent_tid)
            return -EINVAL;
        if (!access_ok((void *)parent_tid, sizeof(pid_t)))
            return -EFAULT;
        if (copy_to_user((void *)parent_tid, &p->pid, sizeof(p->pid)) < 0)
            return -EFAULT;
    }

    if (flags & CLONE_VFORK) {
        while (!__atomic_load_n(&p->vfork_done, __ATOMIC_ACQUIRE))
            proc_sleep(p);
    }

    return (int64_t)p->pid;
}

int64_t sys_exit_group(uint64_t status, uint64_t a1, uint64_t a2,
                       uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_exit(status, 0, 0, 0, 0, 0);
}

int64_t sys_prlimit64(uint64_t pid, uint64_t resource, uint64_t new_ptr,
                      uint64_t old_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (pid != 0 && (pid_t)pid != p->pid) {
        struct process *target = proc_find((pid_t)pid);
        if (!target)
            return -ESRCH;
        return -EPERM;
    }
    if (resource >= RLIM_NLIMITS)
        return -EINVAL;

    if (old_ptr) {
        struct rlimit old = p->rlimits[resource];
        if (copy_to_user((void *)old_ptr, &old, sizeof(old)) < 0)
            return -EFAULT;
    }

    if (new_ptr) {
        if (resource != RLIMIT_NOFILE && resource != RLIMIT_STACK)
            return -EINVAL;
        struct rlimit rl;
        if (copy_from_user(&rl, (void *)new_ptr, sizeof(rl)) < 0)
            return -EFAULT;
        if (rl.rlim_cur > rl.rlim_max)
            return -EINVAL;
        if (resource == RLIMIT_NOFILE &&
            (rl.rlim_cur > CONFIG_MAX_FILES_PER_PROC ||
             rl.rlim_max > CONFIG_MAX_FILES_PER_PROC))
            return -EINVAL;
        p->rlimits[resource] = rl;
    }

    return 0;
}
