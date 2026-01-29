/**
 * kernel/core/syscall/sys_proc.c - Process-related syscalls
 */

#include <kairos/config.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>

int64_t sys_prlimit64(uint64_t pid, uint64_t resource, uint64_t new_ptr,
                      uint64_t old_ptr, uint64_t a4, uint64_t a5);

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

int64_t sys_tkill(uint64_t tid, uint64_t sig, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if ((int64_t)tid <= 0)
        return -EINVAL;
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

int64_t sys_geteuid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    return sys_getuid(a0, a1, a2, a3, a4, a5);
}

int64_t sys_getegid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    return sys_getgid(a0, a1, a2, a3, a4, a5);
}

int64_t sys_getgroups(uint64_t size, uint64_t list_ptr, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if ((int64_t)size < 0)
        return -EINVAL;
    if (size == 0)
        return 0;
    if (!list_ptr)
        return -EFAULT;
    /* No supplementary groups supported yet. */
    return 0;
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

int64_t sys_setreuid(uint64_t ruid, uint64_t euid, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (ruid != (uint64_t)-1)
        p->uid = (uid_t)ruid;
    if (euid != (uint64_t)-1)
        p->uid = (uid_t)euid;
    return 0;
}

int64_t sys_setregid(uint64_t rgid, uint64_t egid, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (rgid != (uint64_t)-1)
        p->gid = (gid_t)rgid;
    if (egid != (uint64_t)-1)
        p->gid = (gid_t)egid;
    return 0;
}

int64_t sys_setresuid(uint64_t ruid, uint64_t euid, uint64_t suid, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (ruid != (uint64_t)-1)
        p->uid = (uid_t)ruid;
    if (euid != (uint64_t)-1)
        p->uid = (uid_t)euid;
    if (suid != (uint64_t)-1)
        p->uid = (uid_t)suid;
    return 0;
}

int64_t sys_setresgid(uint64_t rgid, uint64_t egid, uint64_t sgid, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (rgid != (uint64_t)-1)
        p->gid = (gid_t)rgid;
    if (egid != (uint64_t)-1)
        p->gid = (gid_t)egid;
    if (sgid != (uint64_t)-1)
        p->gid = (gid_t)sgid;
    return 0;
}

int64_t sys_getresuid(uint64_t ruid_ptr, uint64_t euid_ptr, uint64_t suid_ptr,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    uid_t uid = p->uid;
    if (ruid_ptr &&
        copy_to_user((void *)ruid_ptr, &uid, sizeof(uid)) < 0)
        return -EFAULT;
    if (euid_ptr &&
        copy_to_user((void *)euid_ptr, &uid, sizeof(uid)) < 0)
        return -EFAULT;
    if (suid_ptr &&
        copy_to_user((void *)suid_ptr, &uid, sizeof(uid)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_getresgid(uint64_t rgid_ptr, uint64_t egid_ptr, uint64_t sgid_ptr,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    gid_t gid = p->gid;
    if (rgid_ptr &&
        copy_to_user((void *)rgid_ptr, &gid, sizeof(gid)) < 0)
        return -EFAULT;
    if (egid_ptr &&
        copy_to_user((void *)egid_ptr, &gid, sizeof(gid)) < 0)
        return -EFAULT;
    if (sgid_ptr &&
        copy_to_user((void *)sgid_ptr, &gid, sizeof(gid)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_getpriority(uint64_t which, uint64_t who, uint64_t a2, uint64_t a3,
                        uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (which != PRIO_PROCESS)
        return -EINVAL;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (who != 0) {
        p = proc_find((pid_t)who);
        if (!p)
            return -ESRCH;
    }
    return (int64_t)sched_getnice(p);
}

int64_t sys_setpriority(uint64_t which, uint64_t who, uint64_t prio,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (which != PRIO_PROCESS)
        return -EINVAL;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (who != 0) {
        p = proc_find((pid_t)who);
        if (!p)
            return -ESRCH;
    }
    return (int64_t)sched_setnice(p, (int)prio);
}

int64_t sys_sched_getaffinity(uint64_t pid, uint64_t len, uint64_t mask_ptr,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (!mask_ptr)
        return -EFAULT;
    if (len < sizeof(unsigned long))
        return -EINVAL;
    if (pid != 0) {
        struct process *target = proc_find((pid_t)pid);
        if (!target)
            return -ESRCH;
    }

    unsigned long mask = 0;
    int cpus = sched_cpu_count();
    int max_bits = (int)(sizeof(mask) * 8);
    for (int i = 0; i < cpus && i < max_bits; i++)
        mask |= (1UL << i);

    if (copy_to_user((void *)mask_ptr, &mask, sizeof(mask)) < 0)
        return -EFAULT;
    return (int64_t)sizeof(mask);
}

int64_t sys_getrlimit(uint64_t resource, uint64_t rlim_ptr, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_prlimit64(0, resource, 0, rlim_ptr, 0, 0);
}

int64_t sys_setrlimit(uint64_t resource, uint64_t rlim_ptr, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_prlimit64(0, resource, rlim_ptr, 0, 0, 0);
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

int64_t sys_waitid(uint64_t type, uint64_t id, uint64_t info_ptr,
                   uint64_t options, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    enum { P_ALL = 0, P_PID = 1, P_PGID = 2 };
    if (options & ~(WNOHANG | WEXITED))
        return -EINVAL;
    pid_t pid = -1;
    if (type == P_PID) {
        pid = (pid_t)id;
    } else if (type == P_ALL) {
        pid = -1;
    } else {
        return -EINVAL;
    }

    int status = 0;
    pid_t ret = proc_wait(pid, &status, (int)options);
    if (ret == 0 && (options & WNOHANG)) {
        if (info_ptr) {
            siginfo_t info = {0};
            if (copy_to_user((void *)info_ptr, &info, sizeof(info)) < 0)
                return -EFAULT;
        }
        return 0;
    }
    if (ret < 0)
        return ret;

    if (info_ptr) {
        siginfo_t info;
        memset(&info, 0, sizeof(info));
        info.si_signo = SIGCHLD;
        info.si_code = CLD_EXITED;
        info.si_pid = ret;
        info.si_status = status >> 8;
        if (copy_to_user((void *)info_ptr, &info, sizeof(info)) < 0)
            return -EFAULT;
    }
    return 0;
}

int64_t sys_clone(uint64_t flags, uint64_t newsp, uint64_t parent_tid,
                  uint64_t child_tid, uint64_t tls, uint64_t a5) {
    (void)a5;
    (void)tls;

    /* Linux clone flag subset */
    enum {
        CLONE_VM             = 0x00000100,
        CLONE_VFORK          = 0x00004000,
        CLONE_PARENT_SETTID  = 0x00100000,
        CLONE_CHILD_CLEARTID = 0x00200000,
        CLONE_CHILD_SETTID   = 0x01000000,
    };

    uint64_t kflags = flags & ~0xFFULL;
    uint64_t supported = CLONE_VM | CLONE_VFORK | CLONE_PARENT_SETTID |
                         CLONE_CHILD_CLEARTID |
                         CLONE_CHILD_SETTID;

    if (kflags & ~supported)
        return -ENOSYS;
    if ((flags & CLONE_VM) && !(flags & CLONE_VFORK))
        return -ENOSYS;
    if (newsp) {
        if (!access_ok((void *)(newsp - 1), 1))
            return -EFAULT;
    }

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
        while (!__atomic_load_n(&p->vfork_done, __ATOMIC_ACQUIRE)) {
            int rc = proc_sleep_on(&p->vfork_wait, p, true);
            if (rc == -EINTR &&
                __atomic_load_n(&p->vfork_done, __ATOMIC_ACQUIRE)) {
                break;
            }
        }
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

int64_t sys_execveat(uint64_t dirfd, uint64_t path, uint64_t argv,
                     uint64_t envp, uint64_t flags, uint64_t a5) {
    (void)a5;
    if (flags != 0 || (int64_t)dirfd != AT_FDCWD)
        return -ENOSYS;
    return sys_execve(path, argv, envp, 0, 0, 0);
}

int64_t sys_set_robust_list(uint64_t head_ptr, uint64_t len, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (len != 3 * sizeof(uint64_t))
        return -EINVAL;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    p->robust_list = head_ptr;
    p->robust_len = len;
    return 0;
}

int64_t sys_get_robust_list(uint64_t pid, uint64_t head_ptr, uint64_t len_ptr,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (pid != 0 && (pid_t)pid != p->pid)
        return -EPERM;
    if (head_ptr &&
        copy_to_user((void *)head_ptr, &p->robust_list,
                     sizeof(p->robust_list)) < 0)
        return -EFAULT;
    if (len_ptr &&
        copy_to_user((void *)len_ptr, &p->robust_len,
                     sizeof(p->robust_len)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_sched_setparam(uint64_t pid, uint64_t param_ptr, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (pid != 0 && (pid_t)pid != p->pid)
        return -ESRCH;
    if (!param_ptr)
        return -EFAULT;
    struct sched_param param;
    if (copy_from_user(&param, (void *)param_ptr, sizeof(param)) < 0)
        return -EFAULT;
    if (param.sched_priority != 0)
        return -EINVAL;
    return 0;
}

int64_t sys_sched_setscheduler(uint64_t pid, uint64_t policy, uint64_t param_ptr,
                               uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (policy != SCHED_OTHER)
        return -EINVAL;
    return sys_sched_setparam(pid, param_ptr, 0, 0, 0, 0);
}

int64_t sys_sched_getscheduler(uint64_t pid, uint64_t a1, uint64_t a2,
                               uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (pid != 0 && !proc_find((pid_t)pid))
        return -ESRCH;
    return SCHED_OTHER;
}

int64_t sys_sched_getparam(uint64_t pid, uint64_t param_ptr, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (pid != 0 && !proc_find((pid_t)pid))
        return -ESRCH;
    if (!param_ptr)
        return -EFAULT;
    struct sched_param param = {.sched_priority = 0};
    if (copy_to_user((void *)param_ptr, &param, sizeof(param)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_sched_yield(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                        uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    proc_yield();
    return 0;
}

int64_t sys_setpgid(uint64_t pid, uint64_t pgid, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (pid != 0 && (pid_t)pid != p->pid)
        return -EPERM;
    pid_t new_pgid = (pgid == 0) ? p->pid : (pid_t)pgid;
    p->pgid = new_pgid;
    return 0;
}

int64_t sys_getpgid(uint64_t pid, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (pid != 0) {
        p = proc_find((pid_t)pid);
        if (!p)
            return -ESRCH;
    }
    return (int64_t)p->pgid;
}

int64_t sys_getsid(uint64_t pid, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (pid != 0) {
        p = proc_find((pid_t)pid);
        if (!p)
            return -ESRCH;
    }
    return (int64_t)p->sid;
}

int64_t sys_setsid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    p->sid = p->pid;
    p->pgid = p->pid;
    return (int64_t)p->sid;
}

int64_t sys_acct(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return -ENOSYS;
}
