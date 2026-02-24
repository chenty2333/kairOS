/**
 * kernel/core/syscall/sys_proc.c - Process-related syscalls
 */

#include <kairos/clone.h>
#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/namei.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/tty.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#include "sys_fs_helpers.h"

static inline int64_t sysproc_abi_fd(uint64_t v) {
    return (int64_t)(int32_t)(uint32_t)v;
}

static inline int32_t sysproc_abi_i32(uint64_t v) {
    return (int32_t)(uint32_t)v;
}

static inline uint32_t sysproc_abi_u32(uint64_t v) {
    return (uint32_t)v;
}

static inline pid_t sysproc_abi_pid(uint64_t v) {
    return (pid_t)sysproc_abi_i32(v);
}

static inline int sysproc_copy_path_from_user(char *kpath, size_t kpath_len,
                                              uint64_t upath) {
    if (!upath || !kpath || kpath_len == 0)
        return -EFAULT;
    long len = strncpy_from_user(kpath, (const char *)upath, kpath_len);
    if (len < 0)
        return -EFAULT;
    if ((size_t)len >= kpath_len)
        return -ENAMETOOLONG;
    kpath[kpath_len - 1] = '\0';
    return 0;
}

int64_t sys_prlimit64(uint64_t pid, uint64_t resource, uint64_t new_ptr,
                      uint64_t old_ptr, uint64_t a4, uint64_t a5);

int64_t sys_exit(uint64_t status, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    proc_exit(sysproc_abi_i32(status));
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
    int ret = sysproc_copy_path_from_user(kpath, sizeof(kpath), path);
    if (ret < 0)
        return ret;
    return (int64_t)proc_exec(kpath, (char *const *)argv, NULL);
}

int64_t sys_execve(uint64_t path, uint64_t argv, uint64_t envp, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    int ret = sysproc_copy_path_from_user(kpath, sizeof(kpath), path);
    if (ret < 0)
        return ret;
    return (int64_t)proc_exec(kpath, (char *const *)argv, (char *const *)envp);
}

int64_t sys_getpid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)proc_current()->tgid;
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
    pid_t ktgid = sysproc_abi_pid(tgid);
    pid_t ktid = sysproc_abi_pid(tid);
    int32_t ksig = sysproc_abi_i32(sig);
    if (ktgid <= 0 || ktid <= 0)
        return -EINVAL;
    struct process *target = proc_find(ktid);
    if (!target || target->tgid != ktgid)
        return -ESRCH;
    return (int64_t)signal_send(ktid, ksig);
}

int64_t sys_tkill(uint64_t tid, uint64_t sig, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    pid_t ktid = sysproc_abi_pid(tid);
    int32_t ksig = sysproc_abi_i32(sig);
    if (ktid <= 0)
        return -EINVAL;
    return (int64_t)signal_send(ktid, ksig);
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
    p->uid = (uid_t)sysproc_abi_u32(uid);
    return 0;
}

int64_t sys_setgid(uint64_t gid, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    p->gid = (gid_t)sysproc_abi_u32(gid);
    return 0;
}

int64_t sys_setreuid(uint64_t ruid, uint64_t euid, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    uint32_t kruid = sysproc_abi_u32(ruid);
    uint32_t keuid = sysproc_abi_u32(euid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kruid != UINT32_MAX)
        p->uid = (uid_t)kruid;
    if (keuid != UINT32_MAX)
        p->uid = (uid_t)keuid;
    return 0;
}

int64_t sys_setregid(uint64_t rgid, uint64_t egid, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    uint32_t krgid = sysproc_abi_u32(rgid);
    uint32_t kegid = sysproc_abi_u32(egid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (krgid != UINT32_MAX)
        p->gid = (gid_t)krgid;
    if (kegid != UINT32_MAX)
        p->gid = (gid_t)kegid;
    return 0;
}

int64_t sys_setresuid(uint64_t ruid, uint64_t euid, uint64_t suid, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    uint32_t kruid = sysproc_abi_u32(ruid);
    uint32_t keuid = sysproc_abi_u32(euid);
    uint32_t ksuid = sysproc_abi_u32(suid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kruid != UINT32_MAX)
        p->uid = (uid_t)kruid;
    if (keuid != UINT32_MAX)
        p->uid = (uid_t)keuid;
    if (ksuid != UINT32_MAX)
        p->uid = (uid_t)ksuid;
    return 0;
}

int64_t sys_setresgid(uint64_t rgid, uint64_t egid, uint64_t sgid, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    uint32_t krgid = sysproc_abi_u32(rgid);
    uint32_t kegid = sysproc_abi_u32(egid);
    uint32_t ksgid = sysproc_abi_u32(sgid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (krgid != UINT32_MAX)
        p->gid = (gid_t)krgid;
    if (kegid != UINT32_MAX)
        p->gid = (gid_t)kegid;
    if (ksgid != UINT32_MAX)
        p->gid = (gid_t)ksgid;
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
    int32_t kwhich = sysproc_abi_i32(which);
    pid_t kwho = sysproc_abi_pid(who);
    if (kwhich != PRIO_PROCESS)
        return -EINVAL;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kwho != 0) {
        p = proc_find(kwho);
        if (!p)
            return -ESRCH;
    }
    return (int64_t)sched_getnice(p);
}

int64_t sys_setpriority(uint64_t which, uint64_t who, uint64_t prio,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int32_t kwhich = sysproc_abi_i32(which);
    pid_t kwho = sysproc_abi_pid(who);
    int32_t kprio = sysproc_abi_i32(prio);
    if (kwhich != PRIO_PROCESS)
        return -EINVAL;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kwho != 0) {
        p = proc_find(kwho);
        if (!p)
            return -ESRCH;
    }
    return (int64_t)sched_setnice(p, kprio);
}

int64_t sys_sched_getaffinity(uint64_t pid, uint64_t len, uint64_t mask_ptr,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    pid_t kpid = sysproc_abi_pid(pid);
    if (!mask_ptr)
        return -EFAULT;
    if (len < sizeof(unsigned long))
        return -EINVAL;
    struct process *target = NULL;
    if (kpid == 0)
        target = proc_current();
    else
        target = proc_find(kpid);
    if (!target)
        return -ESRCH;

    unsigned long online_mask = 0;
    int cpus = sched_cpu_count();
    int max_bits = (int)(sizeof(unsigned long) * 8);
    for (int i = 0; i < cpus && i < max_bits; i++)
        online_mask |= (1UL << i);

    unsigned long mask = (unsigned long)proc_sched_get_affinity_mask(target);
    mask &= online_mask;
    if (!mask)
        mask = online_mask;

    if (copy_to_user((void *)mask_ptr, &mask, sizeof(mask)) < 0)
        return -EFAULT;
    return (int64_t)sizeof(mask);
}

int64_t sys_sched_setaffinity(uint64_t pid, uint64_t len, uint64_t mask_ptr,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    pid_t kpid = sysproc_abi_pid(pid);
    if (!mask_ptr)
        return -EFAULT;
    if (len < sizeof(unsigned long))
        return -EINVAL;

    struct process *curr = proc_current();
    if (!curr)
        return -EINVAL;

    struct process *target = NULL;
    if (kpid == 0)
        target = curr;
    else
        target = proc_find(kpid);
    if (!target)
        return -ESRCH;
    if (target != curr && curr->uid != 0)
        return -EPERM;

    unsigned long requested = 0;
    if (copy_from_user(&requested, (const void *)mask_ptr, sizeof(requested)) < 0)
        return -EFAULT;
    return (int64_t)sched_set_affinity(target, (uint64_t)requested);
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
    uint32_t uoptions = (uint32_t)options;
    pid_t kpid = sysproc_abi_pid(pid);
    int status = 0;
    pid_t ret = proc_wait(kpid, &status, (int)uoptions);
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
    int32_t ktype = sysproc_abi_i32(type);
    uint32_t uoptions = (uint32_t)options;
    if (uoptions & ~(WNOHANG | WEXITED))
        return -EINVAL;
    pid_t pid = -1;
    if (ktype == P_PID) {
        pid = sysproc_abi_pid(id);
    } else if (ktype == P_ALL) {
        pid = -1;
    } else {
        return -EINVAL;
    }

    int status = 0;
    pid_t ret = proc_wait(pid, &status, (int)uoptions);
    if (ret == 0 && (uoptions & WNOHANG)) {
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
                  uint64_t arg3, uint64_t arg4, uint64_t a5) {
    (void)a5;

#if defined(ARCH_aarch64) || defined(ARCH_riscv64)
    uint64_t tls = arg3;
    uint64_t child_tid = arg4;
#else
    uint64_t child_tid = arg3;
    uint64_t tls = arg4;
#endif

    uint64_t kflags = flags & ~0xFFULL;
    uint64_t supported = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                         CLONE_SYSVSEM | CLONE_VFORK | CLONE_THREAD | CLONE_SETTLS |
                         CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID |
                         CLONE_CHILD_SETTID;

    if (kflags & ~supported)
        return -ENOSYS;
    /* CLONE_THREAD requires CLONE_SIGHAND which requires CLONE_VM */
    if ((flags & CLONE_THREAD) && !(flags & CLONE_SIGHAND))
        return -EINVAL;
    if ((flags & CLONE_SIGHAND) && !(flags & CLONE_VM))
        return -EINVAL;
    if (newsp) {
        if (!access_ok((void *)(newsp - 1), 1))
            return -EFAULT;
    }

    struct proc_fork_opts opts = {0};
    opts.clone_flags = kflags;
    if (newsp)
        opts.child_stack = newsp;
    if (flags & CLONE_SETTLS)
        opts.tls = tls;
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
        wait_for_completion(&p->vfork_completion);
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
    pid_t kpid = sysproc_abi_pid(pid);
    uint32_t kresource = sysproc_abi_u32(resource);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kpid != 0 && kpid != p->pid) {
        struct process *target = proc_find(kpid);
        if (!target)
            return -ESRCH;
        return -EPERM;
    }
    if (kresource >= RLIM_NLIMITS)
        return -EINVAL;

    if (old_ptr) {
        struct rlimit old = p->rlimits[kresource];
        if (copy_to_user((void *)old_ptr, &old, sizeof(old)) < 0)
            return -EFAULT;
    }

    if (new_ptr) {
        if (kresource != RLIMIT_NOFILE && kresource != RLIMIT_STACK)
            return -EINVAL;
        struct rlimit rl;
        if (copy_from_user(&rl, (void *)new_ptr, sizeof(rl)) < 0)
            return -EFAULT;
        if (rl.rlim_cur > rl.rlim_max)
            return -EINVAL;
        if (kresource == RLIMIT_NOFILE &&
            (rl.rlim_cur > CONFIG_MAX_FILES_PER_PROC ||
             rl.rlim_max > CONFIG_MAX_FILES_PER_PROC))
            return -EINVAL;
        p->rlimits[kresource] = rl;
    }

    return 0;
}

int64_t sys_execveat(uint64_t dirfd, uint64_t path, uint64_t argv,
                     uint64_t envp, uint64_t flags, uint64_t a5) {
    (void)a5;
    int64_t kdirfd = sysproc_abi_fd(dirfd);
    uint32_t uflags = (uint32_t)flags;
    uint32_t supported_flags = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;
    int exec_namei_flags = NAMEI_FOLLOW;
    if (uflags & ~supported_flags)
        return -EINVAL;
    if (uflags & AT_SYMLINK_NOFOLLOW)
        exec_namei_flags = NAMEI_NOFOLLOW;

    char kpath[CONFIG_PATH_MAX];

    if (uflags & AT_EMPTY_PATH) {
        /* Execute the file referred to by dirfd directly */
        struct file *f = fd_get(proc_current(), (int)kdirfd);
        if (!f)
            return -EBADF;
        strncpy(kpath, f->path, sizeof(kpath) - 1);
        kpath[sizeof(kpath) - 1] = '\0';
        file_put(f);
    } else {
        int ret = sysproc_copy_path_from_user(kpath, sizeof(kpath), path);
        if (ret < 0)
            return ret;

        /* Resolve relative to dirfd if not absolute and not AT_FDCWD */
        if (kpath[0] != '/' && kdirfd != AT_FDCWD) {
            struct file *df = fd_get(proc_current(), (int)kdirfd);
            if (!df)
                return -EBADF;
            /* Build full path from dirfd path + relative path */
            char full[CONFIG_PATH_MAX];
            int dlen = (int)strlen(df->path);
            int written;
            if (dlen > 0 && df->path[dlen - 1] == '/') {
                written = snprintf(full, sizeof(full), "%s%s", df->path, kpath);
            } else {
                written = snprintf(full, sizeof(full), "%s/%s", df->path, kpath);
            }
            file_put(df);
            if (written < 0)
                return -EINVAL;
            if ((size_t)written >= sizeof(full))
                return -ENAMETOOLONG;
            strncpy(kpath, full, sizeof(kpath) - 1);
            kpath[sizeof(kpath) - 1] = '\0';
        }
    }

    return (int64_t)proc_exec_resolve(kpath, (char *const *)argv,
                                      (char *const *)envp, exec_namei_flags);
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
    pid_t kpid = sysproc_abi_pid(pid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kpid != 0 && kpid != p->pid)
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
    pid_t kpid = sysproc_abi_pid(pid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kpid != 0 && kpid != p->pid)
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
    if (sysproc_abi_i32(policy) != SCHED_OTHER)
        return -EINVAL;
    return sys_sched_setparam(pid, param_ptr, 0, 0, 0, 0);
}

int64_t sys_sched_getscheduler(uint64_t pid, uint64_t a1, uint64_t a2,
                               uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    pid_t kpid = sysproc_abi_pid(pid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kpid != 0 && !proc_find(kpid))
        return -ESRCH;
    return SCHED_OTHER;
}

int64_t sys_sched_getparam(uint64_t pid, uint64_t param_ptr, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    pid_t kpid = sysproc_abi_pid(pid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kpid != 0 && !proc_find(kpid))
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
    pid_t kpid = sysproc_abi_pid(pid);
    pid_t kpgid = sysproc_abi_pid(pgid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kpid != 0 && kpid != p->pid)
        return -EPERM;
    pid_t new_pgid = (kpgid == 0) ? p->pid : kpgid;
    p->pgid = new_pgid;
    return 0;
}

int64_t sys_getpgid(uint64_t pid, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    pid_t kpid = sysproc_abi_pid(pid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kpid != 0) {
        p = proc_find(kpid);
        if (!p)
            return -ESRCH;
    }
    return (int64_t)p->pgid;
}

int64_t sys_getsid(uint64_t pid, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    pid_t kpid = sysproc_abi_pid(pid);
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (kpid != 0) {
        p = proc_find(kpid);
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
    tty_detach_ctty(p);
    p->sid = p->pid;
    p->pgid = p->pid;
    return (int64_t)p->sid;
}

int64_t sys_acct(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (p->uid != 0)
        return -EPERM;

    if (!a0) {
        return 0;
    }

    char kpath[CONFIG_PATH_MAX];
    if (sysfs_copy_path(a0, kpath, sizeof(kpath)) < 0)
        return -EFAULT;

    struct path resolved;
    path_init(&resolved);
    int ret = sysfs_resolve_at(AT_FDCWD, kpath, &resolved, NAMEI_FOLLOW);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    if (resolved.dentry->vnode->type == VNODE_DIR) {
        dentry_put(resolved.dentry);
        return -EISDIR;
    }
    dentry_put(resolved.dentry);

    return 0;
}
