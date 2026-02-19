/**
 * kernel/core/proc/signal.c - Signal Handling Logic
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/pollwait.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>

#define NS_PER_SEC 1000000000ULL

/* sighand helpers */

struct sighand_struct *sighand_alloc(void) {
    struct sighand_struct *sh = kzalloc(sizeof(*sh));
    if (!sh)
        return NULL;
    spin_init(&sh->lock);
    atomic_init(&sh->refcount, 1);
    return sh;
}

struct sighand_struct *sighand_copy(struct sighand_struct *src) {
    struct sighand_struct *sh = kzalloc(sizeof(*sh));
    if (!sh)
        return NULL;
    spin_init(&sh->lock);
    atomic_init(&sh->refcount, 1);
    if (src) {
        spin_lock(&src->lock);
        memcpy(sh->actions, src->actions, sizeof(sh->actions));
        spin_unlock(&src->lock);
    }
    return sh;
}

void sighand_get(struct sighand_struct *sh) {
    if (sh)
        atomic_inc(&sh->refcount);
}

void sighand_put(struct sighand_struct *sh) {
    if (!sh)
        return;
    if (atomic_dec_return(&sh->refcount) == 0)
        kfree(sh);
}

void signal_init_process(struct process *p) {
    p->sighand = sighand_alloc();
    if (!p->sighand) {
        pr_warn("signal: sighand alloc failed for pid %d\n", p->pid);
    }
}

int signal_send(pid_t pid, int sig) {
    if (sig <= 0 || sig > NSIG) return -EINVAL;
    struct process *p = proc_find(pid);
    if (!p) return -ESRCH;

    __atomic_fetch_or(&p->sig_pending, (1ULL << (sig - 1)), __ATOMIC_RELEASE);
    /* Use process lock to synchronize with proc_sleep_on's state transition */
    proc_lock(p);
    if (p->state == PROC_SLEEPING) {
        proc_unlock(p);
        proc_wakeup(p);
    } else {
        proc_unlock(p);
    }
    return 0;
}

void signal_deliver_pending(void) {
    struct process *p = proc_current();
    struct trap_frame *tf = get_current_trapframe();
    if (!p || !p->mm || !p->sig_pending || !tf) return;

    uint64_t pending = __atomic_load_n(&p->sig_pending, __ATOMIC_ACQUIRE);
    for (int i = 0; i < NSIG; i++) {
        uint64_t mask = (1ULL << i);
        if (!(pending & mask)) continue;
        if (p->sig_blocked & mask) continue;

        int sig = i + 1;
        struct sigaction action = {0};
        if (p->sighand) {
            spin_lock(&p->sighand->lock);
            action = p->sighand->actions[i];
            spin_unlock(&p->sighand->lock);
        }
        void (*handler)(int) = action.sa_handler ? action.sa_handler : SIG_DFL;

        if (handler == SIG_IGN || (handler == SIG_DFL && sig == SIGCHLD)) {
            __atomic_fetch_and(&p->sig_pending, ~mask, __ATOMIC_RELEASE);
            pending &= ~mask;
            continue;
        }

        if (handler == SIG_DFL) {
            if (sig == SIGKILL || sig == SIGILL || sig == SIGSEGV || sig == SIGTERM) {
                pr_info("Process %d killed by signal %d\n", p->pid, sig);
                proc_exit(-sig);
            }
            __atomic_fetch_and(&p->sig_pending, ~mask, __ATOMIC_RELEASE);
            pending &= ~mask;
            continue;
        }

        /* User handler defined: Setup stack trampoline */
#if defined(ARCH_riscv64)
        uint64_t sp = tf->tf_sp;
        if ((action.sa_flags & SA_ONSTACK) &&
            !(p->sigaltstack.ss_flags & SS_DISABLE) &&
            p->sigaltstack.ss_sp && p->sigaltstack.ss_size) {
            sp = (uint64_t)p->sigaltstack.ss_sp + p->sigaltstack.ss_size;
            p->sigaltstack.ss_flags |= SS_ONSTACK;
        }
        sp -= sizeof(struct sigcontext);
        sp = ALIGN_DOWN(sp, 16);

        struct sigcontext sc;
        memcpy(sc.regs, tf->regs, sizeof(tf->regs));
        sc.sepc = tf->sepc;
        sc.sstatus = tf->sstatus;
        sc.sigmask = p->sig_blocked;
        
        /* Trampoline: li a7, 64 (SYS_sigreturn); ecall */
        /* RISC-V instructions: 0x04000893 (li a7, 64), 0x00000073 (ecall) */
        sc.trampoline[0] = 0x0000007304000893ULL; 

        if (copy_to_user((void *)sp, &sc, sizeof(sc)) < 0) {
            proc_exit(-SIGSEGV);
        }

        p->sig_blocked |= action.sa_mask | mask;

        /* Hijack execution */
        tf->tf_sp = sp;
        tf->sepc = (uint64_t)handler;
        tf->tf_ra = sp + __builtin_offsetof(struct sigcontext, trampoline);
        tf->tf_a0 = sig;

        __atomic_fetch_and(&p->sig_pending, ~mask, __ATOMIC_RELEASE);
        return; /* Deliver one signal at a time */
#elif defined(ARCH_x86_64)
        uint64_t sp = tf->tf_sp;
        if ((action.sa_flags & SA_ONSTACK) &&
            !(p->sigaltstack.ss_flags & SS_DISABLE) &&
            p->sigaltstack.ss_sp && p->sigaltstack.ss_size) {
            sp = (uint64_t)p->sigaltstack.ss_sp + p->sigaltstack.ss_size;
            p->sigaltstack.ss_flags |= SS_ONSTACK;
        }
        sp -= sizeof(struct sigcontext);
        sp = ALIGN_DOWN(sp, 16);

        struct sigcontext sc;
        sc.tf = *tf;
        sc.sigmask = p->sig_blocked;
        sc.trampoline[0] = 0xB8; /* mov eax, imm32 */
        *(uint32_t *)&sc.trampoline[1] = SYS_sigreturn;
        sc.trampoline[5] = 0xCD; /* int 0x80 */
        sc.trampoline[6] = 0x80;
        sc.trampoline[7] = 0x90;

        if (copy_to_user((void *)sp, &sc, sizeof(sc)) < 0) {
            proc_exit(-SIGSEGV);
        }

        p->sig_blocked |= action.sa_mask | mask;

        /* Push trampoline return address */
        uint64_t tramp = sp + __builtin_offsetof(struct sigcontext, trampoline);
        sp -= sizeof(uint64_t);
        if (copy_to_user((void *)sp, &tramp, sizeof(tramp)) < 0) {
            proc_exit(-SIGSEGV);
        }

        tf->tf_sp = sp;
        tf->sepc = (uint64_t)handler;
        tf->rdi = sig;

        __atomic_fetch_and(&p->sig_pending, ~mask, __ATOMIC_RELEASE);
        return;
#elif defined(ARCH_aarch64)
        uint64_t sp = tf->tf_sp;
        if ((action.sa_flags & SA_ONSTACK) &&
            !(p->sigaltstack.ss_flags & SS_DISABLE) &&
            p->sigaltstack.ss_sp && p->sigaltstack.ss_size) {
            sp = (uint64_t)p->sigaltstack.ss_sp + p->sigaltstack.ss_size;
            p->sigaltstack.ss_flags |= SS_ONSTACK;
        }
        sp -= sizeof(struct sigcontext);
        sp = ALIGN_DOWN(sp, 16);

        struct sigcontext sc;
        sc.tf = *tf;
        sc.sigmask = p->sig_blocked;
        sc.trampoline[0] = 0xd2800808; /* mov x8, #64 */
        sc.trampoline[1] = 0xd4000001; /* svc #0 */

        if (copy_to_user((void *)sp, &sc, sizeof(sc)) < 0) {
            proc_exit(-SIGSEGV);
        }

        p->sig_blocked |= action.sa_mask | mask;

        tf->tf_sp = sp;
        tf->sepc = (uint64_t)handler;
        tf->tf_a0 = sig;

        __atomic_fetch_and(&p->sig_pending, ~mask, __ATOMIC_RELEASE);
        return;
#else
        pr_warn("signal: user handlers unsupported on this arch\n");
        proc_exit(-sig);
        __atomic_fetch_and(&p->sig_pending, ~mask, __ATOMIC_RELEASE);
        return;
#endif
    }
}

int64_t sys_sigreturn(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;

#if defined(ARCH_riscv64)
    struct process *p = proc_current();
    struct trap_frame *tf = get_current_trapframe();
    if (!p || !tf) return -EINVAL;

    struct sigcontext sc;
    if (copy_from_user(&sc, (void *)tf->tf_sp, sizeof(sc)) < 0) return -EFAULT;

    memcpy(tf->regs, sc.regs, sizeof(sc.regs));
    tf->sepc = sc.sepc;
    tf->sstatus = (sc.sstatus & ~SSTATUS_SPP) | SSTATUS_SPIE;
    p->sig_blocked = sc.sigmask;
    if (p->sigaltstack.ss_flags & SS_ONSTACK)
        p->sigaltstack.ss_flags &= ~SS_ONSTACK;

    return (int64_t)sc.regs[9]; /* restore a0 */
#elif defined(ARCH_x86_64)
    struct process *p = proc_current();
    struct trap_frame *tf = get_current_trapframe();
    if (!p || !tf) return -EINVAL;

    struct sigcontext sc;
    if (copy_from_user(&sc, (void *)tf->tf_sp, sizeof(sc)) < 0) return -EFAULT;

    *tf = sc.tf;
    p->sig_blocked = sc.sigmask;
    if (p->sigaltstack.ss_flags & SS_ONSTACK)
        p->sigaltstack.ss_flags &= ~SS_ONSTACK;

    return (int64_t)sc.tf.rax;
#elif defined(ARCH_aarch64)
    struct process *p = proc_current();
    struct trap_frame *tf = get_current_trapframe();
    if (!p || !tf) return -EINVAL;

    struct sigcontext sc;
    if (copy_from_user(&sc, (void *)tf->tf_sp, sizeof(sc)) < 0) return -EFAULT;

    *tf = sc.tf;
    p->sig_blocked = sc.sigmask;
    if (p->sigaltstack.ss_flags & SS_ONSTACK)
        p->sigaltstack.ss_flags &= ~SS_ONSTACK;

    return (int64_t)sc.tf.tf_a0;
#else
    return -ENOSYS;
#endif
}

int64_t sys_kill(uint64_t pid, uint64_t sig, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)signal_send((pid_t)pid, (int)sig);
}

int64_t sys_sigaction(uint64_t sig, uint64_t act_ptr, uint64_t old_ptr,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (sig == 0 || sig > NSIG) return -EINVAL;
    if ((sig == SIGKILL || sig == SIGSTOP) && act_ptr) return -EINVAL;

    struct process *p = proc_current();
    if (!p) return -EINVAL;
    if (!p->sighand) return -ENOMEM;

    struct sigaction act = {0};
    if (act_ptr) {
        if (copy_from_user(&act, (void *)act_ptr, sizeof(act)) < 0) return -EFAULT;
    }

    struct sigaction old = {0};
    spin_lock(&p->sighand->lock);
    if (old_ptr) {
        old = p->sighand->actions[sig - 1];
    }
    if (act_ptr) {
        p->sighand->actions[sig - 1] = act;
    }
    spin_unlock(&p->sighand->lock);

    if (old_ptr) {
        if (copy_to_user((void *)old_ptr, &old, sizeof(old)) < 0) return -EFAULT;
    }

    return 0;
}

int64_t sys_sigprocmask(uint64_t how, uint64_t set_ptr, uint64_t old_ptr,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p) return -EINVAL;

    if (old_ptr) {
        sigset_t old = p->sig_blocked;
        if (copy_to_user((void *)old_ptr, &old, sizeof(old)) < 0) return -EFAULT;
    }

    if (set_ptr) {
        sigset_t set;
        if (copy_from_user(&set, (void *)set_ptr, sizeof(set)) < 0) return -EFAULT;

        switch ((int)how) {
        case SIG_BLOCK:
            p->sig_blocked |= set;
            break;
        case SIG_UNBLOCK:
            p->sig_blocked &= ~set;
            break;
        case SIG_SETMASK:
            p->sig_blocked = set;
            break;
        default:
            return -EINVAL;
        }

        /* Never allow blocking SIGKILL/SIGSTOP */
        p->sig_blocked &=
            ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    }

    return 0;
}

int64_t sys_sigaltstack(uint64_t ss_ptr, uint64_t old_ptr, uint64_t a2,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (old_ptr) {
        if (copy_to_user((void *)old_ptr, &p->sigaltstack,
                         sizeof(p->sigaltstack)) < 0)
            return -EFAULT;
    }
    if (ss_ptr) {
        stack_t ss;
        if (copy_from_user(&ss, (void *)ss_ptr, sizeof(ss)) < 0)
            return -EFAULT;
        if (ss.ss_flags & ~SS_DISABLE)
            return -EINVAL;
        if (!(ss.ss_flags & SS_DISABLE)) {
            if (!ss.ss_sp || ss.ss_size == 0)
                return -EINVAL;
            ss.ss_flags &= ~SS_ONSTACK;
            p->sigaltstack = ss;
        } else {
            p->sigaltstack.ss_sp = NULL;
            p->sigaltstack.ss_size = 0;
            p->sigaltstack.ss_flags = SS_DISABLE;
        }
    }
    return 0;
}

int64_t sys_rt_sigpending(uint64_t set_ptr, uint64_t sigsetsize, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;
    if (!set_ptr)
        return -EFAULT;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    sigset_t pending = p->sig_pending;
    if (copy_to_user((void *)set_ptr, &pending, sizeof(pending)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_rt_sigsuspend(uint64_t mask_ptr, uint64_t sigsetsize, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    sigset_t mask;
    if (copy_from_user(&mask, (void *)mask_ptr, sizeof(mask)) < 0)
        return -EFAULT;
    sigset_t old = p->sig_blocked;
    p->sig_blocked = mask;
    p->sig_blocked &=
        ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));

    while (1) {
        if (p->sig_pending & ~p->sig_blocked)
            break;
        proc_sleep_on(NULL, p, true);
    }
    p->sig_blocked = old;
    return -EINTR;
}

static uint64_t ns_to_sched_ticks(uint64_t ns) {
    uint64_t ticks = (ns * CONFIG_HZ + NS_PER_SEC - 1) / NS_PER_SEC;
    return ticks ? ticks : 1;
}

static int copy_timespec_from_user(uint64_t ptr, struct timespec *out) {
    if (!ptr || !out)
        return 0;
    if (copy_from_user(out, (const void *)ptr, sizeof(*out)) < 0)
        return -EFAULT;
    if (out->tv_sec < 0 || out->tv_nsec < 0 || out->tv_nsec >= (int64_t)NS_PER_SEC)
        return -EINVAL;
    return 1;
}

int64_t sys_rt_sigtimedwait(uint64_t mask_ptr, uint64_t info_ptr,
                            uint64_t timeout_ptr, uint64_t sigsetsize,
                            uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    sigset_t mask;
    if (copy_from_user(&mask, (void *)mask_ptr, sizeof(mask)) < 0)
        return -EFAULT;

    uint64_t deadline = 0;
    bool has_timeout = false;
    if (timeout_ptr) {
        struct timespec ts;
        int rc = copy_timespec_from_user(timeout_ptr, &ts);
        if (rc < 0)
            return rc;
        if (rc > 0) {
            uint64_t ns = (uint64_t)ts.tv_sec * NS_PER_SEC +
                          (uint64_t)ts.tv_nsec;
            deadline = arch_timer_get_ticks() + ns_to_sched_ticks(ns);
            has_timeout = true;
        }
    }

    while (1) {
        sigset_t pending = p->sig_pending & mask;
        if (pending) {
            int sig = __builtin_ctzll(pending) + 1;
            __atomic_fetch_and(&p->sig_pending,
                               ~(1ULL << (sig - 1)), __ATOMIC_RELEASE);
            if (info_ptr) {
                siginfo_t info;
                memset(&info, 0, sizeof(info));
                info.si_signo = sig;
                if (copy_to_user((void *)info_ptr, &info, sizeof(info)) < 0)
                    return -EFAULT;
            }
            return sig;
        }
        if (has_timeout && arch_timer_get_ticks() >= deadline)
            return -EAGAIN;

        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        poll_sleep_arm(&sleep, p, has_timeout ? deadline : 0);
        proc_sleep_on(NULL, NULL, true);
        poll_sleep_cancel(&sleep);
        if (has_timeout && arch_timer_get_ticks() >= deadline)
            return -EAGAIN;
    }
}

int64_t sys_rt_sigqueueinfo(uint64_t pid, uint64_t sig, uint64_t info_ptr,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (info_ptr) {
        siginfo_t info;
        if (copy_from_user(&info, (void *)info_ptr, sizeof(info)) < 0)
            return -EFAULT;
    }
    return (int64_t)signal_send((pid_t)pid, (int)sig);
}
