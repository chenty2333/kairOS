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

#include "proc_internal.h"

#define NS_PER_SEC 1000000000ULL
#define LINUX_RT_SIGSET_BYTES (sizeof(uint32_t) * 2U)

struct linux_rt_sigaction {
    void (*handler)(int);
    unsigned long flags;
    void (*restorer)(void);
    uint32_t mask_words[2];
};

static sigset_t linux_rt_sigset_import(const uint32_t words[2]) {
    if (!words)
        return 0;
    return (sigset_t)(((uint64_t)words[1] << 32) | (uint64_t)words[0]);
}

static void linux_rt_sigset_export(sigset_t set, uint32_t words[2]) {
    if (!words)
        return;
    words[0] = (uint32_t)(set & 0xffffffffu);
    words[1] = (uint32_t)((set >> 32) & 0xffffffffu);
}

static int sigaction_copy_from_user(struct process *p, uint64_t ptr,
                                    struct sigaction *out) {
    if (!out)
        return -EINVAL;
    if (!ptr)
        return -EFAULT;
    if (p && p->syscall_abi == SYSCALL_ABI_LINUX) {
        struct linux_rt_sigaction kact;
        if (copy_from_user(&kact, (void *)ptr, sizeof(kact)) < 0)
            return -EFAULT;
        memset(out, 0, sizeof(*out));
        out->sa_handler = kact.handler;
        out->sa_mask = linux_rt_sigset_import(kact.mask_words);
        out->sa_flags = (int)(kact.flags & 0xfffffffful);
        if (out->sa_flags & SA_RESTORER)
            out->sa_restorer = kact.restorer;
        return 0;
    }
    if (copy_from_user(out, (void *)ptr, sizeof(*out)) < 0)
        return -EFAULT;
    return 0;
}

static int sigaction_copy_to_user(struct process *p, uint64_t ptr,
                                  const struct sigaction *in) {
    if (!ptr)
        return 0;
    if (!in)
        return -EINVAL;
    if (p && p->syscall_abi == SYSCALL_ABI_LINUX) {
        struct linux_rt_sigaction kact = {
            .handler = in->sa_handler,
            .flags = (unsigned long)(uint32_t)in->sa_flags,
            .restorer = in->sa_restorer,
            .mask_words = {0, 0},
        };
        linux_rt_sigset_export(in->sa_mask, kact.mask_words);
        if (copy_to_user((void *)ptr, &kact, sizeof(kact)) < 0)
            return -EFAULT;
        return 0;
    }
    if (copy_to_user((void *)ptr, in, sizeof(*in)) < 0)
        return -EFAULT;
    return 0;
}

static bool signal_default_ignore(int sig) {
    return sig == SIGCHLD || sig == SIGCONT || sig == SIGWINCH;
}

static bool signal_default_stop(int sig) {
    return sig == SIGSTOP || sig == SIGTSTP;
}

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

/* Deliver signal to a known process — set pending bit and wake if sleeping. */
static void signal_send_to(struct process *p, int sig) {
    __atomic_fetch_or(&p->sig_pending, (1ULL << (sig - 1)), __ATOMIC_RELEASE);
    signalfd_notify_pending_signal(p, sig);
    proc_lock(p);
    if (p->state == PROC_SLEEPING) {
        proc_unlock(p);
        proc_wakeup(p);
    } else {
        proc_unlock(p);
    }
}

static int signal_send_core(pid_t pid, int sig, uid_t sender_uid,
                            bool enforce_uid) {
    if (sig <= 0 || sig > NSIG)
        return -EINVAL;
    if (pid <= 0)
        return -ESRCH;

    struct process *target = NULL;
    bool flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    target = proc_find_locked(pid);
    if (target && enforce_uid && sender_uid != 0 && sender_uid != target->uid) {
        spin_unlock_irqrestore(&proc_table_lock, flags);
        return -EPERM;
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
    if (!target)
        return -ESRCH;

    signal_send_to(target, sig);
    return 0;
}

int signal_send(pid_t pid, int sig) {
    return signal_send_core(pid, sig, 0, false);
}

int signal_send_authorized(pid_t pid, int sig, uid_t sender_uid,
                           bool sender_is_superuser) {
    return signal_send_core(pid, sig,
                            sender_is_superuser ? 0 : sender_uid, true);
}

int signal_send_pgrp(pid_t pgrp, int sig) {
    if (sig <= 0 || sig > NSIG) return -EINVAL;
    if (pgrp <= 0) return -ESRCH;

    uint64_t mask = 1ULL << (sig - 1);
    int count = 0;
    bool flags;

    /* Set pending bits under lock; wakeup after release. */
    spin_lock_irqsave(&proc_table_lock, &flags);
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        struct process *p = &proc_table[i];
        if (p->state != PROC_UNUSED && p->state != PROC_EMBRYO &&
            p->pgid == pgrp) {
            __atomic_fetch_or(&p->sig_pending, mask, __ATOMIC_RELEASE);
            count++;
        }
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);

    if (count == 0)
        return -ESRCH;

    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        struct process *p = &proc_table[i];
        if (p->state == PROC_UNUSED || p->state == PROC_EMBRYO)
            continue;
        if (p->pgid != pgrp)
            continue;
        if (!(__atomic_load_n(&p->sig_pending, __ATOMIC_ACQUIRE) & mask))
            continue;
        signalfd_notify_pending_signal(p, sig);
        if (p->state == PROC_SLEEPING)
            proc_wakeup(p);
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

        if (handler == SIG_IGN || (handler == SIG_DFL && signal_default_ignore(sig))) {
            __atomic_fetch_and(&p->sig_pending, ~mask, __ATOMIC_RELEASE);
            pending &= ~mask;
            continue;
        }

        if (handler == SIG_DFL) {
            if (signal_default_stop(sig)) {
                __atomic_fetch_and(&p->sig_pending, ~mask, __ATOMIC_RELEASE);
                while (1) {
                    uint64_t now_pending =
                        __atomic_load_n(&p->sig_pending, __ATOMIC_ACQUIRE);
                    if (now_pending & (1ULL << (SIGKILL - 1)))
                        break;
                    if (now_pending & (1ULL << (SIGCONT - 1))) {
                        __atomic_fetch_and(&p->sig_pending,
                                           ~(1ULL << (SIGCONT - 1)),
                                           __ATOMIC_RELEASE);
                        break;
                    }
                    proc_sleep_on(NULL, p, true);
                }
                pending = __atomic_load_n(&p->sig_pending, __ATOMIC_ACQUIRE);
                i = -1;
                continue;
            }
            pr_info("Process %d killed by signal %d\n", p->pid, sig);
            proc_exit(-sig);
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
        if ((action.sa_flags & SA_RESTORER) && action.sa_restorer) {
            tf->regs[30] = (uint64_t)action.sa_restorer;
        } else {
            tf->regs[30] =
                sp + __builtin_offsetof(struct sigcontext, trampoline);
        }

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
    pid_t target = (pid_t)pid;
    int s = (int)sig;
    if (target > 0)
        return (int64_t)signal_send(target, s);
    if (target == 0) {
        struct process *cur = proc_current();
        return cur ? (int64_t)signal_send_pgrp(cur->pgid, s) : -ESRCH;
    }
    if (target == -1)
        return -ESRCH;
    return (int64_t)signal_send_pgrp(-target, s);
}

int64_t sys_sigaction(uint64_t sig, uint64_t act_ptr, uint64_t old_ptr,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (p->syscall_abi == SYSCALL_ABI_LINUX &&
        a3 != LINUX_RT_SIGSET_BYTES)
        return -EINVAL;
    if (sig == 0 || sig > NSIG) return -EINVAL;
    if ((sig == SIGKILL || sig == SIGSTOP) && act_ptr) return -EINVAL;

    if (!p->sighand) return -ENOMEM;

    struct sigaction act = {0};
    if (act_ptr) {
        int rc = sigaction_copy_from_user(p, act_ptr, &act);
        if (rc < 0)
            return rc;
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

    if (old_ptr)
        return sigaction_copy_to_user(p, old_ptr, &old);

    return 0;
}

int64_t sys_sigprocmask(uint64_t how, uint64_t set_ptr, uint64_t old_ptr,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p) return -EINVAL;
    if (p->syscall_abi == SYSCALL_ABI_LINUX &&
        a3 != sizeof(sigset_t))
        return -EINVAL;

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
    if (ns == 0)
        return 0;
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
