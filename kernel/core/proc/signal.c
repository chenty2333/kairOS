/**
 * kernel/core/proc/signal.c - Signal Handling Logic
 */

#include <asm/arch.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/string.h>
#include <kairos/uaccess.h>

void signal_init_process(struct process *p) {
    p->sigactions = kzalloc(sizeof(struct sigaction) * NSIG);
    if (!p->sigactions) {
        pr_warn("signal: sigaction alloc failed for pid %d\n", p->pid);
    }
}

int signal_send(pid_t pid, int sig) {
    if (sig <= 0 || sig > NSIG) return -EINVAL;
    struct process *p = proc_find(pid);
    if (!p) return -ESRCH;

    __atomic_fetch_or(&p->sig_pending, (1ULL << (sig - 1)), __ATOMIC_RELAXED);
    if (p->state == PROC_SLEEPING)
        proc_wakeup(p);
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
        struct sigaction action = p->sigactions ? p->sigactions[i] : (struct sigaction){0};
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
        uint64_t sp = tf->tf_sp;
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
    }
}

int64_t sys_sigreturn(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;

    struct process *p = proc_current();
    struct trap_frame *tf = get_current_trapframe();
    if (!p || !tf) return -EINVAL;

    struct sigcontext sc;
    if (copy_from_user(&sc, (void *)tf->tf_sp, sizeof(sc)) < 0) return -EFAULT;

    memcpy(tf->regs, sc.regs, sizeof(sc.regs));
    tf->sepc = sc.sepc;
    tf->sstatus = (sc.sstatus & ~SSTATUS_SPP) | SSTATUS_SPIE;
    p->sig_blocked = sc.sigmask;

    return (int64_t)sc.regs[9]; /* restore a0 */
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

    if (old_ptr) {
        struct sigaction old = p->sigactions ? p->sigactions[sig - 1] : (struct sigaction){0};
        if (copy_to_user((void *)old_ptr, &old, sizeof(old)) < 0) return -EFAULT;
    }

    if (act_ptr) {
        struct sigaction act;
        if (copy_from_user(&act, (void *)act_ptr, sizeof(act)) < 0) return -EFAULT;
        if (!p->sigactions) return -ENOMEM;
        p->sigactions[sig - 1] = act;
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
