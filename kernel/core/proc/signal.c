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
}

int signal_send(pid_t pid, int sig) {
    if (sig <= 0 || sig > NSIG) return -EINVAL;
    struct process *p = proc_find(pid);
    if (!p) return -ESRCH;

    p->sig_pending |= (1ULL << (sig - 1));
    if (p->state == PROC_SLEEPING) {
        p->state = PROC_RUNNABLE;
        sched_enqueue(p);
    }
    return 0;
}

void signal_deliver_pending(void) {
    struct process *p = proc_current();
    struct trap_frame *tf = get_current_trapframe();
    if (!p || !p->mm || !p->sig_pending || !tf) return;

    for (int i = 0; i < NSIG; i++) {
        uint64_t mask = (1ULL << i);
        if (!(p->sig_pending & mask)) continue;

        int sig = i + 1;
        void (*handler)(int) = p->sigactions ? p->sigactions[i].sa_handler : SIG_DFL;

        if (handler == SIG_IGN || (handler == SIG_DFL && sig == SIGCHLD)) {
            p->sig_pending &= ~mask;
            continue;
        }

        if (handler == SIG_DFL) {
            if (sig == SIGKILL || sig == SIGILL || sig == SIGSEGV || sig == SIGTERM) {
                pr_info("Process %d killed by signal %d\n", p->pid, sig);
                proc_exit(-sig);
            }
            p->sig_pending &= ~mask;
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
        
        /* Trampoline: li a7, 64 (SYS_sigreturn); ecall */
        /* RISC-V instructions: 0x04000893 (li a7, 64), 0x00000073 (ecall) */
        sc.trampoline[0] = 0x0000007304000893ULL; 

        if (copy_to_user((void *)sp, &sc, sizeof(sc)) < 0) {
            proc_exit(-SIGSEGV);
        }

        /* Hijack execution */
        tf->tf_sp = sp;
        tf->sepc = (uint64_t)handler;
        tf->tf_ra = sp + __builtin_offsetof(struct sigcontext, trampoline);
        tf->tf_a0 = sig;

        p->sig_pending &= ~mask;
        return; /* Deliver one signal at a time */
    }
}