/**
 * kernel/core/proc/signal.c - Signal Handling Logic
 */

#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>

int signal_send(pid_t pid, int sig) {
    if (sig <= 0 || sig > NSIG)
        return -EINVAL;
    struct process *p = proc_find(pid);
    if (!p)
        return -ESRCH;

    p->sig_pending |= (1ULL << (sig - 1));

    /* Wake up process if it's sleeping */
    if (p->state == PROC_SLEEPING) {
        p->state = PROC_RUNNABLE;
        sched_enqueue(p);
    }
    return 0;
}

void signal_deliver_pending(void) {
    struct process *p = proc_current();
    if (!p || !p->mm || !p->sig_pending)
        return;

    /* For now, handle fatal default signals */
    for (int i = 0; i < NSIG; i++) {
        uint64_t mask = (1ULL << i);
        if (p->sig_pending & mask) {
            int sig = i + 1;
            /* Simple logic: if it's a fatal signal, exit process */
            if (sig == SIGKILL || sig == SIGILL || sig == SIGSEGV ||
                sig == SIGTERM) {
                pr_info("Process %d killed by signal %d\n", p->pid, sig);
                proc_exit(-sig);
            }
            /* Clear unhandled signals for now */
            p->sig_pending &= ~mask;
        }
    }
}
