/**
 * kernel/core/proc/proc_wait.c - Waiting and wakeup logic
 */

#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/types.h>

#include "proc_internal.h"

static bool proc_wait_find_reapable(struct process *parent, pid_t pid,
                                    struct process **out_reap) {
    bool found = false;
    struct process *child, *tmp;
    struct process *reap = NULL;

    spin_lock(&proc_table_lock);
    list_for_each_entry_safe(child, tmp, &parent->children, sibling) {
        found = true;
        if (pid > 0 && child->pid != pid)
            continue;
        if (child->state == PROC_ZOMBIE) {
            if (__atomic_load_n(&child->se.on_cpu, __ATOMIC_ACQUIRE))
                continue;
            child->state = PROC_REAPING;
            list_del(&child->sibling);
            reap = child;
            break;
        }
    }
    spin_unlock(&proc_table_lock);

    if (out_reap)
        *out_reap = reap;
    return found;
}

pid_t proc_wait(pid_t pid, int *status, int options __attribute__((unused))) {
    struct process *p = proc_current();
    while (1) {
        struct process *reap = NULL;
        bool found = proc_wait_find_reapable(p, pid, &reap);
        if (reap) {
            pid_t cpid = reap->pid;
            if (status)
                *status = reap->exit_code;
            proc_free(reap);
            return cpid;
        }
        if (!found)
            return -ECHILD;
        if (options & WNOHANG)
            return 0;

        /* Arm waiter first, then re-check children to close wait race. */
        wait_queue_add(&p->exit_wait, p);

        reap = NULL;
        found = proc_wait_find_reapable(p, pid, &reap);
        if (reap) {
            wait_queue_remove(&p->exit_wait, p);
            pid_t cpid = reap->pid;
            if (status)
                *status = reap->exit_code;
            proc_free(reap);
            return cpid;
        }
        if (!found) {
            wait_queue_remove(&p->exit_wait, p);
            return -ECHILD;
        }

        proc_lock(p);
        if (!p->wait_entry.active) {
            /* Woken between re-check and sleep state transition. */
            p->wait_channel = NULL;
            p->sleep_deadline = 0;
            p->state = PROC_RUNNING;
            proc_unlock(p);
            continue;
        }
        if (p->sig_pending) {
            proc_unlock(p);
            wait_queue_remove(&p->exit_wait, p);
            return -EINTR;
        }
        p->wait_channel = &p->exit_wait;
        p->sleep_deadline = 0;
        p->state = PROC_SLEEPING;
        sched_trace_event(SCHED_TRACE_SLEEP, p, (uint64_t)&p->exit_wait, 0);
        proc_unlock(p);

        proc_yield();

        proc_lock(p);
        if (p->wait_entry.active)
            wait_queue_remove_entry(&p->wait_entry);
        p->wait_channel = NULL;
        p->sleep_deadline = 0;
        if (p->state == PROC_SLEEPING)
            p->state = PROC_RUNNING;
        bool interrupted = p->sig_pending;
        proc_unlock(p);
        if (interrupted)
            return -EINTR;
    }
}

void proc_yield(void) {
    schedule();
}

void proc_wakeup(struct process *p) {
    if (!p)
        return;

    proc_lock(p);
    if (p->state != PROC_SLEEPING) {
        proc_unlock(p);
        return;
    }

    if (p->wait_channel && p->wait_entry.active)
        wait_queue_remove_entry(&p->wait_entry);
    p->wait_channel = NULL;
    p->state = PROC_RUNNABLE;
    sched_trace_event(SCHED_TRACE_WAKEUP, p, 0, 0);
    proc_unlock(p);
    sched_enqueue(p);
}
