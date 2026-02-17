/**
 * kernel/core/proc/proc_wait.c - Waiting and wakeup logic
 */

#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/types.h>

#include "proc_internal.h"

pid_t proc_wait(pid_t pid, int *status, int options __attribute__((unused))) {
    struct process *p = proc_current(), *child, *tmp;
    while (1) {
        bool found = false;
        bool busy_zombie = false;
        struct process *reap = NULL;
        spin_lock(&proc_table_lock);
        list_for_each_entry_safe(child, tmp, &p->children, sibling) {
            found = true;
            if (pid > 0 && child->pid != pid)
                continue;
            if (child->state == PROC_ZOMBIE) {
                if (__atomic_load_n(&child->se.on_cpu, __ATOMIC_ACQUIRE)) {
                    busy_zombie = true;
                    continue;
                }
                child->state = PROC_REAPING;
                list_del(&child->sibling);
                reap = child;
                break;
            }
        }
        spin_unlock(&proc_table_lock);
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

        /*
         * Sleep on exit_wait. For busy zombies (still on_cpu after context
         * switch), sched_post_switch_cleanup() will wake us when the zombie
         * finishes switching out.
         */
        int rc = proc_sleep_on(&p->exit_wait, &p->exit_wait, true);

        /* Re-check for zombies after wakeup (handles both normal exit
         * and busy_zombie completion notifications). */
        bool has_zombie = false;
        spin_lock(&proc_table_lock);
        list_for_each_entry_safe(child, tmp, &p->children, sibling) {
            if (pid > 0 && child->pid != pid)
                continue;
            if (child->state == PROC_ZOMBIE) {
                has_zombie = true;
                break;
            }
        }
        spin_unlock(&proc_table_lock);
        (void)rc;
        (void)has_zombie;
        (void)busy_zombie;
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
    proc_unlock(p);
    sched_enqueue(p);
}
