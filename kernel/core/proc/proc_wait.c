/**
 * kernel/core/proc/proc_wait.c - Waiting and wakeup logic
 */

#include <kairos/process.h>
#include <kairos/preempt.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/types.h>

#include "proc_internal.h"

struct proc_wait_scan {
    bool found_child;
    pid_t ready_pid;
    int ready_status;
    struct process *reap;
};

static void proc_wait_scan_children(struct process *parent, pid_t pid,
                                    bool consume, struct proc_wait_scan *scan) {
    if (!scan)
        return;

    memset(scan, 0, sizeof(*scan));

    bool flags;
    struct process *child, *tmp;
    spin_lock_irqsave(&proc_table_lock, &flags);
    list_for_each_entry_safe(child, tmp, &parent->children, sibling) {
        if (pid > 0 && child->pid != pid)
            continue;

        scan->found_child = true;
        if (child->state != PROC_ZOMBIE)
            continue;

        if (consume) {
            if (sched_is_on_cpu(child))
                continue;
            if (se_is_on_rq(&child->se))
                continue;
            child->state = PROC_REAPING;
            list_del(&child->sibling);
            scan->reap = child;
        }

        scan->ready_pid = child->pid;
        scan->ready_status = child->exit_code;
        break;
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
}

static pid_t proc_wait_common(pid_t pid, int *status, int options, bool consume,
                              bool *reaped_out) {
    if (reaped_out)
        *reaped_out = false;

    struct process *p = proc_current();
    while (1) {
        struct proc_wait_scan scan;
        proc_wait_scan_children(p, pid, consume, &scan);
        if (scan.ready_pid > 0) {
            pid_t cpid = scan.ready_pid;
            if (status)
                *status = scan.ready_status;
            if (scan.reap) {
                proc_free(scan.reap);
                if (reaped_out)
                    *reaped_out = true;
            }
            return cpid;
        }
        if (!scan.found_child)
            return -ECHILD;
        if (options & WNOHANG)
            return 0;

        /* Arm waiter first, then re-check children to close wait race. */
        wait_queue_add(&p->exit_wait, p);

        proc_wait_scan_children(p, pid, consume, &scan);
        if (scan.ready_pid > 0) {
            wait_queue_remove(&p->exit_wait, p);
            pid_t cpid = scan.ready_pid;
            if (status)
                *status = scan.ready_status;
            if (scan.reap) {
                proc_free(scan.reap);
                if (reaped_out)
                    *reaped_out = true;
            }
            return cpid;
        }
        if (!scan.found_child) {
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
        if (proc_has_unblocked_signal(p)) {
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
        bool interrupted = proc_has_unblocked_signal(p);
        proc_unlock(p);
        if (interrupted)
            return -EINTR;
    }
}

pid_t proc_wait(pid_t pid, int *status, int options) {
    return proc_wait_common(pid, status, options, true, NULL);
}

pid_t proc_waitid(pid_t pid, int *status, int options, bool *reaped_out) {
    bool consume = (options & WNOWAIT) == 0;
    return proc_wait_common(pid, status, options, consume, reaped_out);
}

void proc_yield(void) {
    schedule();
}

static bool proc_wakeup_can_direct_switch(const struct process *wakee) {
    struct process *curr = proc_current();
    if (!wakee || !curr || curr == wakee)
        return false;
    if (!arch_irq_enabled() || in_atomic())
        return false;
    if (curr->state != PROC_RUNNING)
        return false;
    if (wakee->se.cpu != arch_cpu_id())
        return false;
    return true;
}

void proc_wakeup_ex(struct process *p, bool direct_switch_hint) {
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
    sched_trace_event(SCHED_TRACE_WAKEUP, p, 0, 0);
    proc_unlock(p);
    sched_wake(p);
    if (direct_switch_hint && proc_wakeup_can_direct_switch(p))
        schedule();
}

void proc_wakeup(struct process *p) {
    proc_wakeup_ex(p, false);
}

void proc_wake_expired_sleepers(uint64_t now_ticks) {
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        struct process *p = &proc_table[i];
        uint64_t dl = __atomic_load_n(&p->sleep_deadline, __ATOMIC_ACQUIRE);
        if (dl != 0 && dl <= now_ticks && p->state == PROC_SLEEPING)
            proc_wakeup(p);
    }
}
