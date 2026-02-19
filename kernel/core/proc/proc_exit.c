/**
 * kernel/core/proc/proc_exit.c - Process exit handling
 */

#include <kairos/arch.h>
#include <kairos/futex.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>

#include "proc_internal.h"

static proc_exit_callback_t exit_callbacks[PROC_EXIT_CALLBACKS_MAX];
static int exit_callback_count = 0;
static spinlock_t exit_callback_lock = SPINLOCK_INIT;

void proc_register_exit_callback(proc_exit_callback_t callback)
{
    spin_lock(&exit_callback_lock);
    if (exit_callback_count < PROC_EXIT_CALLBACKS_MAX) {
        exit_callbacks[exit_callback_count++] = callback;
    }
    spin_unlock(&exit_callback_lock);
}

static void proc_reparent_children(struct process *p) {
    struct process *reaper = reaper_proc;
    if (!reaper || reaper == p)
        return;

    bool wake_reaper = false;
    bool flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    struct process *child, *tmp;
    list_for_each_entry_safe(child, tmp, &p->children, sibling) {
        list_del(&child->sibling);
        child->parent = reaper;
        child->ppid = reaper->pid;
        list_add_tail(&child->sibling, &reaper->children);
        if (child->state == PROC_ZOMBIE)
            wake_reaper = true;
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
    if (wake_reaper)
        wait_queue_wakeup_all(&reaper->exit_wait);
}

noreturn void proc_exit(int status) {
    struct process *p = proc_current();
    int code = status & 0xff;
    bool is_thread = (p->group_leader != p);
    pr_info("Process %d exiting: %d\n", p->pid, code);

    if (p->vfork_parent) {
        complete_all(&p->vfork_completion);
        p->vfork_parent = NULL;
    }

    if (p->tid_address) {
        uint32_t zero = 0;
        copy_to_user((void *)p->tid_address, &zero, sizeof(zero));
        futex_wake(p->tid_address, 1);
        p->tid_address = 0;
    }

    /* Call registered exit callbacks (before releasing shared resources) */
    for (int i = 0; i < exit_callback_count; i++) {
        if (exit_callbacks[i]) {
            exit_callbacks[i](p);
        }
    }

    /* Release shared resources via refcount */
    if (p->fdtable) {
        fdtable_put(p->fdtable);
        p->fdtable = NULL;
    }
    if (p->sighand) {
        sighand_put(p->sighand);
        p->sighand = NULL;
    }

    /* Remove from thread group if a non-leader thread */
    if (is_thread) {
        bool flags;
        spin_lock_irqsave(&proc_table_lock, &flags);
        if (!list_empty(&p->thread_group)) {
            list_del(&p->thread_group);
            INIT_LIST_HEAD(&p->thread_group);
        }
        spin_unlock_irqrestore(&proc_table_lock, flags);
    }

    if (!is_thread) {
        proc_reparent_children(p);
    }

    /* Set ZOMBIE: the running task is not on any runqueue, so no dequeue
     * is needed.  schedule() -> put_prev_task will handle the transition. */
    p->exit_code = (code << 8);
    proc_set_state_release(p, PROC_ZOMBIE);

    if (p->parent) {
        wait_queue_wakeup_all(&p->parent->exit_wait);
    }

    schedule();
    while (1)
        arch_cpu_halt();
}
