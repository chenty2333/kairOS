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

static void proc_reparent_children(struct process *p) {
    struct process *reaper = reaper_proc;
    if (!reaper || reaper == p)
        return;

    bool wake_reaper = false;
    spin_lock(&proc_table_lock);
    struct process *child, *tmp;
    list_for_each_entry_safe(child, tmp, &p->children, sibling) {
        list_del(&child->sibling);
        child->parent = reaper;
        child->ppid = reaper->pid;
        list_add_tail(&child->sibling, &reaper->children);
        if (child->state == PROC_ZOMBIE)
            wake_reaper = true;
    }
    spin_unlock(&proc_table_lock);
    if (wake_reaper)
        wait_queue_wakeup_all(&reaper->exit_wait);
}

noreturn void proc_exit(int status) {
    struct process *p = proc_current();
    int code = status & 0xff;
    pr_info("Process %d exiting: %d\n", p->pid, code);

    if (p->vfork_parent) {
        __atomic_store_n(&p->vfork_done, true, __ATOMIC_RELEASE);
        wait_queue_wakeup_all(&p->vfork_wait);
        p->vfork_parent = NULL;
    }

    if (p->tid_address) {
        uint32_t zero = 0;
        copy_to_user((void *)p->tid_address, &zero, sizeof(zero));
        futex_wake(p->tid_address, 1);
        p->tid_address = 0;
    }

    fd_close_all(p);
    proc_reparent_children(p);

    sched_dequeue(p);
    /* Encode for waitpid/WIFEXITED semantics (like Linux) */
    p->exit_code = (code << 8);
    p->state = PROC_ZOMBIE;

    if (p->parent) {
        wait_queue_wakeup_all(&p->parent->exit_wait);
    }

    schedule();
    while (1)
        arch_cpu_halt();
}
