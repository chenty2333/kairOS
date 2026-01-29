/**
 * kernel/core/proc/proc_wait.c - Waiting and wakeup logic
 */

#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/types.h>

#include "proc_internal.h"

static bool is_process_active(struct process *p) {
    for (int i = 0; i < CONFIG_MAX_CPUS; i++) {
        struct percpu_data *cpu = sched_cpu_data(i);
        if (!cpu)
            continue;
        if (__atomic_load_n(&cpu->curr_proc, __ATOMIC_ACQUIRE) == p)
            return true;
        if (__atomic_load_n(&cpu->prev_task, __ATOMIC_ACQUIRE) == p)
            return true;
    }
    return false;
}

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
                if (__atomic_load_n(&child->on_cpu, __ATOMIC_ACQUIRE)) {
                    if (is_process_active(child)) {
                        busy_zombie = true;
                        continue;
                    }
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

        if (busy_zombie) {
            proc_yield();
            continue;
        }

        proc_lock(p);
        p->state = PROC_SLEEPING;
        p->wait_channel = &p->exit_wait;
        proc_unlock(p);
        wait_queue_add(&p->exit_wait, p);

        /* Avoid missed wakeups: re-check for zombies before sleeping. */
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
        if (has_zombie) {
            wait_queue_remove_entry(&p->wait_entry);
            proc_lock(p);
            p->wait_channel = NULL;
            p->state = PROC_RUNNING;
            proc_unlock(p);
            continue;
        }

        schedule();
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

void proc_sleep(void *channel) {
    (void)proc_sleep_on(NULL, channel, false);
}

void proc_wakeup_all(void *channel) {
    struct process *wake_list[CONFIG_MAX_PROCESSES];
    size_t count = 0;

    spin_lock(&proc_table_lock);
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        struct process *p = &proc_table[i];
        if (p->state == PROC_SLEEPING && p->wait_channel == channel) {
            wake_list[count++] = p;
        }
    }
    spin_unlock(&proc_table_lock);

    for (size_t i = 0; i < count; i++) {
        proc_wakeup(wake_list[i]);
    }
}
