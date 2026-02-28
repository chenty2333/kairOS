/**
 * kernel/core/sync/completion.c - Completion primitive
 */

#include <kairos/completion.h>
#include <kairos/arch.h>
#include <kairos/lock_debug.h>
#include <kairos/process.h>
#include <kairos/printk.h>

void completion_init(struct completion *c) {
    c->done = 0;
    spin_init(&c->lock);
    wait_queue_init(&c->wq);
}

void wait_for_completion(struct completion *c) {
    SLEEP_LOCK_DEBUG_CHECK();

    struct process *curr = proc_current();
    if (!curr) {
        spin_lock(&c->lock);
        while (!c->done) {
            spin_unlock(&c->lock);
            arch_cpu_relax();
            spin_lock(&c->lock);
        }
        if (c->done != UINT32_MAX)
            c->done--;
        spin_unlock(&c->lock);
        return;
    }

    spin_lock(&c->lock);
    while (!c->done) {
        wait_queue_add(&c->wq, curr);
        spin_unlock(&c->lock);
        proc_sleep_on(&c->wq, c, false);
        spin_lock(&c->lock);
    }
    if (c->done != UINT32_MAX)
        c->done--;
    spin_unlock(&c->lock);
}

int wait_for_completion_interruptible(struct completion *c) {
    SLEEP_LOCK_DEBUG_CHECK();

    struct process *curr = proc_current();
    if (!curr) {
        spin_lock(&c->lock);
        while (!c->done) {
            spin_unlock(&c->lock);
            arch_cpu_relax();
            spin_lock(&c->lock);
        }
        if (c->done != UINT32_MAX)
            c->done--;
        spin_unlock(&c->lock);
        return 0;
    }

    spin_lock(&c->lock);
    while (!c->done) {
        wait_queue_add(&c->wq, curr);
        spin_unlock(&c->lock);
        int rc = proc_sleep_on(&c->wq, c, true);
        if (rc < 0)
            return rc;
        spin_lock(&c->lock);
    }
    if (c->done != UINT32_MAX)
        c->done--;
    spin_unlock(&c->lock);
    return 0;
}

int wait_for_completion_timeout(struct completion *c, uint64_t ticks) {
    SLEEP_LOCK_DEBUG_CHECK();

    struct process *curr = proc_current();
    if (!curr) {
        uint64_t deadline = arch_timer_get_ticks() + ticks;
        spin_lock(&c->lock);
        while (!c->done) {
            spin_unlock(&c->lock);
            if (arch_timer_get_ticks() >= deadline)
                return -ETIMEDOUT;
            arch_cpu_relax();
            spin_lock(&c->lock);
        }
        if (c->done != UINT32_MAX)
            c->done--;
        spin_unlock(&c->lock);
        return 0;
    }

    uint64_t deadline = arch_timer_get_ticks() + ticks;
    spin_lock(&c->lock);
    while (!c->done) {
        wait_queue_add(&c->wq, curr);
        spin_unlock(&c->lock);
        int rc = proc_sleep_on_mutex_timeout(&c->wq, c, NULL, false, deadline);
        if (rc == -ETIMEDOUT)
            return -ETIMEDOUT;
        spin_lock(&c->lock);
    }
    if (c->done != UINT32_MAX)
        c->done--;
    spin_unlock(&c->lock);
    return 0;
}

void complete_one(struct completion *c) {
    spin_lock(&c->lock);
    if (c->done != UINT32_MAX)
        c->done++;
    spin_unlock(&c->lock);
    wait_queue_wakeup_one(&c->wq);
}

void complete_all(struct completion *c) {
    spin_lock(&c->lock);
    c->done = UINT32_MAX;
    spin_unlock(&c->lock);
    wait_queue_wakeup_all(&c->wq);
}

void reinit_completion(struct completion *c) {
    spin_lock(&c->lock);
    c->done = 0;
    spin_unlock(&c->lock);
}
