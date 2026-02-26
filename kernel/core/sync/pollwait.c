/**
 * kernel/core/sync/pollwait.c - Poll wait infrastructure
 */

#include <kairos/pollwait.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/process.h>
#include <kairos/tracepoint.h>
#include <kairos/vfs.h>

static struct poll_wait_head poll_sleep_head;
static bool poll_sleep_head_init_done;

int poll_timeout_to_deadline_ms(int timeout_ms, uint64_t *deadline_out) {
    if (!deadline_out)
        return -EINVAL;
    *deadline_out = 0;

    if (timeout_ms < -1)
        return -EINVAL;
    if (timeout_ms < 0)
        return 0;

    uint64_t now = arch_timer_get_ticks();
    if (timeout_ms == 0) {
        *deadline_out = now;
        return 0;
    }

    uint64_t delta = ((uint64_t)timeout_ms * CONFIG_HZ + 999) / 1000;
    if (!delta)
        delta = 1;
    *deadline_out = now + delta;
    return 0;
}

bool poll_deadline_expired(uint64_t deadline) {
    return deadline != 0 && arch_timer_get_ticks() >= deadline;
}

int poll_block_current(uint64_t deadline, void *channel) {
    struct process *curr = proc_current();
    if (!curr)
        return -EINVAL;
    if (poll_deadline_expired(deadline))
        return -ETIMEDOUT;

    tracepoint_emit(TRACE_WAIT_BLOCK, deadline ? 1U : 0U, deadline,
                    (uint64_t)(uintptr_t)channel);

    struct poll_sleep sleep = {0};
    INIT_LIST_HEAD(&sleep.node);
    if (deadline)
        poll_sleep_arm(&sleep, curr, deadline);
    int rc = proc_sleep_on(NULL, channel, true);
    if (deadline)
        poll_sleep_cancel(&sleep);

    if (rc < 0)
        return rc;
    if (poll_deadline_expired(deadline))
        return -ETIMEDOUT;
    return 0;
}

void poll_ready_wake_one(struct wait_queue *wq, struct vnode *vn,
                         uint32_t events) {
    tracepoint_emit(TRACE_WAIT_WAKE, 0x80000000U | events,
                    (uint64_t)(uintptr_t)wq,
                    (uint64_t)(uintptr_t)vn);
    if (wq)
        wait_queue_wakeup_one(wq);
    if (vn)
        vfs_poll_wake(vn, events);
}

void poll_ready_wake_all(struct wait_queue *wq, struct vnode *vn,
                         uint32_t events) {
    tracepoint_emit(TRACE_WAIT_WAKE, events, (uint64_t)(uintptr_t)wq,
                    (uint64_t)(uintptr_t)vn);
    if (wq)
        wait_queue_wakeup_all(wq);
    if (vn)
        vfs_poll_wake(vn, events);
}

static void poll_sleep_head_init(void) {
    if (poll_sleep_head_init_done)
        return;
    poll_wait_head_init(&poll_sleep_head);
    poll_sleep_head_init_done = true;
}

void poll_wait_head_init(struct poll_wait_head *head) {
    wait_queue_init(&head->wq);
    INIT_LIST_HEAD(&head->watches);
}

void poll_wait_add(struct poll_wait_head *head, struct poll_waiter *waiter) {
    if (!head || !waiter || !waiter->entry.proc)
        return;

    waiter->head = head;
    wait_queue_add_entry(&head->wq, &waiter->entry);
}

void poll_wait_remove(struct poll_waiter *waiter) {
    if (!waiter)
        return;
    wait_queue_remove_entry(&waiter->entry);
    waiter->head = NULL;
}

void poll_watch_add(struct poll_wait_head *head, struct poll_watch *watch) {
    if (!head || !watch || !watch->notify)
        return;

    bool flags;
    spin_lock_irqsave(&head->wq.lock, &flags);
    if (!watch->active) {
        watch->head = head;
        watch->active = true;
        watch->notifying = false;
        INIT_LIST_HEAD(&watch->notify_node);
        list_add_tail(&watch->node, &head->watches);
    }
    spin_unlock_irqrestore(&head->wq.lock, flags);
}

void poll_watch_remove(struct poll_watch *watch) {
    if (!watch || !watch->active || !watch->head)
        return;

    struct poll_wait_head *head = watch->head;
    bool flags;
    spin_lock_irqsave(&head->wq.lock, &flags);
    if (watch->active) {
        watch->active = false;
        if (!watch->notifying) {
            list_del(&watch->node);
            watch->head = NULL;
        }
    }
    spin_unlock_irqrestore(&head->wq.lock, flags);
}

void poll_wait_wake(struct poll_wait_head *head, uint32_t events) {
    if (!head)
        return;

    LIST_HEAD(wake_list);
    LIST_HEAD(notify_list);

    bool flags;
    spin_lock_irqsave(&head->wq.lock, &flags);
    while (!list_empty(&head->wq.head)) {
        struct wait_queue_entry *entry =
            list_first_entry(&head->wq.head, struct wait_queue_entry, node);
        list_del(&entry->node);
        entry->active = false;
        entry->wq = NULL;
        list_add_tail(&entry->node, &wake_list);
    }

    struct poll_watch *watch;
    list_for_each_entry(watch, &head->watches, node) {
        if (!watch->active || watch->notifying)
            continue;
        if (events && !(watch->events & events))
            continue;
        if (watch->prepare)
            watch->prepare(watch);
        watch->notifying = true;
        list_add_tail(&watch->notify_node, &notify_list);
    }
    spin_unlock_irqrestore(&head->wq.lock, flags);

    struct wait_queue_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &wake_list, node) {
        list_del(&entry->node);
        if (entry->proc)
            proc_wakeup(entry->proc);
    }

    struct poll_watch *wtmp;
    list_for_each_entry_safe(watch, wtmp, &notify_list, notify_node) {
        list_del(&watch->notify_node);
        watch->notify(watch, events);

        bool flags2;
        spin_lock_irqsave(&head->wq.lock, &flags2);
        watch->notifying = false;
        if (!watch->active) {
            list_del(&watch->node);
            watch->head = NULL;
        }
        spin_unlock_irqrestore(&head->wq.lock, flags2);
    }
}

void poll_sleep_arm(struct poll_sleep *sleep, struct process *proc,
                    uint64_t deadline) {
    if (!sleep || !proc)
        return;

    poll_sleep_head_init();

    bool flags;
    spin_lock_irqsave(&poll_sleep_head.wq.lock, &flags);
    if (sleep->active)
        list_del(&sleep->node);
    sleep->proc = proc;
    sleep->deadline = deadline;
    sleep->active = true;
    list_add_tail(&sleep->node, &poll_sleep_head.wq.head);
    spin_unlock_irqrestore(&poll_sleep_head.wq.lock, flags);
}

void poll_sleep_cancel(struct poll_sleep *sleep) {
    if (!sleep || !sleep->active)
        return;

    poll_sleep_head_init();

    bool flags;
    spin_lock_irqsave(&poll_sleep_head.wq.lock, &flags);
    if (sleep->active) {
        list_del(&sleep->node);
        sleep->active = false;
    }
    spin_unlock_irqrestore(&poll_sleep_head.wq.lock, flags);
}

void poll_sleep_tick(uint64_t now) {
    if (!poll_sleep_head_init_done)
        return;

    LIST_HEAD(wake_list);

    bool flags;
    spin_lock_irqsave(&poll_sleep_head.wq.lock, &flags);
    struct poll_sleep *sleep, *tmp;
    list_for_each_entry_safe(sleep, tmp, &poll_sleep_head.wq.head, node) {
        if (sleep->deadline && sleep->deadline <= now) {
            list_del(&sleep->node);
            sleep->active = false;
            list_add_tail(&sleep->node, &wake_list);
        }
    }
    spin_unlock_irqrestore(&poll_sleep_head.wq.lock, flags);

    list_for_each_entry_safe(sleep, tmp, &wake_list, node) {
        list_del(&sleep->node);
        if (sleep->proc)
            proc_wakeup(sleep->proc);
    }
}
