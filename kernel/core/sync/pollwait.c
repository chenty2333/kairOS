/**
 * kernel/core/sync/pollwait.c - Poll wait infrastructure
 */

#include <kairos/pollwait.h>
#include <kairos/process.h>

static struct poll_wait_head poll_sleep_head;
static bool poll_sleep_head_init_done;

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

    spin_lock(&head->wq.lock);
    if (!watch->active) {
        watch->head = head;
        watch->active = true;
        watch->notifying = false;
        INIT_LIST_HEAD(&watch->notify_node);
        list_add_tail(&watch->node, &head->watches);
    }
    spin_unlock(&head->wq.lock);
}

void poll_watch_remove(struct poll_watch *watch) {
    if (!watch || !watch->active || !watch->head)
        return;

    struct poll_wait_head *head = watch->head;
    spin_lock(&head->wq.lock);
    if (watch->active) {
        watch->active = false;
        if (!watch->notifying) {
            list_del(&watch->node);
            watch->head = NULL;
        }
    }
    spin_unlock(&head->wq.lock);
}

void poll_wait_wake(struct poll_wait_head *head, uint32_t events) {
    if (!head)
        return;

    LIST_HEAD(wake_list);
    LIST_HEAD(notify_list);

    spin_lock(&head->wq.lock);
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
    spin_unlock(&head->wq.lock);

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

        spin_lock(&head->wq.lock);
        watch->notifying = false;
        if (!watch->active) {
            list_del(&watch->node);
            watch->head = NULL;
        }
        spin_unlock(&head->wq.lock);
    }
}

void poll_sleep_arm(struct poll_sleep *sleep, struct process *proc,
                    uint64_t deadline) {
    if (!sleep || !proc)
        return;

    poll_sleep_head_init();

    spin_lock(&poll_sleep_head.wq.lock);
    if (sleep->active)
        list_del(&sleep->node);
    sleep->proc = proc;
    sleep->deadline = deadline;
    sleep->active = true;
    list_add_tail(&sleep->node, &poll_sleep_head.wq.head);
    spin_unlock(&poll_sleep_head.wq.lock);
}

void poll_sleep_cancel(struct poll_sleep *sleep) {
    if (!sleep || !sleep->active)
        return;

    poll_sleep_head_init();

    spin_lock(&poll_sleep_head.wq.lock);
    if (sleep->active) {
        list_del(&sleep->node);
        sleep->active = false;
    }
    spin_unlock(&poll_sleep_head.wq.lock);
}

void poll_sleep_tick(uint64_t now) {
    if (!poll_sleep_head_init_done)
        return;

    LIST_HEAD(wake_list);

    spin_lock(&poll_sleep_head.wq.lock);
    struct poll_sleep *sleep, *tmp;
    list_for_each_entry_safe(sleep, tmp, &poll_sleep_head.wq.head, node) {
        if (sleep->deadline && sleep->deadline <= now) {
            list_del(&sleep->node);
            sleep->active = false;
            list_add_tail(&sleep->node, &wake_list);
        }
    }
    spin_unlock(&poll_sleep_head.wq.lock);

    list_for_each_entry_safe(sleep, tmp, &wake_list, node) {
        list_del(&sleep->node);
        if (sleep->proc)
            proc_wakeup(sleep->proc);
    }
}
