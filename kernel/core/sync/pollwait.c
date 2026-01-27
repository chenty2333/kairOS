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
    spin_init(&poll_sleep_head.lock);
    INIT_LIST_HEAD(&poll_sleep_head.head);
    poll_sleep_head_init_done = true;
}

void poll_wait_head_init(struct poll_wait_head *head) {
    spin_init(&head->lock);
    INIT_LIST_HEAD(&head->head);
}

void poll_wait_add(struct poll_wait_head *head, struct poll_waiter *waiter) {
    if (!head || !waiter || !waiter->proc)
        return;

    spin_lock(&head->lock);
    if (!waiter->active) {
        waiter->head = head;
        waiter->active = true;
        list_add_tail(&waiter->node, &head->head);
    }
    spin_unlock(&head->lock);
}

void poll_wait_remove(struct poll_waiter *waiter) {
    if (!waiter || !waiter->active || !waiter->head)
        return;

    struct poll_wait_head *head = waiter->head;
    spin_lock(&head->lock);
    if (waiter->active) {
        list_del(&waiter->node);
        waiter->active = false;
        waiter->head = NULL;
    }
    spin_unlock(&head->lock);
}

void poll_wait_wake(struct poll_wait_head *head) {
    if (!head)
        return;

    LIST_HEAD(wake_list);

    spin_lock(&head->lock);
    while (!list_empty(&head->head)) {
        struct poll_waiter *waiter =
            list_first_entry(&head->head, struct poll_waiter, node);
        list_del(&waiter->node);
        waiter->active = false;
        waiter->head = NULL;
        list_add_tail(&waiter->node, &wake_list);
    }
    spin_unlock(&head->lock);

    struct poll_waiter *waiter, *tmp;
    list_for_each_entry_safe(waiter, tmp, &wake_list, node) {
        list_del(&waiter->node);
        if (waiter->proc)
            proc_wakeup(waiter->proc);
    }
}

void poll_sleep_arm(struct poll_sleep *sleep, struct process *proc,
                    uint64_t deadline) {
    if (!sleep || !proc)
        return;

    poll_sleep_head_init();

    spin_lock(&poll_sleep_head.lock);
    if (sleep->active)
        list_del(&sleep->node);
    sleep->proc = proc;
    sleep->deadline = deadline;
    sleep->active = true;
    list_add_tail(&sleep->node, &poll_sleep_head.head);
    spin_unlock(&poll_sleep_head.lock);
}

void poll_sleep_cancel(struct poll_sleep *sleep) {
    if (!sleep || !sleep->active)
        return;

    poll_sleep_head_init();

    spin_lock(&poll_sleep_head.lock);
    if (sleep->active) {
        list_del(&sleep->node);
        sleep->active = false;
    }
    spin_unlock(&poll_sleep_head.lock);
}

void poll_sleep_tick(uint64_t now) {
    if (!poll_sleep_head_init_done)
        return;

    LIST_HEAD(wake_list);

    spin_lock(&poll_sleep_head.lock);
    struct poll_sleep *sleep, *tmp;
    list_for_each_entry_safe(sleep, tmp, &poll_sleep_head.head, node) {
        if (sleep->deadline && sleep->deadline <= now) {
            list_del(&sleep->node);
            sleep->active = false;
            list_add_tail(&sleep->node, &wake_list);
        }
    }
    spin_unlock(&poll_sleep_head.lock);

    list_for_each_entry_safe(sleep, tmp, &wake_list, node) {
        list_del(&sleep->node);
        if (sleep->proc)
            proc_wakeup(sleep->proc);
    }
}

