/**
 * kernel/core/sync/wait.c - Wait Queue implementation
 */

#include <kairos/process.h>
#include <kairos/spinlock.h>
#include <kairos/wait.h>

void wait_queue_init(struct wait_queue *wq) {
    spin_init(&wq->lock);
    INIT_LIST_HEAD(&wq->head);
}

void wait_queue_entry_init(struct wait_queue_entry *entry, struct process *p) {
    if (!entry)
        return;
    INIT_LIST_HEAD(&entry->node);
    entry->wq = NULL;
    entry->proc = p;
    entry->active = false;
}

void wait_queue_add_entry(struct wait_queue *wq, struct wait_queue_entry *entry) {
    if (!wq || !entry || !entry->proc)
        return;
    bool flags;
    spin_lock_irqsave(&wq->lock, &flags);
    if (!entry->active) {
        entry->wq = wq;
        entry->active = true;
        list_add_tail(&entry->node, &wq->head);
    }
    spin_unlock_irqrestore(&wq->lock, flags);
}

void wait_queue_remove_entry(struct wait_queue_entry *entry) {
    if (!entry || !entry->active || !entry->wq)
        return;
    struct wait_queue *wq = entry->wq;
    bool flags;
    spin_lock_irqsave(&wq->lock, &flags);
    if (entry->active) {
        list_del(&entry->node);
        INIT_LIST_HEAD(&entry->node);
        entry->active = false;
        entry->wq = NULL;
    }
    spin_unlock_irqrestore(&wq->lock, flags);
}

void wait_queue_add(struct wait_queue *wq, struct process *p) {
    if (!p)
        return;
    wait_queue_add_entry(wq, &p->wait_entry);
}

void wait_queue_remove(struct wait_queue *wq __attribute__((unused)),
                       struct process *p) {
    if (!p)
        return;
    wait_queue_remove_entry(&p->wait_entry);
}

static struct wait_queue_entry *wait_queue_pop_one_locked(struct wait_queue *wq,
                                                          bool *single_waiter) {
    struct wait_queue_entry *entry = NULL;
    if (!wq)
        return NULL;

    bool flags;
    spin_lock_irqsave(&wq->lock, &flags);
    if (!list_empty(&wq->head)) {
        entry = list_first_entry(&wq->head, struct wait_queue_entry, node);
        list_del(&entry->node);
        INIT_LIST_HEAD(&entry->node);
        entry->active = false;
        entry->wq = NULL;
        if (single_waiter)
            *single_waiter = list_empty(&wq->head);
    } else if (single_waiter) {
        *single_waiter = false;
    }
    spin_unlock_irqrestore(&wq->lock, flags);
    return entry;
}

void wait_queue_wakeup_one_hint(struct wait_queue *wq, bool direct_switch_hint) {
    bool single_waiter = false;
    struct wait_queue_entry *entry = wait_queue_pop_one_locked(wq, &single_waiter);
    if (!entry || !entry->proc)
        return;
    entry->proc->wait_channel = NULL;
    proc_wakeup_ex(entry->proc, direct_switch_hint && single_waiter);
}

static void wait_queue_wakeup(struct wait_queue *wq, bool all) {
    if (!wq)
        return;

    if (!all) {
        wait_queue_wakeup_one_hint(wq, false);
        return;
    }

    LIST_HEAD(snapshot);
    bool flags;
    spin_lock_irqsave(&wq->lock, &flags);
    while (!list_empty(&wq->head)) {
        struct wait_queue_entry *entry =
            list_first_entry(&wq->head, struct wait_queue_entry, node);
        list_del(&entry->node);
        entry->active = false;
        entry->wq = NULL;
        list_add_tail(&entry->node, &snapshot);
    }
    spin_unlock_irqrestore(&wq->lock, flags);

    while (!list_empty(&snapshot)) {
        struct wait_queue_entry *entry =
            list_first_entry(&snapshot, struct wait_queue_entry, node);
        list_del(&entry->node);
        if (entry->proc) {
            entry->proc->wait_channel = NULL;
            proc_wakeup(entry->proc);
        }
    }
}

void wait_queue_wakeup_one(struct wait_queue *wq) {
    wait_queue_wakeup(wq, false);
}

void wait_queue_wakeup_all(struct wait_queue *wq) {
    wait_queue_wakeup(wq, true);
}
