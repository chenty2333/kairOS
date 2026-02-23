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

static void wait_queue_wakeup(struct wait_queue *wq, bool all) {
    if (!wq)
        return;

    if (!all) {
        struct wait_queue_entry *entry = NULL;
        bool flags;
        spin_lock_irqsave(&wq->lock, &flags);
        if (!list_empty(&wq->head)) {
            entry = list_first_entry(&wq->head, struct wait_queue_entry, node);
            list_del(&entry->node);
            INIT_LIST_HEAD(&entry->node);
            entry->active = false;
            entry->wq = NULL;
        }
        spin_unlock_irqrestore(&wq->lock, flags);
        if (entry && entry->proc) {
            entry->proc->wait_channel = NULL;
            proc_wakeup(entry->proc);
        }
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
