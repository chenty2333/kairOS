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
    spin_lock(&wq->lock);
    if (!entry->active) {
        entry->wq = wq;
        entry->active = true;
        list_add_tail(&entry->node, &wq->head);
    }
    spin_unlock(&wq->lock);
}

void wait_queue_remove_entry(struct wait_queue_entry *entry) {
    if (!entry || !entry->active || !entry->wq)
        return;
    struct wait_queue *wq = entry->wq;
    spin_lock(&wq->lock);
    if (entry->active) {
        list_del(&entry->node);
        INIT_LIST_HEAD(&entry->node);
        entry->active = false;
        entry->wq = NULL;
    }
    spin_unlock(&wq->lock);
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
    while (1) {
        struct wait_queue_entry *entry = NULL;
        spin_lock(&wq->lock);
        if (!list_empty(&wq->head)) {
            entry = list_first_entry(&wq->head, struct wait_queue_entry, node);
            list_del(&entry->node);
            INIT_LIST_HEAD(&entry->node);
            entry->active = false;
            entry->wq = NULL;
        }
        spin_unlock(&wq->lock);
        if (!entry)
            break;
        if (entry->proc) {
            entry->proc->wait_channel = NULL;
            proc_wakeup(entry->proc);
        }
        if (!all)
            break;
    }
}

void wait_queue_wakeup_one(struct wait_queue *wq) {
    wait_queue_wakeup(wq, false);
}

void wait_queue_wakeup_all(struct wait_queue *wq) {
    wait_queue_wakeup(wq, true);
}
