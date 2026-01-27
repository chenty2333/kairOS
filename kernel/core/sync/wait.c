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

void wait_queue_add(struct wait_queue *wq, struct process *p) {
    spin_lock(&wq->lock);
    if (list_empty(&p->wait_list))
        list_add_tail(&p->wait_list, &wq->head);
    spin_unlock(&wq->lock);
}

void wait_queue_remove(struct wait_queue *wq, struct process *p) {
    spin_lock(&wq->lock);
    if (!list_empty(&p->wait_list)) {
        list_del(&p->wait_list);
        INIT_LIST_HEAD(&p->wait_list);
    }
    spin_unlock(&wq->lock);
}

static void wait_queue_wakeup(struct wait_queue *wq, bool all) {
    while (1) {
        struct process *p = NULL;
        spin_lock(&wq->lock);
        if (!list_empty(&wq->head)) {
            p = list_first_entry(&wq->head, struct process, wait_list);
            list_del(&p->wait_list);
            INIT_LIST_HEAD(&p->wait_list);
        }
        spin_unlock(&wq->lock);
        if (!p)
            break;
        p->wait_channel = NULL;
        proc_wakeup(p);
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
