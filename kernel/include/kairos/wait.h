/**
 * kernel/include/kairos/wait.h - Wait Queue interface
 */

#ifndef _KAIROS_WAIT_H
#define _KAIROS_WAIT_H

#include <kairos/list.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>

struct process;

struct wait_queue {
    spinlock_t lock;
    struct list_head head;
};

struct wait_queue_entry {
    struct list_head node;
    struct wait_queue *wq;
    struct process *proc;
    bool active;
};

void wait_queue_init(struct wait_queue *wq);
void wait_queue_entry_init(struct wait_queue_entry *entry, struct process *p);
void wait_queue_add_entry(struct wait_queue *wq, struct wait_queue_entry *entry);
void wait_queue_remove_entry(struct wait_queue_entry *entry);
void wait_queue_add(struct wait_queue *wq, struct process *p);
void wait_queue_remove(struct wait_queue *wq, struct process *p);
void wait_queue_wakeup_one(struct wait_queue *wq);
void wait_queue_wakeup_all(struct wait_queue *wq);

#endif
