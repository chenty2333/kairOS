/**
 * kernel/include/kairos/pollwait.h - Poll wait infrastructure
 */

#ifndef _KAIROS_POLLWAIT_H
#define _KAIROS_POLLWAIT_H

#include <kairos/list.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>

struct process;

struct poll_wait_head {
    spinlock_t lock;
    struct list_head head;
};

struct poll_waiter {
    struct list_head node;
    struct poll_wait_head *head;
    struct process *proc;
    bool active;
};

struct poll_sleep {
    struct list_head node;
    struct process *proc;
    uint64_t deadline;
    bool active;
};

void poll_wait_head_init(struct poll_wait_head *head);
void poll_wait_add(struct poll_wait_head *head, struct poll_waiter *waiter);
void poll_wait_remove(struct poll_waiter *waiter);
void poll_wait_wake(struct poll_wait_head *head);

void poll_sleep_arm(struct poll_sleep *sleep, struct process *proc,
                    uint64_t deadline);
void poll_sleep_cancel(struct poll_sleep *sleep);
void poll_sleep_tick(uint64_t now);

#endif
