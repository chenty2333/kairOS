/**
 * kernel/include/kairos/pollwait.h - Poll wait infrastructure
 */

#ifndef _KAIROS_POLLWAIT_H
#define _KAIROS_POLLWAIT_H

#include <kairos/list.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>
#include <kairos/wait.h>

struct process;
struct mutex;
struct vnode;

struct poll_wait_head {
    struct wait_queue wq;
    struct list_head watches;
};

struct poll_wait_source {
    struct wait_queue wq;
    struct vnode *vn;
};

struct poll_waiter {
    struct wait_queue_entry entry;
    struct poll_wait_head *head;
    struct vnode *vn;
};

struct poll_watch {
    struct list_head node;
    struct list_head notify_node;
    struct poll_wait_head *head;
    void (*prepare)(struct poll_watch *watch);
    void (*notify)(struct poll_watch *watch, uint32_t events);
    uint32_t events;
    void *data;
    bool active;
    bool notifying;
};

struct poll_sleep {
    struct list_head node;
    struct process *proc;
    uint64_t deadline;
    bool active;
};

int poll_timeout_to_deadline_ms(int timeout_ms, uint64_t *deadline_out);
bool poll_deadline_expired(uint64_t deadline);
int poll_block_current_ex(struct wait_queue *wq, uint64_t deadline,
                          void *channel, struct mutex *mtx,
                          bool interruptible);
int poll_block_current(uint64_t deadline, void *channel);
int poll_block_current_mutex(struct wait_queue *wq, uint64_t deadline,
                             void *channel, struct mutex *mtx);

void poll_ready_wake_one(struct wait_queue *wq, struct vnode *vn,
                         uint32_t events);
void poll_ready_wake_all(struct wait_queue *wq, struct vnode *vn,
                         uint32_t events);
void poll_wait_source_init(struct poll_wait_source *src, struct vnode *vn);
void poll_wait_source_set_vnode(struct poll_wait_source *src, struct vnode *vn);
int poll_wait_source_block(struct poll_wait_source *src, uint64_t deadline,
                           void *channel, struct mutex *mtx);
void poll_wait_source_wake_one(struct poll_wait_source *src, uint32_t events);
void poll_wait_source_wake_all(struct poll_wait_source *src, uint32_t events);

void poll_wait_head_init(struct poll_wait_head *head);
void poll_wait_add(struct poll_wait_head *head, struct poll_waiter *waiter);
void poll_wait_remove(struct poll_waiter *waiter);
void poll_wait_wake(struct poll_wait_head *head, uint32_t events);

void poll_watch_add(struct poll_wait_head *head, struct poll_watch *watch);
void poll_watch_remove(struct poll_watch *watch);

void poll_sleep_arm(struct poll_sleep *sleep, struct process *proc,
                    uint64_t deadline);
void poll_sleep_cancel(struct poll_sleep *sleep);
void poll_sleep_tick(uint64_t now);

#endif
