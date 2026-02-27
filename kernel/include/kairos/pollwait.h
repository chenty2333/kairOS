/**
 * kernel/include/kairos/pollwait.h - Poll wait infrastructure
 */

#ifndef _KAIROS_POLLWAIT_H
#define _KAIROS_POLLWAIT_H

#include <kairos/atomic.h>
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
    atomic_t seq;
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

enum poll_wait_stat {
    POLL_WAIT_STAT_EPOLL_WAIT_CALLS = 0,
    POLL_WAIT_STAT_EPOLL_READY_RETURNS,
    POLL_WAIT_STAT_EPOLL_READY_EVENTS,
    POLL_WAIT_STAT_EPOLL_BLOCKS,
    POLL_WAIT_STAT_EPOLL_WAKEUPS,
    POLL_WAIT_STAT_EPOLL_TIMEOUTS,
    POLL_WAIT_STAT_EPOLL_INTERRUPTS,
    POLL_WAIT_STAT_EPOLL_RESCANS,
    POLL_WAIT_STAT_POLL_HEAD_WAKE_CALLS,
    POLL_WAIT_STAT_POLL_HEAD_DIRECT_SWITCH,
    POLL_WAIT_STAT_FDEVENT_EVENTFD_R_BLOCKS,
    POLL_WAIT_STAT_FDEVENT_EVENTFD_W_BLOCKS,
    POLL_WAIT_STAT_FDEVENT_EVENTFD_RD_WAKES,
    POLL_WAIT_STAT_FDEVENT_EVENTFD_WR_WAKES,
    POLL_WAIT_STAT_FDEVENT_TIMERFD_R_BLOCKS,
    POLL_WAIT_STAT_FDEVENT_TIMERFD_RD_WAKES,
    POLL_WAIT_STAT_FDEVENT_SIGNALFD_R_BLOCKS,
    POLL_WAIT_STAT_FDEVENT_SIGNALFD_RD_WAKES,
    POLL_WAIT_STAT_FDEVENT_INOTIFY_R_BLOCKS,
    POLL_WAIT_STAT_FDEVENT_INOTIFY_RD_WAKES,
    POLL_WAIT_STAT_FUTEX_WAIT_BLOCKS,
    POLL_WAIT_STAT_FUTEX_WAIT_WAKES,
    POLL_WAIT_STAT_FUTEX_WAIT_TIMEOUTS,
    POLL_WAIT_STAT_FUTEX_WAIT_INTERRUPTS,
    POLL_WAIT_STAT_FUTEX_WAITV_BLOCKS,
    POLL_WAIT_STAT_FUTEX_WAITV_WAKES,
    POLL_WAIT_STAT_FUTEX_WAITV_TIMEOUTS,
    POLL_WAIT_STAT_FUTEX_WAITV_INTERRUPTS,
    POLL_WAIT_STAT_FUTEX_WAKE_CALLS,
    POLL_WAIT_STAT_FUTEX_WAKE_WOKEN,
    POLL_WAIT_STAT_WAITSRC_SEQ_SKIP_PRE_SLEEP,
    POLL_WAIT_STAT_WAITSRC_SEQ_WAKE_CHANGED,
    POLL_WAIT_STAT_WAITSRC_SEQ_WAKE_UNCHANGED,
    POLL_WAIT_STAT_COUNT,
};

void poll_wait_stat_add(enum poll_wait_stat stat, uint64_t delta);
static inline void poll_wait_stat_inc(enum poll_wait_stat stat) {
    poll_wait_stat_add(stat, 1);
}
uint64_t poll_wait_stat_read(enum poll_wait_stat stat);
const char *poll_wait_stat_name(enum poll_wait_stat stat);
void poll_wait_stats_snapshot(uint64_t out[POLL_WAIT_STAT_COUNT]);
void poll_wait_stats_reset(void);

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
uint32_t poll_wait_source_seq_snapshot(const struct poll_wait_source *src);
int poll_wait_source_block(struct poll_wait_source *src, uint64_t deadline,
                           void *channel, struct mutex *mtx);
int poll_wait_source_block_ex(struct poll_wait_source *src, uint64_t deadline,
                              void *channel, struct mutex *mtx,
                              bool interruptible);
int poll_wait_source_block_seq(struct poll_wait_source *src, uint64_t deadline,
                               void *channel, struct mutex *mtx,
                               uint32_t observed_seq);
int poll_wait_source_block_seq_ex(struct poll_wait_source *src,
                                  uint64_t deadline, void *channel,
                                  struct mutex *mtx, bool interruptible,
                                  uint32_t observed_seq);
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
