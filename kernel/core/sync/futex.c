/**
 * kernel/core/sync/futex.c - Minimal futex implementation (WAIT/WAKE)
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/futex.h>
#include <kairos/pollwait.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>

#define FUTEX_BUCKETS 128
#define NS_PER_SEC 1000000000ULL

struct futex_waiter;

struct futex_bucket {
    struct mutex lock;
    struct list_head waiters;
};

struct futex_waiter {
    struct list_head node;
    struct futex_bucket *bucket;
    struct process *proc;
    vaddr_t uaddr;
    bool active;
    bool woken;
};

static struct futex_bucket futex_buckets[FUTEX_BUCKETS];
static bool futex_ready;

static inline size_t futex_hash(vaddr_t uaddr) {
    uint64_t x = (uint64_t)uaddr >> 2;
    /* Simple multiplicative hash, good enough for a hobby kernel. */
    return (size_t)((x * 11400714819323198485ull) % FUTEX_BUCKETS);
}

static struct futex_bucket *futex_bucket_for(vaddr_t uaddr) {
    return &futex_buckets[futex_hash(uaddr)];
}

static int futex_read_u32(vaddr_t uaddr, uint32_t *out) {
    uint32_t val = 0;
    if (copy_from_user(&val, (const void *)uaddr, sizeof(val)) < 0)
        return -EFAULT;
    *out = val;
    return 0;
}

static uint64_t timespec_to_ticks(const struct timespec *ts) {
    if (!ts)
        return 0;
    if (ts->tv_sec < 0 || ts->tv_nsec < 0 || ts->tv_nsec >= (int64_t)NS_PER_SEC)
        return UINT64_MAX;

    uint64_t sec = (uint64_t)ts->tv_sec;
    uint64_t nsec = (uint64_t)ts->tv_nsec;
    uint64_t ns = sec * NS_PER_SEC + nsec;
    uint64_t ticks = (ns * CONFIG_HZ + NS_PER_SEC - 1) / NS_PER_SEC;
    return ticks ? ticks : 1;
}

static void futex_waiter_remove(struct futex_waiter *waiter) {
    if (!waiter || !waiter->active || !waiter->bucket)
        return;

    struct futex_bucket *bucket = waiter->bucket;
    mutex_lock(&bucket->lock);
    if (waiter->active) {
        list_del(&waiter->node);
        waiter->active = false;
    }
    mutex_unlock(&bucket->lock);
}

void futex_init(void) {
    if (futex_ready)
        return;
    for (size_t i = 0; i < FUTEX_BUCKETS; i++) {
        mutex_init(&futex_buckets[i].lock, "futex_bucket");
        INIT_LIST_HEAD(&futex_buckets[i].waiters);
    }
    futex_ready = true;
}

int futex_wait(uint64_t uaddr_u64, uint32_t val, const struct timespec *timeout) {
    if (!futex_ready)
        futex_init();

    vaddr_t uaddr = (vaddr_t)uaddr_u64;
    if ((uaddr & (sizeof(uint32_t) - 1)) != 0)
        return -EINVAL;

    uint32_t cur = 0;
    int rc = futex_read_u32(uaddr, &cur);
    if (rc < 0)
        return rc;
    if (cur != val)
        return -EAGAIN;

    uint64_t delta = timespec_to_ticks(timeout);
    if (delta == UINT64_MAX)
        return -EINVAL;

    struct process *curr = proc_current();
    struct futex_waiter waiter = {0};
    INIT_LIST_HEAD(&waiter.node);
    waiter.bucket = futex_bucket_for(uaddr);
    waiter.proc = curr;
    waiter.uaddr = uaddr;
    waiter.active = false;
    waiter.woken = false;

    uint64_t deadline = 0;
    if (delta)
        deadline = arch_timer_get_ticks() + delta;

    while (1) {
        mutex_lock(&waiter.bucket->lock);
        if (!waiter.active) {
            list_add_tail(&waiter.node, &waiter.bucket->waiters);
            waiter.active = true;
        }

        rc = futex_read_u32(uaddr, &cur);
        if (rc < 0 || cur != val) {
            if (waiter.active) {
                list_del(&waiter.node);
                waiter.active = false;
            }
            mutex_unlock(&waiter.bucket->lock);
            return (rc < 0) ? rc : -EAGAIN;
        }

        curr->state = PROC_SLEEPING;
        curr->wait_channel = (void *)uaddr;
        mutex_unlock(&waiter.bucket->lock);

        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        if (deadline)
            poll_sleep_arm(&sleep, curr, deadline);
        schedule();
        poll_sleep_cancel(&sleep);

        if (waiter.woken)
            return 0;

        if (curr->sig_pending) {
            futex_waiter_remove(&waiter);
            return -EINTR;
        }

        if (deadline && arch_timer_get_ticks() >= deadline) {
            futex_waiter_remove(&waiter);
            return -ETIMEDOUT;
        }
        /* Spurious wakeup: retry. */
    }
}

int futex_wake(uint64_t uaddr_u64, int nr_wake) {
    if (!futex_ready)
        futex_init();
    if (nr_wake <= 0)
        return 0;

    vaddr_t uaddr = (vaddr_t)uaddr_u64;
    struct futex_bucket *bucket = futex_bucket_for(uaddr);

    LIST_HEAD(wake_list);
    int woken = 0;

    mutex_lock(&bucket->lock);
    struct futex_waiter *waiter, *tmp;
    list_for_each_entry_safe(waiter, tmp, &bucket->waiters, node) {
        if (!waiter->active || waiter->uaddr != uaddr)
            continue;
        list_del(&waiter->node);
        waiter->active = false;
        waiter->woken = true;
        list_add_tail(&waiter->node, &wake_list);
        woken++;
        if (woken >= nr_wake)
            break;
    }
    mutex_unlock(&bucket->lock);

    list_for_each_entry_safe(waiter, tmp, &wake_list, node) {
        list_del(&waiter->node);
        if (waiter->proc)
            proc_wakeup(waiter->proc);
    }

    return woken;
}
