/**
 * kernel/core/sync/futex.c - Minimal futex implementation (WAIT/WAKE)
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/futex.h>
#include <kairos/mm.h>
#include <kairos/pollwait.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/time.h>
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
    struct poll_wait_source *wait_src;
    struct mutex *wait_lock;
    vaddr_t uaddr;
    int index;
    int *wake_index;
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

static int futex_abs_timeout_deadline(const struct timespec *ts, int clockid,
                                      uint64_t *deadline) {
    if (!ts || !deadline)
        return -EINVAL;
    if (ts->tv_sec < 0 || ts->tv_nsec < 0 || ts->tv_nsec >= (int64_t)NS_PER_SEC)
        return -EINVAL;
    if (clockid != CLOCK_MONOTONIC && clockid != CLOCK_REALTIME)
        return -EINVAL;

    uint64_t sec = (uint64_t)ts->tv_sec;
    if (sec > UINT64_MAX / NS_PER_SEC)
        return -EINVAL;
    uint64_t abs_ns = sec * NS_PER_SEC + (uint64_t)ts->tv_nsec;

    uint64_t now_ns = (clockid == CLOCK_REALTIME) ? time_realtime_ns()
                                                  : time_now_ns();
    uint64_t now_ticks = arch_timer_get_ticks();
    if (abs_ns <= now_ns) {
        *deadline = now_ticks;
        return 0;
    }

    uint64_t delta_ns = abs_ns - now_ns;
    uint64_t delta_ticks;
    if (delta_ns > (UINT64_MAX - (NS_PER_SEC - 1)) / CONFIG_HZ) {
        delta_ticks = UINT64_MAX;
    } else {
        delta_ticks = (delta_ns * CONFIG_HZ + NS_PER_SEC - 1) / NS_PER_SEC;
    }
    if (!delta_ticks)
        delta_ticks = 1;
    if (UINT64_MAX - now_ticks < delta_ticks)
        *deadline = UINT64_MAX;
    else
        *deadline = now_ticks + delta_ticks;
    return 0;
}

static inline void futex_waiter_dequeue_locked(struct futex_waiter *waiter) {
    if (!waiter || !waiter->active)
        return;
    list_del(&waiter->node);
    waiter->active = false;
}

static void futex_waiter_remove(struct futex_waiter *waiter) {
    if (!waiter || !waiter->active || !waiter->bucket)
        return;

    struct futex_bucket *bucket = waiter->bucket;
    mutex_lock(&bucket->lock);
    futex_waiter_dequeue_locked(waiter);
    mutex_unlock(&bucket->lock);
}

static void futex_waiters_remove_all(struct futex_waiter *waiters,
                                     uint32_t nr_waiters) {
    if (!waiters)
        return;
    for (uint32_t i = 0; i < nr_waiters; i++)
        futex_waiter_remove(&waiters[i]);
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

    struct poll_wait_source wait_src;
    poll_wait_source_init(&wait_src, NULL);
    struct futex_waiter waiter = {0};
    INIT_LIST_HEAD(&waiter.node);
    waiter.bucket = futex_bucket_for(uaddr);
    waiter.wait_src = &wait_src;
    waiter.uaddr = uaddr;
    waiter.index = -1;
    waiter.wake_index = NULL;
    waiter.wait_lock = NULL;
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
            futex_waiter_dequeue_locked(&waiter);
            mutex_unlock(&waiter.bucket->lock);
            return (rc < 0) ? rc : -EAGAIN;
        }

        poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAIT_BLOCKS);
        int sleep_rc = poll_wait_source_block(&wait_src, deadline, (void *)uaddr,
                                              &waiter.bucket->lock);

        if (waiter.woken) {
            poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAIT_WAKES);
            futex_waiter_dequeue_locked(&waiter);
            mutex_unlock(&waiter.bucket->lock);
            return 0;
        }

        if (sleep_rc == -EINTR) {
            poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAIT_INTERRUPTS);
            futex_waiter_dequeue_locked(&waiter);
            mutex_unlock(&waiter.bucket->lock);
            return -EINTR;
        }

        if (sleep_rc == -ETIMEDOUT ||
            (deadline && arch_timer_get_ticks() >= deadline)) {
            poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAIT_TIMEOUTS);
            futex_waiter_dequeue_locked(&waiter);
            mutex_unlock(&waiter.bucket->lock);
            return -ETIMEDOUT;
        }
        if (sleep_rc < 0) {
            futex_waiter_dequeue_locked(&waiter);
            mutex_unlock(&waiter.bucket->lock);
            return sleep_rc;
        }
        mutex_unlock(&waiter.bucket->lock);
        /* Spurious wakeup: retry. */
    }
}

int futex_wake(uint64_t uaddr_u64, int nr_wake) {
    if (!futex_ready)
        futex_init();
    poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAKE_CALLS);
    if (nr_wake <= 0)
        return 0;

    vaddr_t uaddr = (vaddr_t)uaddr_u64;
    if ((uaddr & (sizeof(uint32_t) - 1)) != 0)
        return -EINVAL;
    struct futex_bucket *bucket = futex_bucket_for(uaddr);

    int woken = 0;

    mutex_lock(&bucket->lock);
    struct futex_waiter *waiter, *tmp;
    list_for_each_entry_safe(waiter, tmp, &bucket->waiters, node) {
        if (!waiter->active || waiter->uaddr != uaddr)
            continue;
        futex_waiter_dequeue_locked(waiter);
        waiter->woken = true;
        struct mutex *wait_lock = waiter->wait_lock;
        if (wait_lock)
            mutex_lock(wait_lock);
        if (waiter->wake_index && waiter->index >= 0) {
            int expected = -1;
            (void)__atomic_compare_exchange_n(waiter->wake_index, &expected,
                                              waiter->index, false,
                                              __ATOMIC_ACQ_REL,
                                              __ATOMIC_ACQUIRE);
        }
        if (waiter->wait_src)
            poll_wait_source_wake_one(waiter->wait_src, 0);
        if (wait_lock)
            mutex_unlock(wait_lock);
        woken++;
        if (woken >= nr_wake)
            break;
    }
    mutex_unlock(&bucket->lock);

    poll_wait_stat_add(POLL_WAIT_STAT_FUTEX_WAKE_WOKEN, (uint64_t)woken);
    return woken;
}

int futex_waitv(const struct futex_waitv *waiters, uint32_t nr_waiters,
                const struct timespec *timeout, int clockid) {
    if (!futex_ready)
        futex_init();
    if (!waiters || nr_waiters == 0 || nr_waiters > FUTEX_WAITV_MAX)
        return -EINVAL;

    uint64_t deadline = 0;
    if (timeout) {
        int rc = futex_abs_timeout_deadline(timeout, clockid, &deadline);
        if (rc < 0)
            return rc;
        if (arch_timer_get_ticks() >= deadline)
            return -ETIMEDOUT;
    }

    if (!proc_current())
        return -EINVAL;
    struct poll_wait_source wait_src;
    poll_wait_source_init(&wait_src, NULL);

    struct futex_waiter *kwaiters =
        kzalloc((size_t)nr_waiters * sizeof(*kwaiters));
    if (!kwaiters)
        return -ENOMEM;

    int wake_index = -1;
    struct mutex wait_lock;
    mutex_init(&wait_lock, "futex_waitv_lock");
    for (uint32_t i = 0; i < nr_waiters; i++) {
        const struct futex_waitv *w = &waiters[i];
        if (w->__reserved != 0) {
            kfree(kwaiters);
            return -EINVAL;
        }
        if ((w->flags & ~FUTEX_PRIVATE_FLAG) != FUTEX_32) {
            kfree(kwaiters);
            return -EINVAL;
        }

        vaddr_t uaddr = (vaddr_t)w->uaddr;
        if ((uaddr & (sizeof(uint32_t) - 1)) != 0) {
            kfree(kwaiters);
            return -EINVAL;
        }

        uint32_t cur = 0;
        int rc = futex_read_u32(uaddr, &cur);
        if (rc < 0) {
            kfree(kwaiters);
            return rc;
        }
        if (cur != (uint32_t)w->val) {
            kfree(kwaiters);
            return -EAGAIN;
        }

        INIT_LIST_HEAD(&kwaiters[i].node);
        kwaiters[i].bucket = futex_bucket_for(uaddr);
        kwaiters[i].wait_src = &wait_src;
        kwaiters[i].uaddr = uaddr;
        kwaiters[i].index = (int)i;
        kwaiters[i].wake_index = &wake_index;
        kwaiters[i].wait_lock = &wait_lock;
        kwaiters[i].active = false;
        kwaiters[i].woken = false;
    }

    while (1) {
        for (uint32_t i = 0; i < nr_waiters; i++) {
            struct futex_waiter *waiter = &kwaiters[i];
            mutex_lock(&waiter->bucket->lock);
            if (!waiter->active) {
                list_add_tail(&waiter->node, &waiter->bucket->waiters);
                waiter->active = true;
            }
            mutex_unlock(&waiter->bucket->lock);
        }

        for (uint32_t i = 0; i < nr_waiters; i++) {
            uint32_t cur = 0;
            int rc = futex_read_u32(kwaiters[i].uaddr, &cur);
            if (rc < 0 || cur != (uint32_t)waiters[i].val) {
                futex_waiters_remove_all(kwaiters, nr_waiters);
                kfree(kwaiters);
                return (rc < 0) ? rc : -EAGAIN;
            }
        }

        mutex_lock(&wait_lock);
        int idx = __atomic_load_n(&wake_index, __ATOMIC_ACQUIRE);
        if (idx >= 0) {
            mutex_unlock(&wait_lock);
            poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAITV_WAKES);
            futex_waiters_remove_all(kwaiters, nr_waiters);
            kfree(kwaiters);
            return idx;
        }

        if (deadline && arch_timer_get_ticks() >= deadline) {
            mutex_unlock(&wait_lock);
            poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAITV_TIMEOUTS);
            futex_waiters_remove_all(kwaiters, nr_waiters);
            kfree(kwaiters);
            return -ETIMEDOUT;
        }

        poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAITV_BLOCKS);
        int sleep_rc =
            poll_wait_source_block(&wait_src, deadline, kwaiters, &wait_lock);

        idx = __atomic_load_n(&wake_index, __ATOMIC_ACQUIRE);
        if (idx >= 0) {
            mutex_unlock(&wait_lock);
            poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAITV_WAKES);
            futex_waiters_remove_all(kwaiters, nr_waiters);
            kfree(kwaiters);
            return idx;
        }
        if (sleep_rc == -EINTR) {
            mutex_unlock(&wait_lock);
            poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAITV_INTERRUPTS);
            futex_waiters_remove_all(kwaiters, nr_waiters);
            kfree(kwaiters);
            return -EINTR;
        }
        if (sleep_rc == -ETIMEDOUT ||
            (deadline && arch_timer_get_ticks() >= deadline)) {
            mutex_unlock(&wait_lock);
            poll_wait_stat_inc(POLL_WAIT_STAT_FUTEX_WAITV_TIMEOUTS);
            futex_waiters_remove_all(kwaiters, nr_waiters);
            kfree(kwaiters);
            return -ETIMEDOUT;
        }
        if (sleep_rc < 0) {
            mutex_unlock(&wait_lock);
            futex_waiters_remove_all(kwaiters, nr_waiters);
            kfree(kwaiters);
            return sleep_rc;
        }
        mutex_unlock(&wait_lock);
    }
}
