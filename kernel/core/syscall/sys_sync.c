/**
 * kernel/core/syscall/sys_sync.c - Synchronization-related syscalls
 */

#include <kairos/config.h>
#include <kairos/futex.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/uaccess.h>

#include "sys_time_helpers.h"

extern int do_sem_init(int count);
extern int do_sem_wait(int sem_id);
extern int do_sem_post(int sem_id);

static inline int syssync_abi_int32(uint64_t v) {
    return (int32_t)(uint32_t)v;
}

int64_t sys_futex(uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_ptr,
                  uint64_t uaddr2, uint64_t val3) {
    (void)uaddr2; (void)val3;
    uint32_t uop = (uint32_t)op;
    uint32_t cmd = uop & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    switch (cmd) {
    case FUTEX_WAIT: {
        struct timespec ts;
        struct timespec *tsp = NULL;
        int rc = sys_copy_timespec(timeout_ptr, &ts, true);
        if (rc < 0)
            return rc;
        if (rc > 0)
            tsp = &ts;
        return futex_wait(uaddr, (uint32_t)val, tsp);
    }
    case FUTEX_WAIT_BITSET: {
        struct timespec ts;
        struct timespec *tsp = NULL;
        if ((uint32_t)val3 == 0)
            return -EINVAL;
        int rc = sys_copy_timespec(timeout_ptr, &ts, true);
        if (rc < 0)
            return rc;
        if (rc > 0)
            tsp = &ts;
        return futex_wait(uaddr, (uint32_t)val, tsp);
    }
    case FUTEX_WAKE:
        return futex_wake(uaddr, (int32_t)(uint32_t)val);
    case FUTEX_WAKE_BITSET:
        if ((uint32_t)val3 == 0)
            return -EINVAL;
        return futex_wake(uaddr, (int32_t)(uint32_t)val);
    default:
        return -EINVAL;
    }
}

int64_t sys_futex_waitv(uint64_t waiters_ptr, uint64_t nr_futexes, uint64_t flags,
                        uint64_t timeout_ptr, uint64_t clockid, uint64_t a5) {
    (void)a5;
    uint32_t uflags = (uint32_t)flags;
    if (uflags != 0)
        return -EINVAL;
    if (!waiters_ptr)
        return -EFAULT;
    if (nr_futexes == 0 || nr_futexes > FUTEX_WAITV_MAX)
        return -EINVAL;

    if (nr_futexes > SIZE_MAX / sizeof(struct futex_waitv))
        return -EINVAL;
    size_t bytes = (size_t)nr_futexes * sizeof(struct futex_waitv);
    struct futex_waitv *waiters = kmalloc(bytes);
    if (!waiters)
        return -ENOMEM;
    if (copy_from_user(waiters, (const void *)waiters_ptr, bytes) < 0) {
        kfree(waiters);
        return -EFAULT;
    }

    struct timespec ts = {0};
    struct timespec *tsp = NULL;
    if (timeout_ptr) {
        if (copy_from_user(&ts, (const void *)timeout_ptr, sizeof(ts)) < 0) {
            kfree(waiters);
            return -EFAULT;
        }
        tsp = &ts;
    }

    int rc = futex_waitv(waiters, (uint32_t)nr_futexes, tsp,
                         (int32_t)(uint32_t)clockid);
    kfree(waiters);
    return rc;
}

int64_t sys_sem_init(uint64_t count, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_init(syssync_abi_int32(count));
}

int64_t sys_sem_wait(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_wait(syssync_abi_int32(sem_id));
}

int64_t sys_sem_post(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_post(syssync_abi_int32(sem_id));
}

static int64_t syslog_read_helper(uint64_t bufp, uint64_t len, bool all,
                                   bool clear)
{
    if (!bufp || !len) {
        return -EINVAL;
    }
    char *kbuf = kmalloc((size_t)len);
    if (!kbuf) {
        return -ENOMEM;
    }
    ssize_t n;
    if (all) {
        n = klog_read_all(kbuf, (size_t)len);
    } else {
        n = klog_read(kbuf, (size_t)len, clear);
    }
    if (n > 0 && copy_to_user((void *)bufp, kbuf, (size_t)n) < 0) {
        kfree(kbuf);
        return -EFAULT;
    }
    kfree(kbuf);
    return n;
}

int64_t sys_syslog(uint64_t type, uint64_t bufp, uint64_t len, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int32_t utype = (int32_t)(uint32_t)type;
    int32_t ulen = (int32_t)(uint32_t)len;
    if (ulen < 0) {
        return -EINVAL;
    }

    switch (utype) {
    case 2: /* SYSLOG_ACTION_READ */
        return syslog_read_helper(bufp, (uint32_t)ulen, false, false);
    case 3: /* SYSLOG_ACTION_READ_ALL */
        return syslog_read_helper(bufp, (uint32_t)ulen, true, false);
    case 4: /* SYSLOG_ACTION_READ_CLEAR */
        return syslog_read_helper(bufp, (uint32_t)ulen, false, true);
    case 5: /* SYSLOG_ACTION_CLEAR */
        klog_clear();
        return 0;
    case 6: /* SYSLOG_ACTION_CONSOLE_OFF */
    case 7: /* SYSLOG_ACTION_CONSOLE_ON */
    case 8: /* SYSLOG_ACTION_CONSOLE_LEVEL */
        return 0;
    case 9: /* SYSLOG_ACTION_SIZE_UNREAD */
        return (int64_t)klog_size_unread();
    case 10: /* SYSLOG_ACTION_SIZE_BUFFER */
        return (int64_t)klog_size_buffer();
    default:
        return -EINVAL;
    }
}

int64_t sys_sync(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return 0;
}
