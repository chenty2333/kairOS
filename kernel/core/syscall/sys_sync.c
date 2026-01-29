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

int64_t sys_futex(uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_ptr,
                  uint64_t uaddr2, uint64_t val3) {
    (void)uaddr2; (void)val3;
    uint32_t cmd = (uint32_t)(op & ~FUTEX_PRIVATE_FLAG);
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
    case FUTEX_WAKE:
        return futex_wake(uaddr, (int)val);
    default:
        return -EINVAL;
    }
}

int64_t sys_sem_init(uint64_t count, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_init((int)count);
}

int64_t sys_sem_wait(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_wait((int)sem_id);
}

int64_t sys_sem_post(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_post((int)sem_id);
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
    if ((int64_t)len < 0) {
        return -EINVAL;
    }

    switch ((int)type) {
    case 2: /* SYSLOG_ACTION_READ */
        return syslog_read_helper(bufp, len, false, false);
    case 3: /* SYSLOG_ACTION_READ_ALL */
        return syslog_read_helper(bufp, len, true, false);
    case 4: /* SYSLOG_ACTION_READ_CLEAR */
        return syslog_read_helper(bufp, len, false, true);
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
