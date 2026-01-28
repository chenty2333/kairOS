/**
 * kernel/core/syscall/sys_sync.c - Synchronization-related syscalls
 */

#include <kairos/config.h>
#include <kairos/futex.h>
#include <kairos/uaccess.h>

extern int do_sem_init(int count);
extern int do_sem_wait(int sem_id);
extern int do_sem_post(int sem_id);

#define NS_PER_SEC 1000000000ULL

static int copy_timespec_from_user(uint64_t ptr, struct timespec *out) {
    if (!ptr || !out)
        return 0;
    if (copy_from_user(out, (const void *)ptr, sizeof(*out)) < 0)
        return -EFAULT;
    if (out->tv_sec < 0 || out->tv_nsec < 0 || out->tv_nsec >= (int64_t)NS_PER_SEC)
        return -EINVAL;
    return 1;
}

int64_t sys_futex(uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_ptr,
                  uint64_t uaddr2, uint64_t val3) {
    (void)uaddr2; (void)val3;
    uint32_t cmd = (uint32_t)(op & ~FUTEX_PRIVATE_FLAG);
    switch (cmd) {
    case FUTEX_WAIT: {
        struct timespec ts;
        struct timespec *tsp = NULL;
        int rc = copy_timespec_from_user(timeout_ptr, &ts);
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
