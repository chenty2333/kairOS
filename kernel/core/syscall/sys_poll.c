/**
 * kernel/core/syscall/sys_poll.c - Poll/select syscalls
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/select.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#define NS_PER_SEC 1000000000ULL

static int poll_check_fds(struct pollfd *fds, size_t nfds) {
    int ready = 0;
    for (size_t i = 0; i < nfds; i++) {
        fds[i].revents = 0;
        if (fds[i].fd < 0) {
            fds[i].revents = POLLNVAL;
            ready++;
            continue;
        }
        struct file *f = fd_get(proc_current(), fds[i].fd);
        if (!f) {
            fds[i].revents = POLLNVAL;
            ready++;
            continue;
        }
        uint32_t revents = (uint32_t)vfs_poll(f, (uint32_t)fds[i].events);
        fds[i].revents = (short)revents;
        if (revents)
            ready++;
    }
    return ready;
}

static void poll_unregister_waiters(struct poll_waiter *waiters, size_t nfds) {
    if (!waiters)
        return;
    for (size_t i = 0; i < nfds; i++)
        vfs_poll_unregister(&waiters[i]);
}

static void poll_register_waiters(struct pollfd *fds, struct poll_waiter *waiters,
                                  size_t nfds) {
    struct process *curr = proc_current();
    if (!waiters || !curr)
        return;

    for (size_t i = 0; i < nfds; i++) {
        waiters[i].entry.proc = curr;
        if (fds[i].fd < 0 || fds[i].revents)
            continue;
        struct file *f = fd_get(curr, fds[i].fd);
        if (!f)
            continue;
        vfs_poll_register(f, &waiters[i], (uint32_t)fds[i].events);
    }
}

static int poll_wait_kernel(struct pollfd *fds, size_t nfds, int timeout_ms) {
    struct poll_waiter *waiters = kzalloc(nfds * sizeof(*waiters));
    if (!waiters)
        return -ENOMEM;

    uint64_t deadline = 0;
    if (timeout_ms > 0) {
        uint64_t delta = ((uint64_t)timeout_ms * CONFIG_HZ + 999) / 1000;
        if (!delta)
            delta = 1;
        deadline = arch_timer_get_ticks() + delta;
    }

    int ready;
    do {
        poll_unregister_waiters(waiters, nfds);
        poll_register_waiters(fds, waiters, nfds);
        ready = poll_check_fds(fds, nfds);
        if (ready || timeout_ms == 0) {
            poll_unregister_waiters(waiters, nfds);
            break;
        }

        uint64_t now = arch_timer_get_ticks();
        if (deadline && now >= deadline) {
            poll_unregister_waiters(waiters, nfds);
            ready = 0;
            break;
        }

        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        if (deadline)
            poll_sleep_arm(&sleep, proc_current(), deadline);
        (void)proc_sleep_on(NULL, &sleep, true);
        poll_sleep_cancel(&sleep);
    } while (1);

    kfree(waiters);
    return ready;
}

static int timespec_to_timeout_ms(const struct timespec *ts) {
    if (!ts)
        return -1;
    if (ts->tv_sec < 0 || ts->tv_nsec < 0 || ts->tv_nsec >= (int64_t)NS_PER_SEC)
        return -EINVAL;
    uint64_t ms = (uint64_t)ts->tv_sec * 1000 + (uint64_t)ts->tv_nsec / 1000000ULL;
    if (ms > 0x7fffffff)
        return 0x7fffffff;
    return (int)ms;
}

int64_t sys_poll(uint64_t fds_ptr, uint64_t nfds, uint64_t timeout_ms,
                 uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (nfds == 0)
        return 0;
    if (!fds_ptr)
        return -EFAULT;
    if (nfds > SIZE_MAX / sizeof(struct pollfd))
        return -EINVAL;

    size_t bytes = (size_t)nfds * sizeof(struct pollfd);
    struct pollfd *kfds = kmalloc(bytes);
    if (!kfds)
        return -ENOMEM;
    if (copy_from_user(kfds, (void *)fds_ptr, bytes) < 0) {
        kfree(kfds);
        return -EFAULT;
    }

    int64_t tmo = (int64_t)timeout_ms;
    if (tmo < -1)
        tmo = -1;
    const int64_t tmo_max = 0x7fffffffLL;
    if (tmo > tmo_max)
        tmo = tmo_max;
    int ready = poll_wait_kernel(kfds, (size_t)nfds, (int)tmo);
    if (ready < 0) {
        kfree(kfds);
        return ready;
    }

    if (copy_to_user((void *)fds_ptr, kfds, bytes) < 0) {
        kfree(kfds);
        return -EFAULT;
    }
    kfree(kfds);
    return ready;
}

static int do_select_common(uint64_t nfds, uint64_t readfds_ptr,
                            uint64_t writefds_ptr, int timeout_ms) {
    if (nfds > FD_SETSIZE)
        return -EINVAL;

    fd_set rfds = {0}, wfds = {0};
    if (readfds_ptr &&
        copy_from_user(&rfds, (void *)readfds_ptr, sizeof(rfds)) < 0)
        return -EFAULT;
    if (writefds_ptr &&
        copy_from_user(&wfds, (void *)writefds_ptr, sizeof(wfds)) < 0)
        return -EFAULT;

    struct pollfd fds[FD_SETSIZE];
    size_t count = 0;
    for (uint64_t fd = 0; fd < nfds; fd++) {
        uint64_t mask = 1ULL << fd;
        short events = 0;
        if (readfds_ptr && (rfds.bits & mask))
            events |= POLLIN;
        if (writefds_ptr && (wfds.bits & mask))
            events |= POLLOUT;
        if (events) {
            fds[count].fd = (int)fd;
            fds[count].events = events;
            fds[count].revents = 0;
            count++;
        }
    }

    if (count == 0)
        return 0;

    int ready = poll_wait_kernel(fds, count, timeout_ms);
    if (ready < 0)
        return ready;

    if (readfds_ptr)
        rfds.bits = 0;
    if (writefds_ptr)
        wfds.bits = 0;
    for (size_t i = 0; i < count; i++) {
        if (fds[i].revents & POLLIN)
            rfds.bits |= (1ULL << fds[i].fd);
        if (fds[i].revents & POLLOUT)
            wfds.bits |= (1ULL << fds[i].fd);
    }

    if (readfds_ptr &&
        copy_to_user((void *)readfds_ptr, &rfds, sizeof(rfds)) < 0)
        ready = -EFAULT;
    if (writefds_ptr &&
        copy_to_user((void *)writefds_ptr, &wfds, sizeof(wfds)) < 0)
        ready = -EFAULT;

    return ready;
}

int64_t sys_select(uint64_t nfds, uint64_t readfds_ptr, uint64_t writefds_ptr,
                   uint64_t exceptfds_ptr, uint64_t timeout_ptr, uint64_t a5) {
    (void)exceptfds_ptr; (void)a5;

    int timeout_ms = -1;
    if (timeout_ptr) {
        struct timeval tv;
        if (copy_from_user(&tv, (void *)timeout_ptr, sizeof(tv)) < 0)
            return -EFAULT;
        if (tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= 1000000)
            return -EINVAL;
        timeout_ms = (int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
    }

    return do_select_common(nfds, readfds_ptr, writefds_ptr, timeout_ms);
}

int64_t sys_ppoll(uint64_t fds_ptr, uint64_t nfds, uint64_t tsp_ptr,
                  uint64_t sigmask_ptr, uint64_t sigsetsize,
                  uint64_t a5) {
    (void)sigmask_ptr; (void)sigsetsize; (void)a5;
    int timeout_ms = -1;
    if (tsp_ptr) {
        struct timespec ts;
        if (copy_from_user(&ts, (void *)tsp_ptr, sizeof(ts)) < 0)
            return -EFAULT;
        int rc = timespec_to_timeout_ms(&ts);
        if (rc < 0)
            return rc;
        timeout_ms = rc;
    }
    return sys_poll(fds_ptr, nfds, (uint64_t)timeout_ms, 0, 0, 0);
}

int64_t sys_pselect6(uint64_t nfds, uint64_t readfds_ptr,
                     uint64_t writefds_ptr, uint64_t exceptfds_ptr,
                     uint64_t timeout_ptr, uint64_t sigmask_ptr) {
    (void)exceptfds_ptr; (void)sigmask_ptr;
    int timeout_ms = -1;
    if (timeout_ptr) {
        struct timespec ts;
        if (copy_from_user(&ts, (void *)timeout_ptr, sizeof(ts)) < 0)
            return -EFAULT;
        int rc = timespec_to_timeout_ms(&ts);
        if (rc < 0)
            return rc;
        timeout_ms = rc;
    }
    return do_select_common(nfds, readfds_ptr, writefds_ptr, timeout_ms);
}
