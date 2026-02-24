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
#define SIG_UNBLOCKABLE_MASK \
    ((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)))

struct poll_sigmask_ctx {
    struct process *proc;
    sigset_t old_mask;
    bool active;
};

static sigset_t poll_sanitize_sigmask(sigset_t mask) {
    return mask & ~SIG_UNBLOCKABLE_MASK;
}

static int poll_sigmask_apply(const sigset_t *new_mask,
                              struct poll_sigmask_ctx *ctx) {
    if (!new_mask || !ctx)
        return -EINVAL;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    ctx->proc = p;
    ctx->old_mask = p->sig_blocked;
    p->sig_blocked = poll_sanitize_sigmask(*new_mask);
    ctx->active = true;
    return 0;
}

static void poll_sigmask_restore(struct poll_sigmask_ctx *ctx) {
    if (!ctx || !ctx->active || !ctx->proc)
        return;
    ctx->proc->sig_blocked = ctx->old_mask;
    ctx->active = false;
}

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
        file_put(f);
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
        /*
         * Ignore user-provided revents bits when arming waiters. Those bits
         * are output-only and may contain stale data from previous polls.
         */
        if (fds[i].fd < 0)
            continue;
        struct file *f = fd_get(curr, fds[i].fd);
        if (!f)
            continue;
        vfs_poll_register(f, &waiters[i], (uint32_t)fds[i].events);
        file_put(f);
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
        int rc = proc_sleep_on(NULL, &sleep, true);
        poll_sleep_cancel(&sleep);
        if (rc == -EINTR) {
            poll_unregister_waiters(waiters, nfds);
            kfree(waiters);
            return -EINTR;
        }
    } while (1);

    kfree(waiters);
    return ready;
}

static int timespec_to_timeout_ms(const struct timespec *ts) {
    if (!ts)
        return -1;
    if (ts->tv_sec < 0 || ts->tv_nsec < 0 || ts->tv_nsec >= (int64_t)NS_PER_SEC)
        return -EINVAL;
    uint64_t sec = (uint64_t)ts->tv_sec;
    if (sec > UINT64_MAX / 1000ULL)
        return 0x7fffffff;
    uint64_t ms = sec * 1000ULL +
                  ((uint64_t)ts->tv_nsec + 999999ULL) / 1000000ULL;
    if (ms > 0x7fffffff)
        return 0x7fffffff;
    return (int)ms;
}

static int timeval_to_timeout_ms(const struct timeval *tv) {
    if (!tv)
        return -1;
    if (tv->tv_sec < 0 || tv->tv_usec < 0 || tv->tv_usec >= 1000000)
        return -EINVAL;
    uint64_t sec = (uint64_t)tv->tv_sec;
    if (sec > UINT64_MAX / 1000ULL)
        return 0x7fffffff;
    uint64_t ms = sec * 1000ULL +
                  ((uint64_t)tv->tv_usec + 999ULL) / 1000ULL;
    if (ms > 0x7fffffffULL)
        return 0x7fffffff;
    return (int)ms;
}

static int timeval_to_timeout_ns(const struct timeval *tv, uint64_t *out_ns) {
    if (!tv || !out_ns)
        return -EINVAL;
    if (tv->tv_sec < 0 || tv->tv_usec < 0 || tv->tv_usec >= 1000000)
        return -EINVAL;
    uint64_t sec = (uint64_t)tv->tv_sec;
    if (sec > UINT64_MAX / NS_PER_SEC)
        return -ERANGE;
    uint64_t ns = sec * NS_PER_SEC + (uint64_t)tv->tv_usec * 1000ULL;
    *out_ns = ns;
    return 0;
}

static struct timeval timeout_ns_to_timeval(uint64_t ns) {
    struct timeval tv = {
        .tv_sec = (time_t)(ns / NS_PER_SEC),
        .tv_usec = (suseconds_t)((ns % NS_PER_SEC) / 1000ULL),
    };
    return tv;
}

static int timespec_to_timeout_ns(const struct timespec *ts, uint64_t *out_ns) {
    if (!ts || !out_ns)
        return -EINVAL;
    if (ts->tv_sec < 0 || ts->tv_nsec < 0 || ts->tv_nsec >= (int64_t)NS_PER_SEC)
        return -EINVAL;
    uint64_t sec = (uint64_t)ts->tv_sec;
    if (sec > UINT64_MAX / NS_PER_SEC)
        return -ERANGE;
    uint64_t ns = sec * NS_PER_SEC + (uint64_t)ts->tv_nsec;
    *out_ns = ns;
    return 0;
}

static struct timespec timeout_ns_to_timespec(uint64_t ns) {
    struct timespec ts = {
        .tv_sec = (time_t)(ns / NS_PER_SEC),
        .tv_nsec = (int64_t)(ns % NS_PER_SEC),
    };
    return ts;
}

static int poll_copy_sigmask_from_user(sigset_t *out, uint64_t mask_ptr,
                                       uint64_t sigsetsize) {
    if (!out)
        return -EINVAL;
    *out = 0;
    if (!mask_ptr)
        return 0;
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;
    if (copy_from_user(out, (void *)mask_ptr, (size_t)sigsetsize) < 0)
        return -EFAULT;
    return 1;
}

static int poll_sleep_timeout(int timeout_ms) {
    if (timeout_ms == 0)
        return 0;

    struct process *curr = proc_current();
    if (!curr)
        return -EINVAL;

    uint64_t deadline = 0;
    if (timeout_ms > 0) {
        uint64_t delta = ((uint64_t)timeout_ms * CONFIG_HZ + 999) / 1000;
        if (!delta)
            delta = 1;
        deadline = arch_timer_get_ticks() + delta;
    }

    while (1) {
        if (deadline && arch_timer_get_ticks() >= deadline)
            return 0;

        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        if (deadline)
            poll_sleep_arm(&sleep, curr, deadline);
        int rc = proc_sleep_on(NULL, deadline ? (void *)&sleep : (void *)curr,
                               true);
        if (deadline)
            poll_sleep_cancel(&sleep);
        if (rc == -EINTR)
            return -EINTR;
    }
}

int64_t sys_poll(uint64_t fds_ptr, uint64_t nfds, uint64_t timeout_ms,
                 uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int64_t tmo = (int64_t)timeout_ms;
    if (tmo < -1)
        tmo = -1;
    const int64_t tmo_max = 0x7fffffffLL;
    if (tmo > tmo_max)
        tmo = tmo_max;

    if (nfds == 0)
        return poll_sleep_timeout((int)tmo);
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
                            uint64_t writefds_ptr, uint64_t exceptfds_ptr,
                            int timeout_ms) {
    if (nfds > FD_SETSIZE)
        return -EINVAL;

    fd_set rfds = {0}, wfds = {0}, efds = {0};
    if (readfds_ptr &&
        copy_from_user(&rfds, (void *)readfds_ptr, sizeof(rfds)) < 0)
        return -EFAULT;
    if (writefds_ptr &&
        copy_from_user(&wfds, (void *)writefds_ptr, sizeof(wfds)) < 0)
        return -EFAULT;
    if (exceptfds_ptr &&
        copy_from_user(&efds, (void *)exceptfds_ptr, sizeof(efds)) < 0)
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
        if (exceptfds_ptr && (efds.bits & mask))
            events |= POLLPRI;
        if (events) {
            fds[count].fd = (int)fd;
            fds[count].events = events;
            fds[count].revents = 0;
            count++;
        }
    }

    if (count == 0)
        return poll_sleep_timeout(timeout_ms);

    int ready = poll_wait_kernel(fds, count, timeout_ms);
    if (ready < 0)
        return ready;

    if (readfds_ptr)
        rfds.bits = 0;
    if (writefds_ptr)
        wfds.bits = 0;
    if (exceptfds_ptr)
        efds.bits = 0;
    for (size_t i = 0; i < count; i++) {
        if (fds[i].revents & POLLIN)
            rfds.bits |= (1ULL << fds[i].fd);
        if (fds[i].revents & POLLOUT)
            wfds.bits |= (1ULL << fds[i].fd);
        if (fds[i].revents & (POLLPRI | POLLERR | POLLHUP))
            efds.bits |= (1ULL << fds[i].fd);
    }

    if (readfds_ptr &&
        copy_to_user((void *)readfds_ptr, &rfds, sizeof(rfds)) < 0)
        ready = -EFAULT;
    if (writefds_ptr &&
        copy_to_user((void *)writefds_ptr, &wfds, sizeof(wfds)) < 0)
        ready = -EFAULT;
    if (exceptfds_ptr &&
        copy_to_user((void *)exceptfds_ptr, &efds, sizeof(efds)) < 0)
        ready = -EFAULT;

    return ready;
}

int64_t sys_select(uint64_t nfds, uint64_t readfds_ptr, uint64_t writefds_ptr,
                   uint64_t exceptfds_ptr, uint64_t timeout_ptr, uint64_t a5) {
    (void)a5;

    int timeout_ms = -1;
    bool have_timeout = false;
    uint64_t timeout_ns = 0;
    uint64_t start_ticks = 0;
    if (timeout_ptr) {
        struct timeval tv;
        if (copy_from_user(&tv, (void *)timeout_ptr, sizeof(tv)) < 0)
            return -EFAULT;
        int timeout_ms_rc = timeval_to_timeout_ms(&tv);
        if (timeout_ms_rc < 0)
            return timeout_ms_rc;
        timeout_ms = timeout_ms_rc;
        int timeout_ns_rc = timeval_to_timeout_ns(&tv, &timeout_ns);
        if (timeout_ns_rc < 0 && timeout_ns_rc != -ERANGE)
            return timeout_ns_rc;
        if (timeout_ns_rc == -ERANGE)
            timeout_ns = UINT64_MAX;
        have_timeout = true;
        start_ticks = arch_timer_get_ticks();
    }

    int64_t ret =
        do_select_common(nfds, readfds_ptr, writefds_ptr, exceptfds_ptr,
                         timeout_ms);
    if (have_timeout && (ret >= 0 || ret == -EINTR)) {
        uint64_t elapsed_ns =
            arch_timer_ticks_to_ns(arch_timer_get_ticks() - start_ticks);
        uint64_t rem_ns = (elapsed_ns >= timeout_ns) ? 0 : (timeout_ns - elapsed_ns);
        struct timeval rem_tv = timeout_ns_to_timeval(rem_ns);
        if (copy_to_user((void *)timeout_ptr, &rem_tv, sizeof(rem_tv)) < 0)
            return -EFAULT;
    }
    return ret;
}

int64_t sys_ppoll(uint64_t fds_ptr, uint64_t nfds, uint64_t tsp_ptr,
                  uint64_t sigmask_ptr, uint64_t sigsetsize,
                  uint64_t a5) {
    (void)a5;
    bool have_sigmask = false;
    sigset_t mask = 0;
    if (sigmask_ptr) {
        int rc = poll_copy_sigmask_from_user(&mask, sigmask_ptr, sigsetsize);
        if (rc < 0)
            return rc;
        have_sigmask = rc > 0;
    }
    int timeout_ms = -1;
    bool have_timeout = false;
    uint64_t timeout_ns = 0;
    uint64_t start_ticks = 0;
    if (tsp_ptr) {
        struct timespec ts;
        if (copy_from_user(&ts, (void *)tsp_ptr, sizeof(ts)) < 0)
            return -EFAULT;
        int timeout_ms_rc = timespec_to_timeout_ms(&ts);
        if (timeout_ms_rc < 0)
            return timeout_ms_rc;
        timeout_ms = timeout_ms_rc;
        int timeout_ns_rc = timespec_to_timeout_ns(&ts, &timeout_ns);
        if (timeout_ns_rc < 0 && timeout_ns_rc != -ERANGE)
            return timeout_ns_rc;
        if (timeout_ns_rc == -ERANGE)
            timeout_ns = UINT64_MAX;
        have_timeout = true;
        start_ticks = arch_timer_get_ticks();
    }

    struct poll_sigmask_ctx ctx = {0};
    if (have_sigmask) {
        int rc = poll_sigmask_apply(&mask, &ctx);
        if (rc < 0)
            return rc;
    }
    int64_t ret = sys_poll(fds_ptr, nfds, (uint64_t)timeout_ms, 0, 0, 0);
    poll_sigmask_restore(&ctx);
    if (have_timeout && (ret >= 0 || ret == -EINTR)) {
        uint64_t elapsed_ns =
            arch_timer_ticks_to_ns(arch_timer_get_ticks() - start_ticks);
        uint64_t rem_ns = (elapsed_ns >= timeout_ns) ? 0 : (timeout_ns - elapsed_ns);
        struct timespec rem_ts = timeout_ns_to_timespec(rem_ns);
        if (copy_to_user((void *)tsp_ptr, &rem_ts, sizeof(rem_ts)) < 0)
            return -EFAULT;
    }
    return ret;
}

int64_t sys_pselect6(uint64_t nfds, uint64_t readfds_ptr,
                     uint64_t writefds_ptr, uint64_t exceptfds_ptr,
                     uint64_t timeout_ptr, uint64_t sigmask_ptr) {
    bool have_sigmask = false;
    sigset_t mask = 0;
    if (sigmask_ptr) {
        struct {
            uint64_t sigmask;
            uint64_t sigsetsize;
        } ss;
        if (copy_from_user(&ss, (void *)sigmask_ptr, sizeof(ss)) < 0)
            return -EFAULT;
        if (ss.sigmask) {
            int rc = poll_copy_sigmask_from_user(&mask, ss.sigmask,
                                                 ss.sigsetsize);
            if (rc < 0)
                return rc;
            have_sigmask = rc > 0;
        }
    }
    int timeout_ms = -1;
    bool have_timeout = false;
    uint64_t timeout_ns = 0;
    uint64_t start_ticks = 0;
    if (timeout_ptr) {
        struct timespec ts;
        if (copy_from_user(&ts, (void *)timeout_ptr, sizeof(ts)) < 0)
            return -EFAULT;
        int timeout_ms_rc = timespec_to_timeout_ms(&ts);
        if (timeout_ms_rc < 0)
            return timeout_ms_rc;
        timeout_ms = timeout_ms_rc;
        int timeout_ns_rc = timespec_to_timeout_ns(&ts, &timeout_ns);
        if (timeout_ns_rc < 0 && timeout_ns_rc != -ERANGE)
            return timeout_ns_rc;
        if (timeout_ns_rc == -ERANGE)
            timeout_ns = UINT64_MAX;
        have_timeout = true;
        start_ticks = arch_timer_get_ticks();
    }

    struct poll_sigmask_ctx ctx = {0};
    if (have_sigmask) {
        int rc = poll_sigmask_apply(&mask, &ctx);
        if (rc < 0)
            return rc;
    }
    int64_t ret =
        do_select_common(nfds, readfds_ptr, writefds_ptr, exceptfds_ptr,
                         timeout_ms);
    poll_sigmask_restore(&ctx);
    if (have_timeout && (ret >= 0 || ret == -EINTR)) {
        uint64_t elapsed_ns =
            arch_timer_ticks_to_ns(arch_timer_get_ticks() - start_ticks);
        uint64_t rem_ns = (elapsed_ns >= timeout_ns) ? 0 : (timeout_ns - elapsed_ns);
        struct timespec rem_ts = timeout_ns_to_timespec(rem_ns);
        if (copy_to_user((void *)timeout_ptr, &rem_ts, sizeof(rem_ts)) < 0)
            return -EFAULT;
    }
    return ret;
}
