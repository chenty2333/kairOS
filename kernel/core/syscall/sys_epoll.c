/**
 * kernel/core/syscall/sys_epoll.c - Epoll syscalls
 */

#include <kairos/epoll.h>
#include <kairos/epoll_internal.h>
#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#define NS_PER_SEC 1000000000ULL

int64_t sys_epoll_create1(uint64_t flags, uint64_t a1, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (flags & ~EPOLL_CLOEXEC)
        return -EINVAL;

    struct file *file = NULL;
    int ret = epoll_create_file(&file);
    if (ret < 0)
        return ret;

    uint32_t fd_flags = (flags & EPOLL_CLOEXEC) ? FD_CLOEXEC : 0;
    int fd = fd_alloc_flags(proc_current(), file, fd_flags);
    if (fd < 0) {
        vfs_close(file);
        return fd;
    }
    return fd;
}

int64_t sys_epoll_ctl(uint64_t epfd, uint64_t op, uint64_t fd,
                      uint64_t event_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    struct epoll_event ev = {0};

    if (op != EPOLL_CTL_DEL) {
        if (!event_ptr)
            return -EFAULT;
        if (copy_from_user(&ev, (void *)event_ptr, sizeof(ev)) < 0)
            return -EFAULT;
    }

    return epoll_ctl_fd((int)epfd, (int)op, (int)fd,
                        (op == EPOLL_CTL_DEL) ? NULL : &ev);
}

int64_t sys_epoll_wait(uint64_t epfd, uint64_t events_ptr, uint64_t maxevents,
                       uint64_t timeout_ms, uint64_t a4, uint64_t a5) {
    if (a4) {
        if (a5 != sizeof(sigset_t))
            return -EINVAL;
        sigset_t mask;
        if (copy_from_user(&mask, (void *)a4, sizeof(mask)) < 0)
            return -EFAULT;
    }
    if (maxevents == 0)
        return -EINVAL;
    if (!events_ptr)
        return -EFAULT;
    if (maxevents > 0x7fffffffULL ||
        maxevents > (uint64_t)((size_t)-1) / sizeof(struct epoll_event))
        return -EINVAL;

    struct epoll_event *out = kzalloc(maxevents * sizeof(*out));
    if (!out)
        return -ENOMEM;

    int64_t tmo = (int64_t)timeout_ms;
    if (tmo < -1)
        tmo = -1;
    if (tmo > 0x7fffffffLL)
        tmo = 0x7fffffffLL;
    int ready = epoll_wait_events((int)epfd, out, (size_t)maxevents,
                                  (int)tmo);
    int64_t ret = ready;
    if (ready > 0 &&
        copy_to_user((void *)events_ptr, out,
                     (size_t)ready * sizeof(*out)) < 0)
        ret = -EFAULT;

    kfree(out);
    return ret;
}

int64_t sys_epoll_pwait2(uint64_t epfd, uint64_t events_ptr, uint64_t maxevents,
                         uint64_t timeout_ptr, uint64_t sigmask_ptr,
                         uint64_t sigsetsize) {
    int64_t timeout_ms = -1;
    if (timeout_ptr) {
        struct timespec ts;
        if (copy_from_user(&ts, (void *)timeout_ptr, sizeof(ts)) < 0)
            return -EFAULT;
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 ||
            ts.tv_nsec >= (int64_t)NS_PER_SEC)
            return -EINVAL;
        uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL +
                      ((uint64_t)ts.tv_nsec + 999999ULL) / 1000000ULL;
        timeout_ms = (ms > 0x7fffffffULL) ? 0x7fffffffLL : (int64_t)ms;
    }
    return sys_epoll_wait(epfd, events_ptr, maxevents, (uint64_t)timeout_ms,
                          sigmask_ptr, sigsetsize);
}
