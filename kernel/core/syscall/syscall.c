/**
 * kernel/core/syscall/syscall.c - Optimized System Call Dispatch
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/select.h>
#include <kairos/sched.h>
#include <kairos/sync.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>
#include <kairos/string.h>
#include <kairos/mm.h>

/* Forward declarations for internal implementations */
extern int do_sem_init(int count);
extern int do_sem_wait(int sem_id);
extern int do_sem_post(int sem_id);

/* --- Process Handlers --- */

int64_t sys_exit(uint64_t status, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    proc_exit((int)status);
}

int64_t sys_fork(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_fork();
    return p ? (int64_t)p->pid : -1;
}

int64_t sys_exec(uint64_t path, uint64_t argv, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0) return -EFAULT;
    return (int64_t)proc_exec(kpath, (char *const *)argv);
}

int64_t sys_getpid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)proc_current()->pid;
}

int64_t sys_wait(uint64_t pid, uint64_t status_ptr, uint64_t options, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int status = 0;
    pid_t ret = proc_wait((pid_t)pid, &status, (int)options);
    if (ret >= 0 && status_ptr) {
        if (copy_to_user((void *)status_ptr, &status, sizeof(status)) < 0) return -EFAULT;
    }
    return (int64_t)ret;
}

int64_t sys_brk(uint64_t addr, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)mm_brk(proc_current()->mm, (vaddr_t)addr);
}

/* --- File/IO Handlers --- */

int64_t sys_open(uint64_t path, uint64_t flags, uint64_t mode, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    struct file *f;
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0) return -EFAULT;
    
    int ret = vfs_open(kpath, (int)flags, (mode_t)mode, &f);
    if (ret < 0) return ret;
    
    int fd = fd_alloc(proc_current(), f);
    if (fd < 0) { vfs_close(f); return -EMFILE; }
    return fd;
}

static int64_t sys_read_write(uint64_t fd, uint64_t buf, uint64_t count, bool is_write) {
    struct file *f = fd_get(proc_current(), (int)fd);
    uint8_t kbuf[512];
    size_t done = 0;

    if (!f) {
        if (is_write && (fd == 1 || fd == 2)) {
            while (done < count) {
                size_t chunk = (count - done > sizeof(kbuf)) ? sizeof(kbuf) : (size_t)(count - done);
                if (copy_from_user(kbuf, (const void *)(buf + done), chunk) < 0)
                    return done ? (int64_t)done : -EFAULT;
                for (size_t i = 0; i < chunk; i++)
                    arch_early_putchar((char)kbuf[i]);
                done += chunk;
            }
            return (int64_t)done;
        }
        return -EBADF;
    }
    
    while (done < count) {
        size_t chunk = (count - done > sizeof(kbuf)) ? sizeof(kbuf) : (size_t)(count - done);
        if (is_write) {
            if (copy_from_user(kbuf, (const void *)(buf + done), chunk) < 0)
                return done ? (int64_t)done : -EFAULT;
            ssize_t n = vfs_write(f, kbuf, chunk);
            if (n < 0)
                return done ? (int64_t)done : (int64_t)n;
            if (n == 0)
                break;
            done += (size_t)n;
        } else {
            ssize_t n = vfs_read(f, kbuf, chunk);
            if (n < 0)
                return done ? (int64_t)done : (int64_t)n;
            if (n == 0)
                break;
            if (copy_to_user((void *)(buf + done), kbuf, (size_t)n) < 0)
                return done ? (int64_t)done : -EFAULT;
            done += (size_t)n;
        }
    }
    return (int64_t)done;
}

int64_t sys_read(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, false);
}

int64_t sys_write(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, true);
}

int64_t sys_close(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_close(proc_current(), (int)fd);
}

int64_t sys_stat(uint64_t path, uint64_t st_ptr, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    struct stat st;
    if (strncpy_from_user(kpath, (const char *)path, sizeof(kpath)) < 0) return -EFAULT;
    
    int ret = vfs_stat(kpath, &st);
    if (ret < 0) return ret;
    if (copy_to_user((void *)st_ptr, &st, sizeof(st)) < 0) return -EFAULT;
    return 0;
}

int64_t sys_fstat(uint64_t fd, uint64_t st_ptr, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f) return -EBADF;
    
    struct stat st;
    int ret = vfs_fstat(f, &st);
    if (ret < 0) return ret;
    if (copy_to_user((void *)st_ptr, &st, sizeof(st)) < 0) return -EFAULT;
    return 0;
}

int64_t sys_dup2(uint64_t oldfd, uint64_t newfd, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_dup2(proc_current(), (int)oldfd, (int)newfd);
}

static int pipe_create_fds(uint64_t fd_array, uint32_t flags) {
    struct file *rf = NULL, *wf = NULL;
    int fds[2] = {-1, -1}, ret = 0;
    extern int pipe_create(struct file **read_pipe, struct file **write_pipe);

    if ((ret = pipe_create(&rf, &wf)) < 0)
        return ret;

    if (flags & O_NONBLOCK) {
        mutex_lock(&rf->lock);
        rf->flags |= O_NONBLOCK;
        mutex_unlock(&rf->lock);
        mutex_lock(&wf->lock);
        wf->flags |= O_NONBLOCK;
        mutex_unlock(&wf->lock);
    }

    if ((fds[0] = fd_alloc(proc_current(), rf)) < 0) {
        ret = -EMFILE;
        goto err;
    }
    if ((fds[1] = fd_alloc(proc_current(), wf)) < 0) {
        ret = -EMFILE;
        goto err;
    }
    if (copy_to_user((void *)fd_array, fds, sizeof(fds)) < 0) {
        ret = -EFAULT;
        goto err;
    }
    return 0;
err:
    if (fds[0] >= 0) {
        fd_close(proc_current(), fds[0]);
    } else if (rf) {
        vfs_close(rf);
    }
    if (fds[1] >= 0) {
        fd_close(proc_current(), fds[1]);
    } else if (wf) {
        vfs_close(wf);
    }
    return ret;
}

int64_t sys_pipe(uint64_t fd_array, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)pipe_create_fds(fd_array, 0);
}

int64_t sys_pipe2(uint64_t fd_array, uint64_t flags, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    uint32_t allowed = O_NONBLOCK;
    if (flags & ~allowed)
        return -EINVAL;
    return (int64_t)pipe_create_fds(fd_array, (uint32_t)flags);
}

int64_t sys_fcntl(uint64_t fd, uint64_t cmd, uint64_t arg, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f) return -EBADF;

    switch ((int)cmd) {
    case F_GETFL: {
        mutex_lock(&f->lock);
        int flags = (int)f->flags;
        mutex_unlock(&f->lock);
        return flags;
    }
    case F_SETFL: {
        uint32_t setmask = O_NONBLOCK | O_APPEND;
        mutex_lock(&f->lock);
        f->flags = (f->flags & ~setmask) | ((uint32_t)arg & setmask);
        int flags = (int)f->flags;
        mutex_unlock(&f->lock);
        return flags;
    }
    default:
        return -EINVAL;
    }
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
        waiters[i].proc = curr;
        if (fds[i].fd < 0 || fds[i].revents)
            continue;
        struct file *f = fd_get(curr, fds[i].fd);
        if (!f)
            continue;
        vfs_poll_register(f, &waiters[i], (uint32_t)fds[i].events);
    }
}

int64_t sys_poll(uint64_t fds_ptr, uint64_t nfds, uint64_t timeout_ms,
                 uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (nfds == 0) return 0;
    if (nfds > 1024) return -EINVAL;

    size_t bytes = nfds * sizeof(struct pollfd);
    struct pollfd *kfds = kmalloc(bytes);
    if (!kfds) return -ENOMEM;
    if (copy_from_user(kfds, (void *)fds_ptr, bytes) < 0) {
        kfree(kfds);
        return -EFAULT;
    }

    struct poll_waiter *waiters = kzalloc(nfds * sizeof(*waiters));
    if (!waiters) {
        kfree(kfds);
        return -ENOMEM;
    }

    int timeout = (int)timeout_ms;
    uint64_t start = arch_timer_get_ticks();
    uint64_t deadline = 0;
    if (timeout > 0) {
        uint64_t delta = ((uint64_t)timeout * CONFIG_HZ + 999) / 1000;
        if (!delta)
            delta = 1;
        deadline = start + delta;
    }

    int ready;
    do {
        poll_unregister_waiters(waiters, (size_t)nfds);
        ready = poll_check_fds(kfds, (size_t)nfds);
        if (ready || timeout == 0)
            break;

        uint64_t now = arch_timer_get_ticks();
        if (deadline && now >= deadline) {
            ready = 0;
            break;
        }

        poll_register_waiters(kfds, waiters, (size_t)nfds);

        struct process *curr = proc_current();
        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        if (deadline)
            poll_sleep_arm(&sleep, curr, deadline);
        proc_sleep(&sleep);
        poll_sleep_cancel(&sleep);
    } while (1);

    poll_unregister_waiters(waiters, (size_t)nfds);

    if (copy_to_user((void *)fds_ptr, kfds, bytes) < 0) {
        kfree(waiters);
        kfree(kfds);
        return -EFAULT;
    }
    kfree(waiters);
    kfree(kfds);
    return ready;
}

int64_t sys_select(uint64_t nfds, uint64_t readfds_ptr, uint64_t writefds_ptr,
                   uint64_t exceptfds_ptr, uint64_t timeout_ptr, uint64_t a5) {
    (void)exceptfds_ptr; (void)a5;
    if (nfds > FD_SETSIZE) return -EINVAL;

    fd_set rfds = {0}, wfds = {0};
    if (readfds_ptr && copy_from_user(&rfds, (void *)readfds_ptr, sizeof(rfds)) < 0)
        return -EFAULT;
    if (writefds_ptr && copy_from_user(&wfds, (void *)writefds_ptr, sizeof(wfds)) < 0)
        return -EFAULT;

    struct pollfd fds[FD_SETSIZE];
    size_t count = 0;
    for (uint64_t fd = 0; fd < nfds; fd++) {
        uint64_t mask = 1ULL << fd;
        short events = 0;
        if (readfds_ptr && (rfds.bits & mask)) events |= POLLIN;
        if (writefds_ptr && (wfds.bits & mask)) events |= POLLOUT;
        if (events) {
            fds[count].fd = (int)fd;
            fds[count].events = events;
            fds[count].revents = 0;
            count++;
        }
    }

    if (count == 0)
        return 0;

    int timeout_ms = -1;
    if (timeout_ptr) {
        struct timeval tv;
        if (copy_from_user(&tv, (void *)timeout_ptr, sizeof(tv)) < 0)
            return -EFAULT;
        if (tv.tv_sec < 0 || tv.tv_usec < 0)
            return -EINVAL;
        timeout_ms = (int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
    }

    struct poll_waiter *waiters = kzalloc(count * sizeof(*waiters));
    if (!waiters)
        return -ENOMEM;

    uint64_t start = arch_timer_get_ticks();
    uint64_t deadline = 0;
    if (timeout_ms > 0) {
        uint64_t delta = ((uint64_t)timeout_ms * CONFIG_HZ + 999) / 1000;
        if (!delta)
            delta = 1;
        deadline = start + delta;
    }

    int ready;
    do {
        poll_unregister_waiters(waiters, count);
        ready = poll_check_fds(fds, count);
        if (ready || timeout_ms == 0)
            break;

        uint64_t now = arch_timer_get_ticks();
        if (deadline && now >= deadline) {
            ready = 0;
            break;
        }

        poll_register_waiters(fds, waiters, count);

        struct process *curr = proc_current();
        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        if (deadline)
            poll_sleep_arm(&sleep, curr, deadline);
        proc_sleep(&sleep);
        poll_sleep_cancel(&sleep);
    } while (1);

    poll_unregister_waiters(waiters, count);

    if (readfds_ptr) rfds.bits = 0;
    if (writefds_ptr) wfds.bits = 0;
    for (size_t i = 0; i < count; i++) {
        if (fds[i].revents & POLLIN)
            rfds.bits |= (1ULL << fds[i].fd);
        if (fds[i].revents & POLLOUT)
            wfds.bits |= (1ULL << fds[i].fd);
    }

    if (readfds_ptr && copy_to_user((void *)readfds_ptr, &rfds, sizeof(rfds)) < 0)
        ready = -EFAULT;
    if (writefds_ptr && copy_to_user((void *)writefds_ptr, &wfds, sizeof(wfds)) < 0)
        ready = -EFAULT;

    kfree(waiters);
    return ready;
}

/* --- Semaphore Handlers --- */

int64_t sys_sem_init(uint64_t count, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_init((int)count);
}

int64_t sys_sem_wait(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_wait((int)sem_id);
}

int64_t sys_sem_post(uint64_t sem_id, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)do_sem_post((int)sem_id);
}

/* --- Table & Dispatch --- */

syscall_fn_t syscall_table[SYS_MAX] = {
    [SYS_exit]    = sys_exit,
    [SYS_fork]    = sys_fork,
    [SYS_exec]    = sys_exec,
    [SYS_getpid]  = sys_getpid,
    [SYS_wait]    = sys_wait,
    [SYS_brk]     = sys_brk,
    [SYS_open]    = sys_open,
    [SYS_read]    = sys_read,
    [SYS_write]   = sys_write,
    [SYS_close]   = sys_close,
    [SYS_stat]    = sys_stat,
    [SYS_fstat]   = sys_fstat,
    [SYS_dup2]    = sys_dup2,
    [SYS_fcntl]   = sys_fcntl,
    [SYS_pipe]    = sys_pipe,
    [SYS_pipe2]   = sys_pipe2,
    [SYS_sem_init] = sys_sem_init,
    [SYS_sem_wait] = sys_sem_wait,
    [SYS_sem_post] = sys_sem_post,
    [SYS_poll]    = sys_poll,
    [SYS_select]  = sys_select,
    [SYS_kill]    = sys_kill,
    [SYS_sigaction] = sys_sigaction,
    [SYS_sigprocmask] = sys_sigprocmask,
    [SYS_sigreturn] = sys_sigreturn,
};

int64_t syscall_dispatch(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    if (num >= SYS_MAX || !syscall_table[num]) return -ENOSYS;
    return syscall_table[num](a0, a1, a2, a3, a4, a5);
}

void syscall_init(void) {
    pr_info("Syscall: initialized\n");
}
