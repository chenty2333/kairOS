#include <kairos/arch.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/time.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>
#include <kairos/wait.h>

#define NS_PER_SEC 1000000000ULL

#define EFD_SEMAPHORE 0x1
#define EFD_CLOEXEC O_CLOEXEC
#define EFD_NONBLOCK O_NONBLOCK

#define TFD_TIMER_ABSTIME 0x1
#define TFD_CLOEXEC O_CLOEXEC
#define TFD_NONBLOCK O_NONBLOCK

#define EVENTFD_COUNTER_MAX (UINT64_MAX - 1ULL)
#define EVENTFD_MAGIC 0x65766466U
#define TIMERFD_MAGIC 0x746d6664U

struct linux_itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

struct eventfd_ctx {
    uint32_t magic;
    spinlock_t lock;
    struct wait_queue rd_wait;
    struct wait_queue wr_wait;
    struct vnode *vnode;
    uint64_t counter;
    bool semaphore;
    bool closed;
};

struct timerfd_ctx {
    uint32_t magic;
    spinlock_t lock;
    struct wait_queue rd_wait;
    struct vnode *vnode;
    struct list_head list;
    uint64_t interval_ns;
    uint64_t next_expire_ns;
    uint64_t expirations;
    int clockid;
    bool armed;
    bool closed;
};

static LIST_HEAD(timerfd_list);
static spinlock_t timerfd_list_lock = SPINLOCK_INIT;

static int eventfd_close(struct vnode *vn);
static int eventfd_poll(struct file *file, uint32_t events);
static ssize_t eventfd_fread(struct file *file, void *buf, size_t len);
static ssize_t eventfd_fwrite(struct file *file, const void *buf, size_t len);

static struct file_ops eventfd_file_ops = {
    .close = eventfd_close,
    .fread = eventfd_fread,
    .fwrite = eventfd_fwrite,
    .poll = eventfd_poll,
};

static int timerfd_close(struct vnode *vn);
static int timerfd_poll(struct file *file, uint32_t events);
static ssize_t timerfd_fread(struct file *file, void *buf, size_t len);

static struct file_ops timerfd_file_ops = {
    .close = timerfd_close,
    .fread = timerfd_fread,
    .poll = timerfd_poll,
};

static uint64_t u64_add_sat(uint64_t lhs, uint64_t rhs) {
    if (UINT64_MAX - lhs < rhs)
        return UINT64_MAX;
    return lhs + rhs;
}

static int timespec_to_ns(const struct timespec *ts, uint64_t *out_ns) {
    if (!ts || !out_ns)
        return -EINVAL;
    if (ts->tv_sec < 0 || ts->tv_nsec < 0 ||
        ts->tv_nsec >= (int64_t)NS_PER_SEC) {
        return -EINVAL;
    }
    uint64_t sec = (uint64_t)ts->tv_sec;
    if (sec > UINT64_MAX / NS_PER_SEC)
        return -EINVAL;
    *out_ns = sec * NS_PER_SEC + (uint64_t)ts->tv_nsec;
    return 0;
}

static struct timespec ns_to_timespec(uint64_t ns) {
    struct timespec ts = {
        .tv_sec = (time_t)(ns / NS_PER_SEC),
        .tv_nsec = (int64_t)(ns % NS_PER_SEC),
    };
    return ts;
}

static int eventfd_close(struct vnode *vn) {
    if (!vn)
        return 0;
    struct eventfd_ctx *ctx = (struct eventfd_ctx *)vn->fs_data;
    if (ctx && ctx->magic == EVENTFD_MAGIC) {
        bool irq;
        spin_lock_irqsave(&ctx->lock, &irq);
        ctx->closed = true;
        spin_unlock_irqrestore(&ctx->lock, irq);
        wait_queue_wakeup_all(&ctx->rd_wait);
        wait_queue_wakeup_all(&ctx->wr_wait);
        vfs_poll_wake(vn, POLLIN | POLLOUT | POLLHUP);
        ctx->magic = 0;
        kfree(ctx);
    }
    kfree(vn);
    return 0;
}

static int eventfd_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;
    struct eventfd_ctx *ctx = (struct eventfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != EVENTFD_MAGIC)
        return POLLNVAL;

    uint32_t revents = 0;
    bool irq;
    spin_lock_irqsave(&ctx->lock, &irq);
    if (ctx->counter > 0)
        revents |= POLLIN;
    if (ctx->counter < EVENTFD_COUNTER_MAX)
        revents |= POLLOUT;
    spin_unlock_irqrestore(&ctx->lock, irq);
    return (int)(revents & events);
}

static ssize_t eventfd_fread(struct file *file, void *buf, size_t len) {
    if (!file || !file->vnode || !buf)
        return -EINVAL;
    if (len != sizeof(uint64_t))
        return -EINVAL;

    struct eventfd_ctx *ctx = (struct eventfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != EVENTFD_MAGIC)
        return -EINVAL;

    while (1) {
        uint64_t val = 0;
        bool irq;
        spin_lock_irqsave(&ctx->lock, &irq);
        if (ctx->counter > 0) {
            if (ctx->semaphore) {
                ctx->counter--;
                val = 1;
            } else {
                val = ctx->counter;
                ctx->counter = 0;
            }
            spin_unlock_irqrestore(&ctx->lock, irq);
            memcpy(buf, &val, sizeof(val));
            wait_queue_wakeup_all(&ctx->wr_wait);
            vfs_poll_wake(ctx->vnode, POLLOUT);
            return (ssize_t)sizeof(uint64_t);
        }
        if (ctx->closed) {
            spin_unlock_irqrestore(&ctx->lock, irq);
            return -EINVAL;
        }
        bool nonblock = (file->flags & O_NONBLOCK) != 0;
        spin_unlock_irqrestore(&ctx->lock, irq);
        if (nonblock)
            return -EAGAIN;
        int rc = proc_sleep_on_mutex(&ctx->rd_wait, ctx, &file->lock, true);
        if (rc < 0)
            return rc;
    }
}

static ssize_t eventfd_fwrite(struct file *file, const void *buf, size_t len) {
    if (!file || !file->vnode || !buf)
        return -EINVAL;
    if (len != sizeof(uint64_t))
        return -EINVAL;

    struct eventfd_ctx *ctx = (struct eventfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != EVENTFD_MAGIC)
        return -EINVAL;

    uint64_t val = 0;
    memcpy(&val, buf, sizeof(val));
    if (val == UINT64_MAX)
        return -EINVAL;

    while (1) {
        bool wake_readers = false;
        bool irq;
        spin_lock_irqsave(&ctx->lock, &irq);
        if (ctx->closed) {
            spin_unlock_irqrestore(&ctx->lock, irq);
            return -EINVAL;
        }
        if (val <= EVENTFD_COUNTER_MAX - ctx->counter) {
            bool was_empty = (ctx->counter == 0);
            ctx->counter += val;
            wake_readers = (val > 0) && was_empty;
            spin_unlock_irqrestore(&ctx->lock, irq);
            if (wake_readers) {
                wait_queue_wakeup_all(&ctx->rd_wait);
                vfs_poll_wake(ctx->vnode, POLLIN);
            }
            return (ssize_t)sizeof(uint64_t);
        }
        bool nonblock = (file->flags & O_NONBLOCK) != 0;
        spin_unlock_irqrestore(&ctx->lock, irq);
        if (nonblock)
            return -EAGAIN;
        int rc = proc_sleep_on_mutex(&ctx->wr_wait, ctx, &file->lock, true);
        if (rc < 0)
            return rc;
    }
}

static int eventfd_create_file(uint32_t initval, uint64_t flags, struct file **out) {
    struct eventfd_ctx *ctx = kzalloc(sizeof(*ctx));
    struct vnode *vn = kzalloc(sizeof(*vn));
    struct file *file = vfs_file_alloc();
    if (!ctx || !vn || !file) {
        kfree(ctx);
        kfree(vn);
        if (file)
            vfs_file_free(file);
        return -ENOMEM;
    }

    ctx->magic = EVENTFD_MAGIC;
    spin_init(&ctx->lock);
    wait_queue_init(&ctx->rd_wait);
    wait_queue_init(&ctx->wr_wait);
    ctx->counter = initval;
    ctx->semaphore = (flags & EFD_SEMAPHORE) != 0;
    ctx->closed = false;
    ctx->vnode = vn;

    vn->type = VNODE_FILE;
    vn->mode = S_IFREG | 0600;
    vn->nlink = 1;
    vn->ops = &eventfd_file_ops;
    vn->fs_data = ctx;
    atomic_init(&vn->refcount, 1);
    vn->parent = NULL;
    vn->name[0] = '\0';
    rwlock_init(&vn->lock, "eventfd_vnode");
    poll_wait_head_init(&vn->pollers);

    file->vnode = vn;
    file->flags = O_RDWR;
    if (flags & EFD_NONBLOCK)
        file->flags |= O_NONBLOCK;
    *out = file;
    return 0;
}

static uint64_t timerfd_now_ns(int clockid, uint64_t mono_ns, uint64_t realtime_ns) {
    if (clockid == CLOCK_REALTIME)
        return realtime_ns;
    return mono_ns;
}

static bool timerfd_refresh_locked(struct timerfd_ctx *ctx, uint64_t mono_ns,
                                   uint64_t realtime_ns) {
    if (!ctx || !ctx->armed)
        return false;

    uint64_t now_ns = timerfd_now_ns(ctx->clockid, mono_ns, realtime_ns);
    if (now_ns < ctx->next_expire_ns)
        return false;

    uint64_t prev = ctx->expirations;
    if (ctx->interval_ns == 0) {
        ctx->expirations = u64_add_sat(ctx->expirations, 1);
        ctx->armed = false;
        ctx->next_expire_ns = 0;
    } else {
        uint64_t overruns =
            ((now_ns - ctx->next_expire_ns) / ctx->interval_ns) + 1;
        ctx->expirations = u64_add_sat(ctx->expirations, overruns);
        uint64_t step = 0;
        uint64_t next = 0;
        if (__builtin_mul_overflow(overruns, ctx->interval_ns, &step) ||
            __builtin_add_overflow(ctx->next_expire_ns, step, &next)) {
            if (__builtin_add_overflow(now_ns, ctx->interval_ns, &next))
                next = UINT64_MAX;
        }
        ctx->next_expire_ns = next;
    }

    return prev == 0 && ctx->expirations > 0;
}

static void timerfd_fill_curr_locked(struct timerfd_ctx *ctx, uint64_t mono_ns,
                                     uint64_t realtime_ns,
                                     struct linux_itimerspec *out) {
    memset(out, 0, sizeof(*out));
    if (!ctx)
        return;
    out->it_interval = ns_to_timespec(ctx->interval_ns);
    if (!ctx->armed)
        return;
    uint64_t now_ns = timerfd_now_ns(ctx->clockid, mono_ns, realtime_ns);
    uint64_t rem = (ctx->next_expire_ns > now_ns) ?
                   (ctx->next_expire_ns - now_ns) : 0;
    out->it_value = ns_to_timespec(rem);
}

static int timerfd_close(struct vnode *vn) {
    if (!vn)
        return 0;
    struct timerfd_ctx *ctx = (struct timerfd_ctx *)vn->fs_data;
    if (ctx && ctx->magic == TIMERFD_MAGIC) {
        bool irq;
        spin_lock_irqsave(&timerfd_list_lock, &irq);
        if (!list_empty(&ctx->list))
            list_del(&ctx->list);
        spin_unlock_irqrestore(&timerfd_list_lock, irq);

        spin_lock_irqsave(&ctx->lock, &irq);
        ctx->closed = true;
        spin_unlock_irqrestore(&ctx->lock, irq);
        wait_queue_wakeup_all(&ctx->rd_wait);
        vfs_poll_wake(vn, POLLIN | POLLHUP);

        ctx->magic = 0;
        kfree(ctx);
    }
    kfree(vn);
    return 0;
}

static int timerfd_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;
    struct timerfd_ctx *ctx = (struct timerfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != TIMERFD_MAGIC)
        return POLLNVAL;

    uint64_t mono_ns = time_now_ns();
    uint64_t realtime_ns = time_realtime_ns();

    bool irq;
    spin_lock_irqsave(&ctx->lock, &irq);
    (void)timerfd_refresh_locked(ctx, mono_ns, realtime_ns);
    uint32_t revents = (ctx->expirations > 0) ? POLLIN : 0;
    spin_unlock_irqrestore(&ctx->lock, irq);
    return (int)(revents & events);
}

static ssize_t timerfd_fread(struct file *file, void *buf, size_t len) {
    if (!file || !file->vnode || !buf)
        return -EINVAL;
    if (len != sizeof(uint64_t))
        return -EINVAL;

    struct timerfd_ctx *ctx = (struct timerfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != TIMERFD_MAGIC)
        return -EINVAL;

    while (1) {
        uint64_t mono_ns = time_now_ns();
        uint64_t realtime_ns = time_realtime_ns();
        bool irq;
        spin_lock_irqsave(&ctx->lock, &irq);
        (void)timerfd_refresh_locked(ctx, mono_ns, realtime_ns);
        if (ctx->expirations > 0) {
            uint64_t out = ctx->expirations;
            ctx->expirations = 0;
            spin_unlock_irqrestore(&ctx->lock, irq);
            memcpy(buf, &out, sizeof(out));
            return (ssize_t)sizeof(uint64_t);
        }
        if (ctx->closed) {
            spin_unlock_irqrestore(&ctx->lock, irq);
            return -EINVAL;
        }
        bool nonblock = (file->flags & O_NONBLOCK) != 0;
        spin_unlock_irqrestore(&ctx->lock, irq);
        if (nonblock)
            return -EAGAIN;
        int rc = proc_sleep_on_mutex(&ctx->rd_wait, ctx, &file->lock, true);
        if (rc < 0)
            return rc;
    }
}

static int timerfd_create_file(int clockid, uint64_t flags, struct file **out) {
    struct timerfd_ctx *ctx = kzalloc(sizeof(*ctx));
    struct vnode *vn = kzalloc(sizeof(*vn));
    struct file *file = vfs_file_alloc();
    if (!ctx || !vn || !file) {
        kfree(ctx);
        kfree(vn);
        if (file)
            vfs_file_free(file);
        return -ENOMEM;
    }

    ctx->magic = TIMERFD_MAGIC;
    spin_init(&ctx->lock);
    wait_queue_init(&ctx->rd_wait);
    INIT_LIST_HEAD(&ctx->list);
    ctx->vnode = vn;
    ctx->clockid = clockid;
    ctx->interval_ns = 0;
    ctx->next_expire_ns = 0;
    ctx->expirations = 0;
    ctx->armed = false;
    ctx->closed = false;

    bool irq;
    spin_lock_irqsave(&timerfd_list_lock, &irq);
    list_add_tail(&ctx->list, &timerfd_list);
    spin_unlock_irqrestore(&timerfd_list_lock, irq);

    vn->type = VNODE_FILE;
    vn->mode = S_IFREG | 0600;
    vn->nlink = 1;
    vn->ops = &timerfd_file_ops;
    vn->fs_data = ctx;
    atomic_init(&vn->refcount, 1);
    vn->parent = NULL;
    vn->name[0] = '\0';
    rwlock_init(&vn->lock, "timerfd_vnode");
    poll_wait_head_init(&vn->pollers);

    file->vnode = vn;
    file->flags = O_RDWR;
    if (flags & TFD_NONBLOCK)
        file->flags |= O_NONBLOCK;
    *out = file;
    return 0;
}

void timerfd_tick(uint64_t now_ticks) {
    (void)now_ticks;
    uint64_t mono_ns = time_now_ns();
    uint64_t realtime_ns = time_realtime_ns();

    bool irq;
    spin_lock_irqsave(&timerfd_list_lock, &irq);
    struct timerfd_ctx *ctx;
    list_for_each_entry(ctx, &timerfd_list, list) {
        bool wake = false;
        spin_lock(&ctx->lock);
        wake = timerfd_refresh_locked(ctx, mono_ns, realtime_ns);
        spin_unlock(&ctx->lock);
        if (wake) {
            wait_queue_wakeup_all(&ctx->rd_wait);
            vfs_poll_wake(ctx->vnode, POLLIN);
        }
    }
    spin_unlock_irqrestore(&timerfd_list_lock, irq);
}

int64_t sys_eventfd2(uint64_t initval, uint64_t flags, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (flags & ~(EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK))
        return -EINVAL;

    struct file *file = NULL;
    int rc = eventfd_create_file((uint32_t)initval, flags, &file);
    if (rc < 0)
        return rc;

    uint32_t fd_flags = (flags & EFD_CLOEXEC) ? FD_CLOEXEC : 0;
    int fd = fd_alloc_flags(proc_current(), file, fd_flags);
    if (fd < 0) {
        vfs_close(file);
        return fd;
    }
    return fd;
}

int64_t sys_timerfd_create(uint64_t clockid, uint64_t flags, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
        return -EINVAL;
    if (flags & ~(TFD_CLOEXEC | TFD_NONBLOCK))
        return -EINVAL;

    struct file *file = NULL;
    int rc = timerfd_create_file((int)clockid, flags, &file);
    if (rc < 0)
        return rc;

    uint32_t fd_flags = (flags & TFD_CLOEXEC) ? FD_CLOEXEC : 0;
    int fd = fd_alloc_flags(proc_current(), file, fd_flags);
    if (fd < 0) {
        vfs_close(file);
        return fd;
    }
    return fd;
}

int64_t sys_timerfd_settime(uint64_t fd, uint64_t flags, uint64_t new_ptr,
                            uint64_t old_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (flags & ~TFD_TIMER_ABSTIME)
        return -EINVAL;
    if (!new_ptr)
        return -EFAULT;

    struct file *file = fd_get(proc_current(), (int)fd);
    if (!file)
        return -EBADF;
    if (!file->vnode) {
        file_put(file);
        return -EINVAL;
    }
    struct timerfd_ctx *ctx = (struct timerfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != TIMERFD_MAGIC) {
        file_put(file);
        return -EINVAL;
    }

    struct linux_itimerspec new_its = {0};
    if (copy_from_user(&new_its, (const void *)new_ptr, sizeof(new_its)) < 0) {
        file_put(file);
        return -EFAULT;
    }

    uint64_t value_ns = 0;
    uint64_t interval_ns = 0;
    int rc = timespec_to_ns(&new_its.it_value, &value_ns);
    if (rc < 0) {
        file_put(file);
        return rc;
    }
    rc = timespec_to_ns(&new_its.it_interval, &interval_ns);
    if (rc < 0) {
        file_put(file);
        return rc;
    }

    uint64_t mono_ns = time_now_ns();
    uint64_t realtime_ns = time_realtime_ns();
    bool wake = false;
    struct linux_itimerspec old_its = {0};
    bool irq;
    spin_lock_irqsave(&ctx->lock, &irq);
    wake = timerfd_refresh_locked(ctx, mono_ns, realtime_ns);
    if (old_ptr)
        timerfd_fill_curr_locked(ctx, mono_ns, realtime_ns, &old_its);

    ctx->interval_ns = interval_ns;
    ctx->expirations = 0;
    if (value_ns == 0) {
        ctx->armed = false;
        ctx->next_expire_ns = 0;
    } else {
        uint64_t first_ns = value_ns;
        if (!(flags & TFD_TIMER_ABSTIME)) {
            first_ns = u64_add_sat(timerfd_now_ns(ctx->clockid, mono_ns, realtime_ns),
                                   value_ns);
        }
        ctx->armed = true;
        ctx->next_expire_ns = first_ns;
        if (timerfd_refresh_locked(ctx, mono_ns, realtime_ns))
            wake = true;
    }
    spin_unlock_irqrestore(&ctx->lock, irq);

    if (old_ptr &&
        copy_to_user((void *)old_ptr, &old_its, sizeof(old_its)) < 0) {
        file_put(file);
        return -EFAULT;
    }
    if (wake) {
        wait_queue_wakeup_all(&ctx->rd_wait);
        vfs_poll_wake(ctx->vnode, POLLIN);
    }
    file_put(file);
    return 0;
}

int64_t sys_timerfd_gettime(uint64_t fd, uint64_t curr_ptr, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!curr_ptr)
        return -EFAULT;

    struct file *file = fd_get(proc_current(), (int)fd);
    if (!file)
        return -EBADF;
    if (!file->vnode) {
        file_put(file);
        return -EINVAL;
    }
    struct timerfd_ctx *ctx = (struct timerfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != TIMERFD_MAGIC) {
        file_put(file);
        return -EINVAL;
    }

    uint64_t mono_ns = time_now_ns();
    uint64_t realtime_ns = time_realtime_ns();
    struct linux_itimerspec curr = {0};

    bool irq;
    spin_lock_irqsave(&ctx->lock, &irq);
    (void)timerfd_refresh_locked(ctx, mono_ns, realtime_ns);
    timerfd_fill_curr_locked(ctx, mono_ns, realtime_ns, &curr);
    spin_unlock_irqrestore(&ctx->lock, irq);

    if (copy_to_user((void *)curr_ptr, &curr, sizeof(curr)) < 0) {
        file_put(file);
        return -EFAULT;
    }
    file_put(file);
    return 0;
}
