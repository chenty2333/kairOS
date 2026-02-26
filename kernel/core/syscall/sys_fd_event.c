#include <kairos/arch.h>
#include <kairos/dentry.h>
#include <kairos/handle_bridge.h>
#include <kairos/inotify.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/namei.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/time.h>
#include <kairos/tracepoint.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>
#include <kairos/wait.h>

#include "sys_fs_helpers.h"

#define NS_PER_SEC 1000000000ULL

#define EFD_SEMAPHORE 0x1
#define EFD_CLOEXEC O_CLOEXEC
#define EFD_NONBLOCK O_NONBLOCK

#define TFD_TIMER_ABSTIME 0x1
#define TFD_TIMER_CANCEL_ON_SET 0x2
#define TFD_CLOEXEC O_CLOEXEC
#define TFD_NONBLOCK O_NONBLOCK

#define SFD_CLOEXEC O_CLOEXEC
#define SFD_NONBLOCK O_NONBLOCK

#define EVENTFD_COUNTER_MAX (UINT64_MAX - 1ULL)
#define EVENTFD_MAGIC 0x65766466U
#define TIMERFD_MAGIC 0x746d6664U
#define SIGNALFD_MAGIC 0x73666466U
#define INOTIFY_MAGIC 0x696e6664U

#define INOTIFY_Q_MAX_BYTES (64U * 1024U)

static inline int sysfd_abi_int32(uint64_t v) {
    return (int32_t)(uint32_t)v;
}

struct linux_itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

struct linux_signalfd_siginfo {
    uint32_t ssi_signo;
    int32_t ssi_errno;
    int32_t ssi_code;
    uint32_t ssi_pid;
    uint32_t ssi_uid;
    int32_t ssi_fd;
    uint32_t ssi_tid;
    uint32_t ssi_band;
    uint32_t ssi_overrun;
    uint32_t ssi_trapno;
    int32_t ssi_status;
    int32_t ssi_int;
    uint64_t ssi_ptr;
    uint64_t ssi_utime;
    uint64_t ssi_stime;
    uint64_t ssi_addr;
    uint16_t ssi_addr_lsb;
    uint16_t __pad2;
    int32_t ssi_syscall;
    uint64_t ssi_call_addr;
    uint32_t ssi_arch;
    uint8_t __pad[128 - 14 * 4 - 5 * 8 - 2 * 2];
};

struct linux_inotify_event {
    int32_t wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len;
};

struct eventfd_ctx {
    uint32_t magic;
    spinlock_t lock;
    struct poll_wait_source rd_src;
    struct poll_wait_source wr_src;
    uint64_t counter;
    bool semaphore;
    bool closed;
};

struct timerfd_ctx {
    uint32_t magic;
    spinlock_t lock;
    struct poll_wait_source rd_src;
    struct list_head list;
    uint64_t interval_ns;
    uint64_t next_expire_ns;
    uint64_t expirations;
    uint64_t realtime_gen;
    int clockid;
    bool cancel_on_set;
    bool canceled;
    bool armed;
    bool closed;
};

struct signalfd_ctx {
    uint32_t magic;
    spinlock_t lock;
    struct poll_wait_source rd_src;
    struct list_head node;
    sigset_t mask;
    bool closed;
};

struct inotify_watch {
    struct list_head node;
    int wd;
    struct vnode *vn;
    uint32_t mask;
};

struct inotify_event_node {
    struct list_head node;
    int wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len;
    char name[CONFIG_NAME_MAX];
};

struct inotify_ctx {
    uint32_t magic;
    struct mutex lock;
    struct poll_wait_source rd_src;
    struct list_head node;
    struct list_head watches;
    struct list_head events;
    size_t queued_bytes;
    int next_wd;
    bool overflow_pending;
    bool closed;
};

static LIST_HEAD(timerfd_list);
static spinlock_t timerfd_list_lock = SPINLOCK_INIT;
static LIST_HEAD(signalfd_instances);
static spinlock_t signalfd_instances_lock = SPINLOCK_INIT;
static struct list_head inotify_instances;
static struct mutex inotify_instances_lock;
static spinlock_t inotify_init_lock = SPINLOCK_INIT;
static bool inotify_ready;
static uint32_t inotify_cookie_seed;

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

static int signalfd_close(struct vnode *vn);
static int signalfd_poll(struct file *file, uint32_t events);
static ssize_t signalfd_fread(struct file *file, void *buf, size_t len);

static struct file_ops signalfd_file_ops = {
    .close = signalfd_close,
    .fread = signalfd_fread,
    .poll = signalfd_poll,
};

static int inotify_close(struct vnode *vn);
static int inotify_poll(struct file *file, uint32_t events);
static ssize_t inotify_fread(struct file *file, void *buf, size_t len);

static struct file_ops inotify_file_ops = {
    .close = inotify_close,
    .fread = inotify_fread,
    .poll = inotify_poll,
};

enum fd_event_wait_kind {
    FD_EVENT_WAIT_EVENTFD_READ = 1,
    FD_EVENT_WAIT_EVENTFD_WRITE = 2,
    FD_EVENT_WAIT_TIMERFD_READ = 3,
    FD_EVENT_WAIT_SIGNALFD_READ = 4,
    FD_EVENT_WAIT_INOTIFY_READ = 5,
};

#define FD_EVENT_TRACE_BLOCK 0x0001U
#define FD_EVENT_TRACE_WAKE 0x0002U
#define FD_EVENT_TRACE_KIND_SHIFT 8

static inline uint32_t
fd_event_trace_flags(uint32_t action, enum fd_event_wait_kind kind) {
    return action | ((uint32_t)kind << FD_EVENT_TRACE_KIND_SHIFT);
}

static inline void fd_event_note_block(enum poll_wait_stat stat,
                                       enum fd_event_wait_kind kind,
                                       const void *ctx) {
    poll_wait_stat_inc(stat);
    tracepoint_emit(TRACE_WAIT_FD_EVENT,
                    fd_event_trace_flags(FD_EVENT_TRACE_BLOCK, kind), 0,
                    (uint64_t)(uintptr_t)ctx);
}

static inline void fd_event_note_wake(enum poll_wait_stat stat,
                                      enum fd_event_wait_kind kind,
                                      uint32_t events, const void *ctx) {
    poll_wait_stat_inc(stat);
    tracepoint_emit(TRACE_WAIT_FD_EVENT,
                    fd_event_trace_flags(FD_EVENT_TRACE_WAKE, kind),
                    (uint64_t)events, (uint64_t)(uintptr_t)ctx);
}

static inline void fd_event_wake_all(struct poll_wait_source *src,
                                     uint32_t events, enum poll_wait_stat stat,
                                     enum fd_event_wait_kind kind,
                                     const void *ctx) {
    if (!src)
        return;
    fd_event_note_wake(stat, kind, events, ctx);
    poll_wait_source_wake_all(src, events);
}

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
        fd_event_wake_all(&ctx->rd_src, POLLIN | POLLOUT | POLLHUP,
                          POLL_WAIT_STAT_FDEVENT_EVENTFD_RD_WAKES,
                          FD_EVENT_WAIT_EVENTFD_READ, ctx);
        fd_event_wake_all(&ctx->wr_src, 0,
                          POLL_WAIT_STAT_FDEVENT_EVENTFD_WR_WAKES,
                          FD_EVENT_WAIT_EVENTFD_WRITE, ctx);
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
            fd_event_wake_all(&ctx->wr_src, POLLOUT,
                              POLL_WAIT_STAT_FDEVENT_EVENTFD_WR_WAKES,
                              FD_EVENT_WAIT_EVENTFD_WRITE, ctx);
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
        fd_event_note_block(POLL_WAIT_STAT_FDEVENT_EVENTFD_R_BLOCKS,
                            FD_EVENT_WAIT_EVENTFD_READ, ctx);
        int rc = poll_wait_source_block(&ctx->rd_src, 0, ctx, &file->lock);
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
                fd_event_wake_all(&ctx->rd_src, POLLIN,
                                  POLL_WAIT_STAT_FDEVENT_EVENTFD_RD_WAKES,
                                  FD_EVENT_WAIT_EVENTFD_READ, ctx);
            }
            return (ssize_t)sizeof(uint64_t);
        }
        bool nonblock = (file->flags & O_NONBLOCK) != 0;
        spin_unlock_irqrestore(&ctx->lock, irq);
        if (nonblock)
            return -EAGAIN;
        fd_event_note_block(POLL_WAIT_STAT_FDEVENT_EVENTFD_W_BLOCKS,
                            FD_EVENT_WAIT_EVENTFD_WRITE, ctx);
        int rc = poll_wait_source_block(&ctx->wr_src, 0, ctx, &file->lock);
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
    poll_wait_source_init(&ctx->rd_src, vn);
    poll_wait_source_init(&ctx->wr_src, NULL);
    ctx->counter = initval;
    ctx->semaphore = (flags & EFD_SEMAPHORE) != 0;
    ctx->closed = false;

    vn->type = VNODE_FILE;
    vn->mode = S_IFREG | 0600;
    vn->nlink = 1;
    vn->ops = &eventfd_file_ops;
    vn->fs_data = ctx;
    atomic_init(&vn->refcount, 1);
    vn->kobj = NULL;
    atomic_init(&vn->kobj_state, 0);
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

static sigset_t signalfd_sanitize_mask(sigset_t mask) {
    sigset_t allowed = UINT64_MAX;
    if (NSIG < 64)
        allowed = (1ULL << NSIG) - 1ULL;
    mask &= allowed;
    mask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    return mask;
}

static bool signalfd_take_signal(struct process *p, sigset_t mask, int *sig_out) {
    if (!p || !sig_out)
        return false;

    while (1) {
        sigset_t pending = __atomic_load_n(&p->sig_pending, __ATOMIC_ACQUIRE);
        sigset_t ready = pending & mask;
        if (!ready)
            return false;
        int bit = __builtin_ctzll(ready);
        sigset_t clear = ~(1ULL << bit);
        sigset_t expected = pending;
        sigset_t desired = pending & clear;
        if (__atomic_compare_exchange_n(&p->sig_pending, &expected, desired,
                                        false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE)) {
            *sig_out = bit + 1;
            return true;
        }
    }
}

static int signalfd_close(struct vnode *vn) {
    if (!vn)
        return 0;
    struct signalfd_ctx *ctx = (struct signalfd_ctx *)vn->fs_data;
    if (ctx && ctx->magic == SIGNALFD_MAGIC) {
        bool list_irq;
        spin_lock_irqsave(&signalfd_instances_lock, &list_irq);
        if (!list_empty(&ctx->node))
            list_del(&ctx->node);
        spin_unlock_irqrestore(&signalfd_instances_lock, list_irq);

        bool irq;
        spin_lock_irqsave(&ctx->lock, &irq);
        ctx->closed = true;
        spin_unlock_irqrestore(&ctx->lock, irq);
        fd_event_wake_all(&ctx->rd_src, POLLIN | POLLHUP,
                          POLL_WAIT_STAT_FDEVENT_SIGNALFD_RD_WAKES,
                          FD_EVENT_WAIT_SIGNALFD_READ, ctx);
        ctx->magic = 0;
        kfree(ctx);
    }
    kfree(vn);
    return 0;
}

static int signalfd_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;
    struct signalfd_ctx *ctx = (struct signalfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != SIGNALFD_MAGIC)
        return POLLNVAL;

    struct process *p = proc_current();
    if (!p)
        return POLLNVAL;

    sigset_t mask;
    bool closed;
    bool irq;
    spin_lock_irqsave(&ctx->lock, &irq);
    mask = ctx->mask;
    closed = ctx->closed;
    spin_unlock_irqrestore(&ctx->lock, irq);

    sigset_t pending = __atomic_load_n(&p->sig_pending, __ATOMIC_ACQUIRE);
    uint32_t revents = 0;
    if (pending & mask)
        revents |= POLLIN;
    if (closed)
        revents |= POLLHUP;
    return (int)(revents & events);
}

static void signalfd_fill_siginfo(struct linux_signalfd_siginfo *info, int sig) {
    memset(info, 0, sizeof(*info));
    info->ssi_signo = (uint32_t)sig;
}

static ssize_t signalfd_fread(struct file *file, void *buf, size_t len) {
    if (!file || !file->vnode || !buf)
        return -EINVAL;
    if (len < sizeof(struct linux_signalfd_siginfo))
        return -EINVAL;

    struct signalfd_ctx *ctx = (struct signalfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != SIGNALFD_MAGIC)
        return -EINVAL;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    size_t max_entries = len / sizeof(struct linux_signalfd_siginfo);
    while (1) {
        sigset_t mask = 0;
        bool closed = false;
        bool irq;
        spin_lock_irqsave(&ctx->lock, &irq);
        mask = ctx->mask;
        closed = ctx->closed;
        spin_unlock_irqrestore(&ctx->lock, irq);
        if (closed)
            return -EINVAL;

        size_t emitted = 0;
        uint8_t *dst = (uint8_t *)buf;
        while (emitted < max_entries) {
            int sig = 0;
            if (!signalfd_take_signal(p, mask, &sig))
                break;
            struct linux_signalfd_siginfo info;
            signalfd_fill_siginfo(&info, sig);
            memcpy(dst + emitted * sizeof(info), &info, sizeof(info));
            emitted++;
        }
        if (emitted > 0)
            return (ssize_t)(emitted * sizeof(struct linux_signalfd_siginfo));

        if (file->flags & O_NONBLOCK)
            return -EAGAIN;
        fd_event_note_block(POLL_WAIT_STAT_FDEVENT_SIGNALFD_R_BLOCKS,
                            FD_EVENT_WAIT_SIGNALFD_READ, ctx);
        int rc = poll_wait_source_block(&ctx->rd_src, 0, p, &file->lock);
        if (rc < 0)
            return rc;
    }
}

static int signalfd_create_file(sigset_t mask, uint64_t flags, struct file **out) {
    struct signalfd_ctx *ctx = kzalloc(sizeof(*ctx));
    struct vnode *vn = kzalloc(sizeof(*vn));
    struct file *file = vfs_file_alloc();
    if (!ctx || !vn || !file) {
        kfree(ctx);
        kfree(vn);
        if (file)
            vfs_file_free(file);
        return -ENOMEM;
    }

    ctx->magic = SIGNALFD_MAGIC;
    spin_init(&ctx->lock);
    poll_wait_source_init(&ctx->rd_src, vn);
    INIT_LIST_HEAD(&ctx->node);
    ctx->mask = signalfd_sanitize_mask(mask);
    ctx->closed = false;

    bool irq;
    spin_lock_irqsave(&signalfd_instances_lock, &irq);
    list_add_tail(&ctx->node, &signalfd_instances);
    spin_unlock_irqrestore(&signalfd_instances_lock, irq);

    vn->type = VNODE_FILE;
    vn->mode = S_IFREG | 0600;
    vn->nlink = 1;
    vn->ops = &signalfd_file_ops;
    vn->fs_data = ctx;
    atomic_init(&vn->refcount, 1);
    vn->kobj = NULL;
    atomic_init(&vn->kobj_state, 0);
    vn->parent = NULL;
    vn->name[0] = '\0';
    rwlock_init(&vn->lock, "signalfd_vnode");
    poll_wait_head_init(&vn->pollers);

    file->vnode = vn;
    file->flags = O_RDONLY;
    if (flags & SFD_NONBLOCK)
        file->flags |= O_NONBLOCK;
    *out = file;
    return 0;
}

void signalfd_notify_pending_signal(struct process *p, int sig) {
    if (!p || sig <= 0 || sig > NSIG)
        return;
    uint64_t sigmask = 1ULL << (sig - 1);

    bool irq;
    spin_lock_irqsave(&signalfd_instances_lock, &irq);
    struct signalfd_ctx *ctx;
    list_for_each_entry(ctx, &signalfd_instances, node) {
        bool ctx_irq;
        bool wake = false;
        spin_lock_irqsave(&ctx->lock, &ctx_irq);
        if (!ctx->closed && (ctx->mask & sigmask))
            wake = true;
        spin_unlock_irqrestore(&ctx->lock, ctx_irq);
        if (wake)
            fd_event_wake_all(&ctx->rd_src, POLLIN,
                              POLL_WAIT_STAT_FDEVENT_SIGNALFD_RD_WAKES,
                              FD_EVENT_WAIT_SIGNALFD_READ, ctx);
    }
    spin_unlock_irqrestore(&signalfd_instances_lock, irq);
}

static void inotify_global_init(void) {
    if (__atomic_load_n(&inotify_ready, __ATOMIC_ACQUIRE))
        return;
    bool irq;
    spin_lock_irqsave(&inotify_init_lock, &irq);
    if (__atomic_load_n(&inotify_ready, __ATOMIC_RELAXED)) {
        spin_unlock_irqrestore(&inotify_init_lock, irq);
        return;
    }
    mutex_init(&inotify_instances_lock, "inotify_instances");
    INIT_LIST_HEAD(&inotify_instances);
    inotify_cookie_seed = 0;
    __atomic_store_n(&inotify_ready, true, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&inotify_init_lock, irq);
}

uint32_t inotify_next_cookie(void) {
    inotify_global_init();
    uint32_t cookie = __atomic_add_fetch(&inotify_cookie_seed, 1, __ATOMIC_RELAXED);
    if (cookie == 0)
        cookie = __atomic_add_fetch(&inotify_cookie_seed, 1, __ATOMIC_RELAXED);
    return cookie;
}

static size_t inotify_name_payload_len(const char *name) {
    if (!name || !name[0])
        return 0;
    size_t n = strnlen(name, CONFIG_NAME_MAX - 1) + 1;
    size_t align = sizeof(uint32_t) - 1;
    return (n + align) & ~align;
}

static size_t inotify_event_size(const struct inotify_event_node *ev) {
    return sizeof(struct linux_inotify_event) + (size_t)ev->len;
}

static struct inotify_watch *inotify_find_watch_by_wd(struct inotify_ctx *ctx,
                                                      int wd) {
    if (!ctx)
        return NULL;
    struct inotify_watch *watch;
    list_for_each_entry(watch, &ctx->watches, node) {
        if (watch->wd == wd)
            return watch;
    }
    return NULL;
}

static struct inotify_watch *inotify_find_watch_by_vnode(struct inotify_ctx *ctx,
                                                         struct vnode *vn) {
    if (!ctx || !vn)
        return NULL;
    struct inotify_watch *watch;
    list_for_each_entry(watch, &ctx->watches, node) {
        if (watch->vn == vn)
            return watch;
    }
    return NULL;
}

static void inotify_queue_event_locked(struct inotify_ctx *ctx, int wd,
                                       uint32_t mask, uint32_t cookie,
                                       const char *name) {
    if (!ctx || ctx->closed)
        return;

    size_t payload = inotify_name_payload_len(name);
    size_t need = sizeof(struct linux_inotify_event) + payload;
    if (ctx->queued_bytes + need > INOTIFY_Q_MAX_BYTES) {
        if (ctx->overflow_pending)
            return;
        struct inotify_event_node *overflow = kzalloc(sizeof(*overflow));
        if (!overflow)
            return;
        overflow->wd = -1;
        overflow->mask = IN_Q_OVERFLOW;
        overflow->cookie = 0;
        overflow->len = 0;
        list_add_tail(&overflow->node, &ctx->events);
        ctx->queued_bytes += sizeof(struct linux_inotify_event);
        ctx->overflow_pending = true;
        fd_event_wake_all(&ctx->rd_src, POLLIN,
                          POLL_WAIT_STAT_FDEVENT_INOTIFY_RD_WAKES,
                          FD_EVENT_WAIT_INOTIFY_READ, ctx);
        return;
    }

    struct inotify_event_node *ev = kzalloc(sizeof(*ev));
    if (!ev)
        return;

    ev->wd = wd;
    ev->mask = mask;
    ev->cookie = cookie;
    ev->len = (uint32_t)payload;
    if (payload > 0 && name) {
        size_t n = strnlen(name, CONFIG_NAME_MAX - 1);
        memcpy(ev->name, name, n);
        ev->name[n] = '\0';
    }

    list_add_tail(&ev->node, &ctx->events);
    ctx->queued_bytes += need;
    fd_event_wake_all(&ctx->rd_src, POLLIN,
                      POLL_WAIT_STAT_FDEVENT_INOTIFY_RD_WAKES,
                      FD_EVENT_WAIT_INOTIFY_READ, ctx);
}

static void inotify_watch_destroy(struct inotify_watch *watch) {
    if (!watch)
        return;
    if (watch->vn)
        vnode_put(watch->vn);
    kfree(watch);
}

static void inotify_remove_watch_locked(struct inotify_ctx *ctx,
                                        struct inotify_watch *watch,
                                        bool emit_ignored) {
    if (!ctx || !watch)
        return;
    int wd = watch->wd;
    list_del(&watch->node);
    inotify_watch_destroy(watch);
    if (emit_ignored)
        inotify_queue_event_locked(ctx, wd, IN_IGNORED, 0, NULL);
}

static void inotify_drop_all_locked(struct inotify_ctx *ctx) {
    if (!ctx)
        return;
    struct inotify_watch *watch, *wtmp;
    list_for_each_entry_safe(watch, wtmp, &ctx->watches, node) {
        list_del(&watch->node);
        inotify_watch_destroy(watch);
    }
    struct inotify_event_node *ev, *etmp;
    list_for_each_entry_safe(ev, etmp, &ctx->events, node) {
        list_del(&ev->node);
        kfree(ev);
    }
    ctx->queued_bytes = 0;
    ctx->overflow_pending = false;
}

static int inotify_close(struct vnode *vn) {
    if (!vn)
        return 0;
    struct inotify_ctx *ctx = (struct inotify_ctx *)vn->fs_data;
    if (ctx && ctx->magic == INOTIFY_MAGIC) {
        inotify_global_init();
        mutex_lock(&inotify_instances_lock);
        if (!list_empty(&ctx->node))
            list_del(&ctx->node);
        mutex_unlock(&inotify_instances_lock);

        mutex_lock(&ctx->lock);
        ctx->closed = true;
        inotify_drop_all_locked(ctx);
        mutex_unlock(&ctx->lock);

        fd_event_wake_all(&ctx->rd_src, POLLIN | POLLHUP,
                          POLL_WAIT_STAT_FDEVENT_INOTIFY_RD_WAKES,
                          FD_EVENT_WAIT_INOTIFY_READ, ctx);
        ctx->magic = 0;
        kfree(ctx);
    }
    kfree(vn);
    return 0;
}

static int inotify_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;
    struct inotify_ctx *ctx = (struct inotify_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != INOTIFY_MAGIC)
        return POLLNVAL;

    uint32_t revents = 0;
    mutex_lock(&ctx->lock);
    if (!list_empty(&ctx->events))
        revents |= POLLIN;
    if (ctx->closed)
        revents |= POLLHUP;
    mutex_unlock(&ctx->lock);
    return (int)(revents & events);
}

static ssize_t inotify_fread(struct file *file, void *buf, size_t len) {
    if (!file || !file->vnode || !buf)
        return -EINVAL;
    if (len < sizeof(struct linux_inotify_event))
        return -EINVAL;

    struct inotify_ctx *ctx = (struct inotify_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != INOTIFY_MAGIC)
        return -EINVAL;

    while (1) {
        mutex_lock(&ctx->lock);
        if (!list_empty(&ctx->events)) {
            size_t copied = 0;
            uint8_t *dst = (uint8_t *)buf;
            struct inotify_event_node *ev, *tmp;
            list_for_each_entry_safe(ev, tmp, &ctx->events, node) {
                size_t need = inotify_event_size(ev);
                if (copied == 0 && need > len) {
                    mutex_unlock(&ctx->lock);
                    return -EINVAL;
                }
                if (copied + need > len)
                    break;

                struct linux_inotify_event hdr = {
                    .wd = ev->wd,
                    .mask = ev->mask,
                    .cookie = ev->cookie,
                    .len = ev->len,
                };
                memcpy(dst + copied, &hdr, sizeof(hdr));
                copied += sizeof(hdr);
                if (ev->len > 0) {
                    memcpy(dst + copied, ev->name, ev->len);
                    copied += ev->len;
                }

                list_del(&ev->node);
                ctx->queued_bytes -= need;
                if (ev->mask == IN_Q_OVERFLOW)
                    ctx->overflow_pending = false;
                kfree(ev);
            }
            mutex_unlock(&ctx->lock);
            return (ssize_t)copied;
        }

        if (ctx->closed) {
            mutex_unlock(&ctx->lock);
            return -EINVAL;
        }
        bool nonblock = (file->flags & O_NONBLOCK) != 0;
        mutex_unlock(&ctx->lock);
        if (nonblock)
            return -EAGAIN;

        fd_event_note_block(POLL_WAIT_STAT_FDEVENT_INOTIFY_R_BLOCKS,
                            FD_EVENT_WAIT_INOTIFY_READ, ctx);
        int rc = poll_wait_source_block(&ctx->rd_src, 0, ctx, &file->lock);
        if (rc < 0)
            return rc;
    }
}

static int inotify_create_file(uint64_t flags, struct file **out) {
    inotify_global_init();

    struct inotify_ctx *ctx = kzalloc(sizeof(*ctx));
    struct vnode *vn = kzalloc(sizeof(*vn));
    struct file *file = vfs_file_alloc();
    if (!ctx || !vn || !file) {
        kfree(ctx);
        kfree(vn);
        if (file)
            vfs_file_free(file);
        return -ENOMEM;
    }

    ctx->magic = INOTIFY_MAGIC;
    mutex_init(&ctx->lock, "inotify");
    poll_wait_source_init(&ctx->rd_src, vn);
    INIT_LIST_HEAD(&ctx->node);
    INIT_LIST_HEAD(&ctx->watches);
    INIT_LIST_HEAD(&ctx->events);
    ctx->queued_bytes = 0;
    ctx->next_wd = 1;
    ctx->overflow_pending = false;
    ctx->closed = false;

    mutex_lock(&inotify_instances_lock);
    list_add_tail(&ctx->node, &inotify_instances);
    mutex_unlock(&inotify_instances_lock);

    vn->type = VNODE_FILE;
    vn->mode = S_IFREG | 0600;
    vn->nlink = 1;
    vn->ops = &inotify_file_ops;
    vn->fs_data = ctx;
    atomic_init(&vn->refcount, 1);
    vn->kobj = NULL;
    atomic_init(&vn->kobj_state, 0);
    vn->parent = NULL;
    vn->name[0] = '\0';
    rwlock_init(&vn->lock, "inotify_vnode");
    poll_wait_head_init(&vn->pollers);

    file->vnode = vn;
    file->flags = O_RDONLY;
    if (flags & IN_NONBLOCK)
        file->flags |= O_NONBLOCK;
    *out = file;
    return 0;
}

void inotify_fsnotify(struct vnode *vn, const char *name, uint32_t mask,
                      uint32_t cookie) {
    if (!vn || !(mask & (IN_ALL_EVENTS | IN_IGNORED | IN_Q_OVERFLOW)))
        return;
    inotify_global_init();

    char stable_name[CONFIG_NAME_MAX];
    stable_name[0] = '\0';
    if (name) {
        strncpy(stable_name, name, sizeof(stable_name) - 1);
        stable_name[sizeof(stable_name) - 1] = '\0';
    }

    mutex_lock(&inotify_instances_lock);
    struct inotify_ctx *ctx;
    list_for_each_entry(ctx, &inotify_instances, node) {
        mutex_lock(&ctx->lock);
        if (ctx->closed) {
            mutex_unlock(&ctx->lock);
            continue;
        }
        struct inotify_watch *watch, *tmp;
        list_for_each_entry_safe(watch, tmp, &ctx->watches, node) {
            if (watch->vn != vn)
                continue;
            uint32_t event_bits = mask & IN_ALL_EVENTS;
            if (event_bits && !(watch->mask & event_bits))
                continue;
            inotify_queue_event_locked(ctx, watch->wd, mask, cookie,
                                       stable_name[0] ? stable_name : NULL);
            if (watch->mask & IN_ONESHOT)
                inotify_remove_watch_locked(ctx, watch, true);
        }
        mutex_unlock(&ctx->lock);
    }
    mutex_unlock(&inotify_instances_lock);
}

static uint64_t timerfd_now_ns(int clockid, uint64_t mono_ns, uint64_t realtime_ns) {
    if (clockid == CLOCK_REALTIME)
        return realtime_ns;
    return mono_ns;
}

static int timerfd_normalize_clockid(uint64_t clockid, int *out_clockid) {
    if (!out_clockid)
        return -EINVAL;
    switch (clockid) {
    case CLOCK_REALTIME:
    case CLOCK_REALTIME_ALARM:
        *out_clockid = CLOCK_REALTIME;
        return 0;
    case CLOCK_MONOTONIC:
    case CLOCK_BOOTTIME:
    case CLOCK_BOOTTIME_ALARM:
        *out_clockid = CLOCK_MONOTONIC;
        return 0;
    default:
        return -EINVAL;
    }
}

static bool timerfd_cancel_on_set_locked(struct timerfd_ctx *ctx,
                                         uint64_t realtime_gen) {
    if (!ctx || !ctx->armed || !ctx->cancel_on_set ||
        ctx->clockid != CLOCK_REALTIME) {
        return false;
    }
    if (ctx->realtime_gen == realtime_gen)
        return false;

    ctx->armed = false;
    ctx->next_expire_ns = 0;
    ctx->interval_ns = 0;
    ctx->expirations = 0;
    ctx->cancel_on_set = false;
    ctx->canceled = true;
    return true;
}

static bool timerfd_refresh_locked(struct timerfd_ctx *ctx, uint64_t mono_ns,
                                   uint64_t realtime_ns) {
    if (!ctx)
        return false;

    if (timerfd_cancel_on_set_locked(ctx, time_realtime_generation()))
        return true;

    if (!ctx->armed)
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
        fd_event_wake_all(&ctx->rd_src, POLLIN | POLLHUP,
                          POLL_WAIT_STAT_FDEVENT_TIMERFD_RD_WAKES,
                          FD_EVENT_WAIT_TIMERFD_READ, ctx);

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
    uint32_t revents = (ctx->expirations > 0 || ctx->canceled) ? POLLIN : 0;
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
        if (ctx->canceled) {
            spin_unlock_irqrestore(&ctx->lock, irq);
            return -ECANCELED;
        }
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
        fd_event_note_block(POLL_WAIT_STAT_FDEVENT_TIMERFD_R_BLOCKS,
                            FD_EVENT_WAIT_TIMERFD_READ, ctx);
        int rc = poll_wait_source_block(&ctx->rd_src, 0, ctx, &file->lock);
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
    poll_wait_source_init(&ctx->rd_src, vn);
    INIT_LIST_HEAD(&ctx->list);
    ctx->clockid = clockid;
    ctx->interval_ns = 0;
    ctx->next_expire_ns = 0;
    ctx->expirations = 0;
    ctx->realtime_gen = time_realtime_generation();
    ctx->cancel_on_set = false;
    ctx->canceled = false;
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
    vn->kobj = NULL;
    atomic_init(&vn->kobj_state, 0);
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
            fd_event_wake_all(&ctx->rd_src, POLLIN,
                              POLL_WAIT_STAT_FDEVENT_TIMERFD_RD_WAKES,
                              FD_EVENT_WAIT_TIMERFD_READ, ctx);
        }
    }
    spin_unlock_irqrestore(&timerfd_list_lock, irq);
}

int64_t sys_eventfd2(uint64_t initval, uint64_t flags, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    uint32_t uflags = (uint32_t)flags;
    if (uflags & ~(EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK))
        return -EINVAL;

    struct file *file = NULL;
    int rc = eventfd_create_file((uint32_t)initval, uflags, &file);
    if (rc < 0)
        return rc;

    uint32_t fd_flags = (uflags & EFD_CLOEXEC) ? FD_CLOEXEC : 0;
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
    uint32_t uflags = (uint32_t)flags;
    if (uflags & ~(TFD_CLOEXEC | TFD_NONBLOCK))
        return -EINVAL;

    int norm_clockid = 0;
    int clock_rc = timerfd_normalize_clockid(clockid, &norm_clockid);
    if (clock_rc < 0)
        return clock_rc;

    struct file *file = NULL;
    int rc = timerfd_create_file(norm_clockid, uflags, &file);
    if (rc < 0)
        return rc;

    uint32_t fd_flags = (uflags & TFD_CLOEXEC) ? FD_CLOEXEC : 0;
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
    int kfd = sysfd_abi_int32(fd);
    uint32_t uflags = (uint32_t)flags;
    if (uflags & ~(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET))
        return -EINVAL;
    if (!new_ptr)
        return -EFAULT;

    struct file *file = NULL;
    int frc = handle_bridge_pin_fd(proc_current(), kfd, 0, &file, NULL);
    if (frc < 0)
        return frc;
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

    bool cancel_on_set = (uflags & TFD_TIMER_CANCEL_ON_SET) != 0;
    if (cancel_on_set && !(uflags & TFD_TIMER_ABSTIME)) {
        file_put(file);
        return -EINVAL;
    }
    if (cancel_on_set && ctx->clockid != CLOCK_REALTIME) {
        file_put(file);
        return -EINVAL;
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

    ctx->canceled = false;
    ctx->interval_ns = interval_ns;
    ctx->expirations = 0;
    ctx->realtime_gen = time_realtime_generation();
    ctx->cancel_on_set = cancel_on_set;
    if (value_ns == 0) {
        ctx->armed = false;
        ctx->next_expire_ns = 0;
        ctx->cancel_on_set = false;
    } else {
        uint64_t first_ns = value_ns;
        if (!(uflags & TFD_TIMER_ABSTIME)) {
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
        fd_event_wake_all(&ctx->rd_src, POLLIN,
                          POLL_WAIT_STAT_FDEVENT_TIMERFD_RD_WAKES,
                          FD_EVENT_WAIT_TIMERFD_READ, ctx);
    }
    file_put(file);
    return 0;
}

int64_t sys_timerfd_gettime(uint64_t fd, uint64_t curr_ptr, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    int kfd = sysfd_abi_int32(fd);
    if (!curr_ptr)
        return -EFAULT;

    struct file *file = NULL;
    int frc = handle_bridge_pin_fd(proc_current(), kfd, 0, &file, NULL);
    if (frc < 0)
        return frc;
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

int64_t sys_signalfd4(uint64_t fd, uint64_t mask_ptr, uint64_t sigsetsize,
                      uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    int kfd = sysfd_abi_int32(fd);
    if (!mask_ptr)
        return -EFAULT;
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;
    uint32_t uflags = (uint32_t)flags;
    if (uflags & ~(SFD_CLOEXEC | SFD_NONBLOCK))
        return -EINVAL;

    sigset_t mask = 0;
    if (copy_from_user(&mask, (const void *)mask_ptr, sizeof(mask)) < 0)
        return -EFAULT;
    mask = signalfd_sanitize_mask(mask);

    if (kfd == -1) {
        struct file *file = NULL;
        int rc = signalfd_create_file(mask, uflags, &file);
        if (rc < 0)
            return rc;

        uint32_t fd_flags = (uflags & SFD_CLOEXEC) ? FD_CLOEXEC : 0;
        int newfd = fd_alloc_flags(proc_current(), file, fd_flags);
        if (newfd < 0) {
            vfs_close(file);
            return newfd;
        }
        return newfd;
    }

    struct file *file = NULL;
    int frc = handle_bridge_pin_fd(proc_current(), kfd, 0, &file, NULL);
    if (frc < 0)
        return frc;
    if (!file->vnode) {
        file_put(file);
        return -EINVAL;
    }
    struct signalfd_ctx *ctx = (struct signalfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != SIGNALFD_MAGIC) {
        file_put(file);
        return -EINVAL;
    }

    bool irq;
    spin_lock_irqsave(&ctx->lock, &irq);
    ctx->mask = mask;
    spin_unlock_irqrestore(&ctx->lock, irq);
    fd_event_wake_all(&ctx->rd_src, POLLIN,
                      POLL_WAIT_STAT_FDEVENT_SIGNALFD_RD_WAKES,
                      FD_EVENT_WAIT_SIGNALFD_READ, ctx);
    file_put(file);
    return (int64_t)kfd;
}

static struct inotify_ctx *inotify_ctx_from_fd(struct file *file) {
    if (!file || !file->vnode)
        return NULL;
    struct inotify_ctx *ctx = (struct inotify_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != INOTIFY_MAGIC)
        return NULL;
    return ctx;
}

int64_t sys_inotify_init1(uint64_t flags, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    uint32_t uflags = (uint32_t)flags;
    if (uflags & ~(IN_CLOEXEC | IN_NONBLOCK))
        return -EINVAL;

    struct file *file = NULL;
    int rc = inotify_create_file(uflags, &file);
    if (rc < 0)
        return rc;

    uint32_t fd_flags = (uflags & IN_CLOEXEC) ? FD_CLOEXEC : 0;
    int fd = fd_alloc_flags(proc_current(), file, fd_flags);
    if (fd < 0) {
        vfs_close(file);
        return fd;
    }
    return fd;
}

int64_t sys_inotify_add_watch(uint64_t fd, uint64_t path_ptr, uint64_t mask,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int kfd = sysfd_abi_int32(fd);
    if (!path_ptr)
        return -EFAULT;
    if ((mask & IN_MASK_ADD) && (mask & IN_MASK_CREATE))
        return -EINVAL;

    uint32_t watch_mask = (uint32_t)(mask & (IN_ALL_EVENTS | IN_ONESHOT |
                                             IN_EXCL_UNLINK));
    if ((watch_mask & IN_ALL_EVENTS) == 0)
        return -EINVAL;

    struct path resolved;
    path_init(&resolved);
    int nflags = NAMEI_FOLLOW;
    if (mask & IN_DONT_FOLLOW)
        nflags = NAMEI_NOFOLLOW;
    int rc = sysfs_resolve_at_user(AT_FDCWD, path_ptr, &resolved, nflags);
    if (rc < 0)
        return rc;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    if ((mask & IN_ONLYDIR) && resolved.dentry->vnode->type != VNODE_DIR) {
        dentry_put(resolved.dentry);
        return -ENOTDIR;
    }

    struct file *file = NULL;
    int frc = handle_bridge_pin_fd(proc_current(), kfd, 0, &file, NULL);
    if (frc < 0) {
        dentry_put(resolved.dentry);
        return frc;
    }
    struct inotify_ctx *ctx = inotify_ctx_from_fd(file);
    if (!ctx) {
        file_put(file);
        dentry_put(resolved.dentry);
        return -EINVAL;
    }

    int wd = -EINVAL;
    mutex_lock(&ctx->lock);
    struct inotify_watch *watch =
        inotify_find_watch_by_vnode(ctx, resolved.dentry->vnode);
    if (watch) {
        if (mask & IN_MASK_CREATE) {
            wd = -EEXIST;
        } else {
            if (mask & IN_MASK_ADD)
                watch->mask |= watch_mask;
            else
                watch->mask = watch_mask;
            wd = watch->wd;
        }
    } else {
        if (mask & IN_MASK_ADD) {
            wd = -EINVAL;
        } else {
            struct inotify_watch *new_watch = kzalloc(sizeof(*new_watch));
            if (!new_watch) {
                wd = -ENOMEM;
            } else {
                int next = ctx->next_wd++;
                if (ctx->next_wd <= 0)
                    ctx->next_wd = 1;
                if (next <= 0)
                    next = ctx->next_wd++;
                new_watch->wd = next;
                new_watch->vn = resolved.dentry->vnode;
                vnode_get(new_watch->vn);
                new_watch->mask = watch_mask;
                list_add_tail(&new_watch->node, &ctx->watches);
                wd = new_watch->wd;
            }
        }
    }
    mutex_unlock(&ctx->lock);

    file_put(file);
    dentry_put(resolved.dentry);
    return wd;
}

int64_t sys_inotify_rm_watch(uint64_t fd, uint64_t wd, uint64_t a2, uint64_t a3,
                             uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    int kfd = sysfd_abi_int32(fd);
    int kwd = sysfd_abi_int32(wd);
    struct file *file = NULL;
    int frc = handle_bridge_pin_fd(proc_current(), kfd, 0, &file, NULL);
    if (frc < 0)
        return frc;
    struct inotify_ctx *ctx = inotify_ctx_from_fd(file);
    if (!ctx) {
        file_put(file);
        return -EINVAL;
    }

    int rc = -EINVAL;
    mutex_lock(&ctx->lock);
    struct inotify_watch *watch = inotify_find_watch_by_wd(ctx, kwd);
    if (watch) {
        inotify_remove_watch_locked(ctx, watch, true);
        rc = 0;
    }
    mutex_unlock(&ctx->lock);

    file_put(file);
    return rc;
}
