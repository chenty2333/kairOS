/**
 * kernel/core/syscall/sys_pidfd.c - pidfd syscalls
 */

#include <kairos/list.h>
#include <kairos/handle_bridge.h>
#include <kairos/pidfd.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/process.h>
#include <kairos/signal.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#define PIDFD_MAGIC 0x70666466U
#define PIDFD_NONBLOCK O_NONBLOCK

struct pidfd_ctx {
    uint32_t magic;
    spinlock_t lock;
    struct poll_wait_source wait_src;
    struct list_head node;
    pid_t pid;
    uint64_t start_time;
    bool exited;
    bool closed;
};

static LIST_HEAD(pidfd_instances);
static spinlock_t pidfd_instances_lock = SPINLOCK_INIT;
static spinlock_t pidfd_init_lock = SPINLOCK_INIT;
static bool pidfd_ready;

static int pidfd_close(struct vnode *vn);
static int pidfd_poll(struct file *file, uint32_t events);

static struct file_ops pidfd_file_ops = {
    .close = pidfd_close,
    .poll = pidfd_poll,
};

static inline pid_t syspidfd_abi_pid(uint64_t v) {
    return (pid_t)(int32_t)(uint32_t)v;
}

static inline int syspidfd_abi_int32(uint64_t v) {
    return (int32_t)(uint32_t)v;
}

static void pidfd_on_process_exit(struct process *p) {
    if (!p)
        return;

    bool irq;
    spin_lock_irqsave(&pidfd_instances_lock, &irq);
    struct pidfd_ctx *ctx;
    list_for_each_entry(ctx, &pidfd_instances, node) {
        if (ctx->pid != p->pid || ctx->start_time != p->start_time)
            continue;

        bool ctx_irq;
        spin_lock_irqsave(&ctx->lock, &ctx_irq);
        if (!ctx->closed && !ctx->exited) {
            ctx->exited = true;
            poll_wait_source_wake_all(&ctx->wait_src, POLLIN | POLLHUP);
        }
        spin_unlock_irqrestore(&ctx->lock, ctx_irq);
    }
    spin_unlock_irqrestore(&pidfd_instances_lock, irq);
}

static void pidfd_init_once(void) {
    if (__atomic_load_n(&pidfd_ready, __ATOMIC_ACQUIRE))
        return;

    spin_lock(&pidfd_init_lock);
    if (!pidfd_ready) {
        proc_register_exit_callback(pidfd_on_process_exit);
        __atomic_store_n(&pidfd_ready, true, __ATOMIC_RELEASE);
    }
    spin_unlock(&pidfd_init_lock);
}

static int pidfd_is_target_alive(const struct pidfd_ctx *ctx) {
    if (!ctx)
        return -EINVAL;

    struct process *target = proc_find(ctx->pid);
    if (!target)
        return -ESRCH;
    if (target->start_time != ctx->start_time)
        return -ESRCH;
    if (target->state == PROC_ZOMBIE || target->state == PROC_REAPING)
        return -ESRCH;
    return 0;
}

int pidfd_get_target(struct file *file, pid_t *pid_out,
                     uint64_t *start_time_out) {
    if (pid_out)
        *pid_out = 0;
    if (start_time_out)
        *start_time_out = 0;
    if (!file || !file->vnode || !pid_out)
        return -EBADF;

    struct pidfd_ctx *ctx = (struct pidfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != PIDFD_MAGIC)
        return -EBADF;

    *pid_out = ctx->pid;
    if (start_time_out)
        *start_time_out = ctx->start_time;
    return 0;
}

static int pidfd_create_file(pid_t pid, uint32_t open_flags, struct file **out) {
    if (!out)
        return -EINVAL;
    *out = NULL;

    struct process *target = proc_find(pid);
    if (!target)
        return -ESRCH;

    struct pidfd_ctx *ctx = kzalloc(sizeof(*ctx));
    struct vnode *vn = kzalloc(sizeof(*vn));
    struct file *file = vfs_file_alloc();
    if (!ctx || !vn || !file) {
        kfree(ctx);
        kfree(vn);
        if (file)
            vfs_file_free(file);
        return -ENOMEM;
    }

    ctx->magic = PIDFD_MAGIC;
    spin_init(&ctx->lock);
    poll_wait_source_init(&ctx->wait_src, vn);
    INIT_LIST_HEAD(&ctx->node);
    ctx->pid = pid;
    ctx->start_time = target->start_time;
    ctx->exited = (target->state == PROC_ZOMBIE || target->state == PROC_REAPING);
    ctx->closed = false;

    vn->type = VNODE_FILE;
    vn->mode = S_IFREG | 0;
    vn->ops = &pidfd_file_ops;
    vn->fs_data = ctx;
    vn->size = 0;
    atomic_init(&vn->refcount, 1);
    rwlock_init(&vn->lock, "pidfd_vnode");
    poll_wait_head_init(&vn->pollers);

    file->vnode = vn;
    file->dentry = NULL;
    file->offset = 0;
    file->flags = O_RDONLY | (open_flags & O_NONBLOCK);
    file->path[0] = '\0';

    bool irq;
    spin_lock_irqsave(&pidfd_instances_lock, &irq);
    list_add_tail(&ctx->node, &pidfd_instances);
    spin_unlock_irqrestore(&pidfd_instances_lock, irq);

    *out = file;
    return 0;
}

static int pidfd_close(struct vnode *vn) {
    if (!vn)
        return 0;

    struct pidfd_ctx *ctx = (struct pidfd_ctx *)vn->fs_data;
    if (ctx && ctx->magic == PIDFD_MAGIC) {
        bool irq;
        spin_lock_irqsave(&pidfd_instances_lock, &irq);
        if (!list_empty(&ctx->node))
            list_del(&ctx->node);
        spin_unlock_irqrestore(&pidfd_instances_lock, irq);

        bool ctx_irq;
        spin_lock_irqsave(&ctx->lock, &ctx_irq);
        ctx->closed = true;
        spin_unlock_irqrestore(&ctx->lock, ctx_irq);

        ctx->magic = 0;
        kfree(ctx);
    }

    kfree(vn);
    return 0;
}

static int pidfd_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;

    struct pidfd_ctx *ctx = (struct pidfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != PIDFD_MAGIC)
        return POLLNVAL;

    bool exited;
    bool irq;
    spin_lock_irqsave(&ctx->lock, &irq);
    exited = ctx->exited;
    spin_unlock_irqrestore(&ctx->lock, irq);

    if (exited)
        return (int)((POLLIN | POLLHUP) & events);
    return 0;
}

int64_t sys_pidfd_open(uint64_t pid, uint64_t flags, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    pidfd_init_once();

    pid_t kpid = syspidfd_abi_pid(pid);
    uint32_t uflags = (uint32_t)flags;
    if ((uint64_t)uflags != flags)
        return -EINVAL;
    if (kpid <= 0)
        return -EINVAL;
    if (uflags & ~PIDFD_NONBLOCK)
        return -EINVAL;

    struct file *file = NULL;
    int rc = pidfd_create_file(kpid, uflags, &file);
    if (rc < 0)
        return rc;

    int fd = fd_alloc_flags(proc_current(), file, FD_CLOEXEC);
    if (fd < 0) {
        vfs_close(file);
        return fd;
    }
    return (int64_t)fd;
}

int64_t sys_pidfd_send_signal(uint64_t pidfd, uint64_t sig, uint64_t info,
                              uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4;
    (void)a5;

    int kfd = syspidfd_abi_int32(pidfd);
    int ksig = syspidfd_abi_int32(sig);
    uint32_t uflags = (uint32_t)flags;

    if ((uint64_t)uflags != flags)
        return -EINVAL;
    if (kfd < 0)
        return -EBADF;
    if (uflags != 0)
        return -EINVAL;
    if (ksig < 0 || ksig > NSIG)
        return -EINVAL;
    if (info != 0) {
        siginfo_t kinfo;
        if (copy_from_user(&kinfo, (const void *)info, sizeof(kinfo)) < 0)
            return -EFAULT;
    }

    struct file *file = NULL;
    int frc = fd_get_required(proc_current(), kfd, FD_RIGHT_IOCTL, &file);
    if (frc < 0)
        return frc;

    int ret = 0;
    do {
        if (!file->vnode) {
            ret = -EBADF;
            break;
        }

        struct pidfd_ctx *ctx = (struct pidfd_ctx *)file->vnode->fs_data;
        if (!ctx || ctx->magic != PIDFD_MAGIC) {
            ret = -EBADF;
            break;
        }

        int alive = pidfd_is_target_alive(ctx);
        if (alive < 0) {
            bool irq;
            spin_lock_irqsave(&ctx->lock, &irq);
            if (alive == -ESRCH && !ctx->closed && !ctx->exited) {
                ctx->exited = true;
                poll_wait_source_wake_all(&ctx->wait_src, POLLIN | POLLHUP);
            }
            spin_unlock_irqrestore(&ctx->lock, irq);
            ret = alive;
            break;
        }

        if (ksig == 0) {
            ret = 0;
            break;
        }

        ret = signal_send(ctx->pid, ksig);
    } while (0);

    file_put(file);
    return (int64_t)ret;
}

int64_t sys_pidfd_getfd(uint64_t pidfd, uint64_t targetfd, uint64_t flags,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3;
    (void)a4;
    (void)a5;

    int kpidfd = syspidfd_abi_int32(pidfd);
    int ktargetfd = syspidfd_abi_int32(targetfd);
    uint32_t uflags = (uint32_t)flags;

    if ((uint64_t)uflags != flags)
        return -EINVAL;
    if (kpidfd < 0 || ktargetfd < 0)
        return -EBADF;
    if (uflags != 0)
        return -EINVAL;

    struct process *self = proc_current();
    if (!self)
        return -EINVAL;

    struct file *pidfd_file = NULL;
    int rc = fd_get_required(self, kpidfd, FD_RIGHT_IOCTL, &pidfd_file);
    if (rc < 0)
        return rc;

    pid_t target_pid = 0;
    uint64_t target_start = 0;
    rc = pidfd_get_target(pidfd_file, &target_pid, &target_start);
    if (rc < 0) {
        file_put(pidfd_file);
        return rc;
    }

    struct process *target = proc_find(target_pid);
    if (!target || target->start_time != target_start ||
        target->state == PROC_ZOMBIE || target->state == PROC_REAPING) {
        file_put(pidfd_file);
        return -ESRCH;
    }

    if (target != self && self->uid != 0 && self->uid != target->uid) {
        file_put(pidfd_file);
        return -EPERM;
    }

    int newfd = -1;
    rc = handle_bridge_dup_fd(target, ktargetfd, self, FD_CLOEXEC, &newfd);
    file_put(pidfd_file);
    if (rc < 0)
        return rc;
    return (int64_t)newfd;
}
