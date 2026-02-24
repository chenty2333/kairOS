/**
 * kernel/drivers/tty/pty.c - Pseudo-terminal (PTY) implementation
 */

#include <kairos/atomic.h>
#include <kairos/devfs.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/ringbuf.h>
#include <kairos/string.h>
#include <kairos/tty.h>
#include <kairos/tty_driver.h>
#include <kairos/tty_ldisc.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#define PTY_MAX 64

enum pty_endpoint {
    PTY_ENDPOINT_MASTER = 1,
    PTY_ENDPOINT_SLAVE = 2,
};

struct pty_pair {
    int idx;
    atomic_t refcount; /* slot + opened files */
    spinlock_t lock;
    bool live;

    uint16_t master_files;
    uint16_t slave_files;

    struct tty_struct *master;
    struct tty_struct *slave;
};

struct pty_file_ctx {
    struct pty_pair *pair;
    enum pty_endpoint endpoint;
};

static struct pty_pair *pty_slots[PTY_MAX];
static spinlock_t pty_lock = SPINLOCK_INIT;
static const struct tty_ldisc_ops pty_master_ldisc_ops;
extern struct tty_driver pty_master_driver;

static void pty_pair_get(struct pty_pair *pair) {
    if (pair)
        atomic_inc(&pair->refcount);
}

static void pty_pair_destroy(struct pty_pair *pair) {
    if (!pair)
        return;

    struct tty_struct *master = pair->master;
    struct tty_struct *slave = pair->slave;
    pair->master = NULL;
    pair->slave = NULL;

    if (master) {
        master->link = NULL;
        tty_free(master);
    }
    if (slave) {
        slave->link = NULL;
        tty_free(slave);
    }

    kfree(pair);
}

static void pty_pair_put(struct pty_pair *pair) {
    if (!pair)
        return;

    uint32_t refs = atomic_dec_return(&pair->refcount);
    if (refs == 0)
        pty_pair_destroy(pair);
}

static struct pty_pair *pty_slot_get(int idx) {
    if (idx < 0 || idx >= PTY_MAX)
        return NULL;

    struct pty_pair *pair = NULL;
    spin_lock(&pty_lock);
    pair = pty_slots[idx];
    if (pair)
        pty_pair_get(pair);
    spin_unlock(&pty_lock);
    return pair;
}

static void pty_slot_detach(struct pty_pair *pair) {
    if (!pair || pair->idx < 0 || pair->idx >= PTY_MAX)
        return;

    bool detached = false;
    spin_lock(&pty_lock);
    if (pty_slots[pair->idx] == pair) {
        pty_slots[pair->idx] = NULL;
        detached = true;
    }
    spin_unlock(&pty_lock);

    if (detached)
        pty_pair_put(pair); /* drop slot reference */
}

static int pty_pair_create(struct pty_pair **out_pair) {
    if (!out_pair)
        return -EINVAL;

    struct pty_pair *pair = kzalloc(sizeof(*pair));
    if (!pair)
        return -ENOMEM;

    spin_init(&pair->lock);
    atomic_init(&pair->refcount, 1); /* slot reference */
    pair->idx = -1;
    pair->live = true;

    spin_lock(&pty_lock);
    for (int i = 0; i < PTY_MAX; i++) {
        if (!pty_slots[i]) {
            pty_slots[i] = pair;
            pair->idx = i;
            break;
        }
    }
    spin_unlock(&pty_lock);

    if (pair->idx < 0) {
        kfree(pair);
        return -ENOSPC;
    }

    pair->master = tty_alloc(&pty_master_driver, pair->idx);
    if (!pair->master) {
        spin_lock(&pair->lock);
        pair->live = false;
        spin_unlock(&pair->lock);
        pty_slot_detach(pair);
        return -ENOMEM;
    }

    pair->slave = tty_alloc(&pty_slave_driver, pair->idx);
    if (!pair->slave) {
        spin_lock(&pair->lock);
        pair->live = false;
        spin_unlock(&pair->lock);
        pty_slot_detach(pair);
        return -ENOMEM;
    }

    pair->master->link = pair->slave;
    pair->slave->link = pair->master;
    pair->master->flags |= TTY_PTY_MASTER;
    pair->master->ldisc.ops = &pty_master_ldisc_ops;

    *out_pair = pair;
    return 0;
}

static struct pty_file_ctx *pty_file_ctx_get(struct file *file,
                                              enum pty_endpoint endpoint) {
    if (!file || !file->private_data)
        return NULL;

    struct pty_file_ctx *ctx = (struct pty_file_ctx *)file->private_data;
    if (!ctx->pair || ctx->endpoint != endpoint)
        return NULL;

    return ctx;
}

static int pty_pair_try_detach_if_unused(struct pty_pair *pair) {
    bool detach = false;

    spin_lock(&pair->lock);
    if (pair->live && pair->master_files == 0 && pair->slave_files == 0) {
        pair->live = false;
        detach = true;
    }
    spin_unlock(&pair->lock);

    if (detach)
        pty_slot_detach(pair);

    return detach ? 1 : 0;
}

static int pty_master_open(struct tty_struct *tty) {
    (void)tty;
    return 0;
}

static void pty_master_close(struct tty_struct *tty) {
    (void)tty;
}

static ssize_t pty_master_write(struct tty_struct *tty, const uint8_t *buf,
                                size_t count, uint32_t flags) {
    (void)flags;
    struct tty_struct *slave = tty->link;
    if (!slave)
        return -EIO;
    tty_receive_buf(slave, buf, count);
    return (ssize_t)count;
}

static void pty_master_put_char(struct tty_struct *tty, uint8_t ch) {
    struct tty_struct *slave = tty->link;
    if (!slave)
        return;
    tty_receive_buf(slave, &ch, 1);
}

static void pty_master_hangup(struct tty_struct *tty) {
    struct tty_struct *slave = tty->link;
    if (slave)
        tty_hangup(slave);
}

static const struct tty_driver_ops pty_master_ops = {
    .open = pty_master_open,
    .close = pty_master_close,
    .write = pty_master_write,
    .put_char = pty_master_put_char,
    .hangup = pty_master_hangup,
};

static int pty_slave_open(struct tty_struct *tty) {
    (void)tty;
    return 0;
}

static void pty_slave_close(struct tty_struct *tty) {
    (void)tty;
}

static int pty_wait_master_input_space(struct tty_struct *master) {
    if (!master)
        return -EIO;

    struct vnode *vn = master->vnode;
    struct process *p = proc_current();
    if (!vn || !p)
        return -EAGAIN;

    for (;;) {
        bool irq_state = arch_irq_save();
        spin_lock(&master->lock);
        bool has_space = ringbuf_avail(&master->input_rb) > 0;
        bool hungup = (master->flags & TTY_HUPPED) != 0;
        spin_unlock(&master->lock);
        arch_irq_restore(irq_state);

        if (has_space)
            return 1;
        if (hungup)
            return 0;

        struct poll_waiter waiter = {0};
        INIT_LIST_HEAD(&waiter.entry.node);
        waiter.entry.proc = p;
        poll_wait_add(&vn->pollers, &waiter);

        irq_state = arch_irq_save();
        spin_lock(&master->lock);
        has_space = ringbuf_avail(&master->input_rb) > 0;
        hungup = (master->flags & TTY_HUPPED) != 0;
        spin_unlock(&master->lock);
        arch_irq_restore(irq_state);
        if (has_space || hungup) {
            poll_wait_remove(&waiter);
            return has_space ? 1 : 0;
        }

        proc_lock(p);
        if (p->sig_pending) {
            proc_unlock(p);
            poll_wait_remove(&waiter);
            return -EINTR;
        }
        p->wait_channel = &waiter;
        p->sleep_deadline = 0;
        p->state = PROC_SLEEPING;
        proc_unlock(p);
        proc_yield();

        proc_lock(p);
        p->wait_channel = NULL;
        p->sleep_deadline = 0;
        p->state = PROC_RUNNING;
        bool interrupted = p->sig_pending;
        proc_unlock(p);
        poll_wait_remove(&waiter);
        if (interrupted)
            return -EINTR;
    }
}

/* Slave write → push to master's input_rb (screen output path) */
static ssize_t pty_slave_write(struct tty_struct *tty, const uint8_t *buf,
                               size_t count, uint32_t flags) {
    struct tty_struct *master = tty->link;
    if (!master)
        return -EIO;
    if (!buf)
        return -EINVAL;
    if (count == 0)
        return 0;

    size_t written = 0;
    while (written < count) {
        bool irq_state = arch_irq_save();
        spin_lock(&master->lock);
        size_t avail = ringbuf_avail(&master->input_rb);
        bool hungup = (master->flags & TTY_HUPPED) != 0;
        size_t pushed = 0;
        while (pushed < avail && written < count) {
            (void)ringbuf_push(&master->input_rb, (char)buf[written], false);
            pushed++;
            written++;
        }
        spin_unlock(&master->lock);
        arch_irq_restore(irq_state);

        if (pushed && master->vnode)
            vfs_poll_wake(master->vnode, POLLIN);
        if (written == count)
            break;
        if (hungup)
            return written ? (ssize_t)written : -EIO;
        if (flags & O_NONBLOCK)
            return written ? (ssize_t)written : -EAGAIN;

        int wait_rc = pty_wait_master_input_space(master);
        if (wait_rc < 0)
            return written ? (ssize_t)written : (ssize_t)wait_rc;
        if (wait_rc == 0)
            return written ? (ssize_t)written : -EIO;
    }
    return (ssize_t)written;
}

static void pty_slave_put_char(struct tty_struct *tty, uint8_t ch) {
    (void)pty_slave_write(tty, &ch, 1, O_NONBLOCK);
}

static void pty_slave_hangup(struct tty_struct *tty) {
    struct tty_struct *master = tty->link;
    if (master)
        tty_hangup(master);
}

static const struct tty_driver_ops pty_slave_ops = {
    .open = pty_slave_open,
    .close = pty_slave_close,
    .write = pty_slave_write,
    .put_char = pty_slave_put_char,
    .hangup = pty_slave_hangup,
};

/* ── Driver structs ──────────────────────────────────────────────── */

struct tty_driver pty_master_driver = {
    .name = "ptm",
    .major = 5,
    .minor_start = 2,
    .num = PTY_MAX,
    .ops = &pty_master_ops,
};

struct tty_driver pty_slave_driver = {
    .name = "pts",
    .major = 136,
    .minor_start = 0,
    .num = PTY_MAX,
    .ops = &pty_slave_ops,
};

/* Master ldisc: passthrough (no line editing on master side) */

static int pty_master_ldisc_open(struct tty_struct *tty) {
    (void)tty;
    return 0;
}

static void pty_master_ldisc_close(struct tty_struct *tty) {
    (void)tty;
}

/*
 * Master read: blocking/non-blocking from master's input_rb (slave output).
 */
static ssize_t pty_master_ldisc_read(struct tty_struct *tty, uint8_t *buf,
                                     size_t count, uint32_t flags) {
    if (!tty || !buf)
        return -EINVAL;
    if (count == 0)
        return 0;

    struct vnode *vn = tty->vnode;

    for (;;) {
        bool irq_state = arch_irq_save();
        spin_lock(&tty->lock);
        size_t got = 0;
        char ch;
        while (got < count && ringbuf_pop(&tty->input_rb, &ch))
            buf[got++] = (uint8_t)ch;
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);

        if (got > 0) {
            if (vn)
                vfs_poll_wake(vn, POLLOUT);
            return (ssize_t)got;
        }
        if (tty->link && (tty->link->flags & TTY_HUPPED))
            return 0; /* slave hung up → EOF */
        if (flags & O_NONBLOCK)
            return -EAGAIN;

        struct process *p = proc_current();
        if (!p)
            return -EAGAIN;
        if (!vn)
            return -EIO;

        /* Poll-wait based blocking */
        struct poll_waiter waiter = {0};
        INIT_LIST_HEAD(&waiter.entry.node);
        waiter.entry.proc = p;

        irq_state = arch_irq_save();
        spin_lock(&tty->lock);
        bool has_data = !ringbuf_empty(&tty->input_rb);
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);
        if (has_data)
            continue;

        poll_wait_add(&vn->pollers, &waiter);

        irq_state = arch_irq_save();
        spin_lock(&tty->lock);
        has_data = !ringbuf_empty(&tty->input_rb);
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);
        if (has_data) {
            poll_wait_remove(&waiter);
            continue;
        }

        proc_lock(p);
        if (p->sig_pending) {
            proc_unlock(p);
            poll_wait_remove(&waiter);
            return -EINTR;
        }
        p->wait_channel = &waiter;
        p->sleep_deadline = 0;
        p->state = PROC_SLEEPING;
        proc_unlock(p);

        /* Final re-check before yield */
        irq_state = arch_irq_save();
        spin_lock(&tty->lock);
        has_data = !ringbuf_empty(&tty->input_rb);
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);
        if (!has_data)
            proc_yield();

        proc_lock(p);
        p->wait_channel = NULL;
        p->sleep_deadline = 0;
        p->state = PROC_RUNNING;
        bool interrupted = p->sig_pending;
        proc_unlock(p);

        poll_wait_remove(&waiter);
        if (interrupted)
            return -EINTR;
    }
}

static ssize_t pty_master_ldisc_write(struct tty_struct *tty,
                                      const uint8_t *buf, size_t count,
                                      uint32_t flags) {
    if (!tty || !tty->driver || !tty->driver->ops || !tty->driver->ops->write)
        return -EIO;
    return tty->driver->ops->write(tty, buf, count, flags);
}

static int pty_master_ldisc_poll(struct tty_struct *tty, uint32_t events) {
    uint32_t revents = 0;
    bool irq_state = arch_irq_save();
    spin_lock(&tty->lock);
    if (!ringbuf_empty(&tty->input_rb))
        revents |= POLLIN;
    if (ringbuf_avail(&tty->input_rb) > 0)
        revents |= POLLOUT;
    spin_unlock(&tty->lock);
    arch_irq_restore(irq_state);
    return (int)(revents & events);
}

static const struct tty_ldisc_ops pty_master_ldisc_ops = {
    .open = pty_master_ldisc_open,
    .close = pty_master_ldisc_close,
    .read = pty_master_ldisc_read,
    .write = pty_master_ldisc_write,
    .poll = pty_master_ldisc_poll,
};

/* ── /dev/ptmx ───────────────────────────────────────────────────── */

static int ptmx_open(struct file *file) {
    if (!file || !file->vnode)
        return -EINVAL;
    if (file->private_data)
        return 0;

    struct pty_pair *pair = NULL;
    int ret = pty_pair_create(&pair);
    if (ret < 0)
        return ret;

    struct pty_file_ctx *ctx = kzalloc(sizeof(*ctx));
    if (!ctx) {
        spin_lock(&pair->lock);
        pair->live = false;
        spin_unlock(&pair->lock);
        pty_slot_detach(pair);
        return -ENOMEM;
    }

    if (tty_open(pair->master) < 0) {
        kfree(ctx);
        spin_lock(&pair->lock);
        pair->live = false;
        spin_unlock(&pair->lock);
        pty_slot_detach(pair);
        return -EIO;
    }

    pair->master->vnode = file->vnode;

    pty_pair_get(pair); /* file reference */
    spin_lock(&pair->lock);
    pair->master_files++;
    spin_unlock(&pair->lock);

    ctx->pair = pair;
    ctx->endpoint = PTY_ENDPOINT_MASTER;
    file->private_data = ctx;
    return 0;
}

static void ptmx_release(struct file *file) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_MASTER);
    if (!ctx)
        return;

    struct pty_pair *pair = ctx->pair;
    file->private_data = NULL;
    kfree(ctx);

    struct tty_struct *master = NULL;
    struct tty_struct *slave = NULL;
    bool drop_master = false;
    bool last_master = false;

    spin_lock(&pair->lock);
    master = pair->master;
    slave = pair->slave;
    if (pair->master_files > 0) {
        pair->master_files--;
        drop_master = true;
    }
    last_master = (pair->master_files == 0);
    spin_unlock(&pair->lock);

    if (drop_master && master)
        tty_close(master);
    if (last_master && slave)
        tty_hangup(slave);

    pty_pair_try_detach_if_unused(pair);
    pty_pair_put(pair);
}

static ssize_t ptmx_fread(struct file *file, void *buf, size_t len) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_MASTER);
    if (!ctx || !ctx->pair->master)
        return -EIO;
    return tty_read(ctx->pair->master, (uint8_t *)buf, len, file->flags);
}

static ssize_t ptmx_fwrite(struct file *file, const void *buf, size_t len) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_MASTER);
    if (!ctx || !ctx->pair->master)
        return -EIO;
    return tty_write(ctx->pair->master, (const uint8_t *)buf, len, file->flags);
}

static int ptmx_ioctl(struct file *file, uint64_t cmd, uint64_t arg) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_MASTER);
    if (!ctx || !ctx->pair->master)
        return -EIO;
    return tty_ioctl(ctx->pair->master, cmd, arg);
}

static int ptmx_poll(struct file *file, uint32_t events) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_MASTER);
    if (!ctx || !ctx->pair->master)
        return POLLNVAL;
    return tty_poll(ctx->pair->master, events);
}

static struct file_ops ptmx_ops = {
    .open = ptmx_open,
    .release = ptmx_release,
    .fread = ptmx_fread,
    .fwrite = ptmx_fwrite,
    .ioctl = ptmx_ioctl,
    .poll = ptmx_poll,
};

/* ── /dev/pts/N ──────────────────────────────────────────────────── */

static int pts_index_from_vnode(struct vnode *vn) {
    if (!vn)
        return -1;
    intptr_t idx = (intptr_t)devfs_get_priv(vn);
    if (idx < 0 || idx >= PTY_MAX)
        return -1;
    return (int)idx;
}

static int pts_open(struct file *file) {
    if (!file || !file->vnode)
        return -EINVAL;

    int idx = pts_index_from_vnode(file->vnode);
    if (idx < 0)
        return -ENXIO;

    struct pty_pair *pair = pty_slot_get(idx);
    if (!pair)
        return -ENXIO;

    struct pty_file_ctx *ctx = kzalloc(sizeof(*ctx));
    if (!ctx) {
        pty_pair_put(pair);
        return -ENOMEM;
    }

    struct tty_struct *slave = NULL;
    spin_lock(&pair->lock);
    if (pair->live && pair->slave) {
        pair->slave_files++;
        slave = pair->slave;
    }
    spin_unlock(&pair->lock);

    if (!slave) {
        kfree(ctx);
        pty_pair_put(pair);
        return -ENXIO;
    }

    if (tty_open(slave) < 0) {
        bool detach = false;
        spin_lock(&pair->lock);
        if (pair->slave_files > 0)
            pair->slave_files--;
        if (pair->live && pair->master_files == 0 && pair->slave_files == 0) {
            pair->live = false;
            detach = true;
        }
        spin_unlock(&pair->lock);
        if (detach)
            pty_slot_detach(pair);
        kfree(ctx);
        pty_pair_put(pair);
        return -EIO;
    }

    if (!slave->vnode)
        slave->vnode = file->vnode;

    ctx->pair = pair; /* slot_get ref becomes file ref */
    ctx->endpoint = PTY_ENDPOINT_SLAVE;
    file->private_data = ctx;
    return 0;
}

static void pts_release(struct file *file) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_SLAVE);
    if (!ctx)
        return;

    struct pty_pair *pair = ctx->pair;
    file->private_data = NULL;
    kfree(ctx);

    struct tty_struct *slave = NULL;
    struct tty_struct *master = NULL;
    bool drop_slave = false;
    bool last_slave = false;

    spin_lock(&pair->lock);
    slave = pair->slave;
    master = pair->master;
    if (pair->slave_files > 0) {
        pair->slave_files--;
        drop_slave = true;
    }
    last_slave = (pair->slave_files == 0);
    spin_unlock(&pair->lock);

    if (drop_slave && slave)
        tty_close(slave);
    if (last_slave && master)
        tty_hangup(master);

    pty_pair_try_detach_if_unused(pair);
    pty_pair_put(pair);
}

static ssize_t pts_fread(struct file *file, void *buf, size_t len) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_SLAVE);
    if (!ctx || !ctx->pair->slave)
        return -EIO;
    return tty_read(ctx->pair->slave, (uint8_t *)buf, len, file->flags);
}

static ssize_t pts_fwrite(struct file *file, const void *buf, size_t len) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_SLAVE);
    if (!ctx || !ctx->pair->slave)
        return -EIO;
    return tty_write(ctx->pair->slave, (const uint8_t *)buf, len, file->flags);
}

static int pts_ioctl(struct file *file, uint64_t cmd, uint64_t arg) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_SLAVE);
    if (!ctx || !ctx->pair->slave)
        return -EIO;
    return tty_ioctl(ctx->pair->slave, cmd, arg);
}

static int pts_poll(struct file *file, uint32_t events) {
    struct pty_file_ctx *ctx = pty_file_ctx_get(file, PTY_ENDPOINT_SLAVE);
    if (!ctx || !ctx->pair->slave)
        return POLLNVAL;
    return tty_poll(ctx->pair->slave, events);
}

static struct file_ops pts_ops = {
    .open = pts_open,
    .release = pts_release,
    .fread = pts_fread,
    .fwrite = pts_fwrite,
    .ioctl = pts_ioctl,
    .poll = pts_poll,
};

/* ── Init ────────────────────────────────────────────────────────── */

int pty_driver_init(void) {
    tty_register_driver(&pty_master_driver);
    tty_register_driver(&pty_slave_driver);

    /* Register /dev/ptmx */
    devfs_register_node("/dev/ptmx", &ptmx_ops, NULL);

    /* Register /dev/pts directory and pre-create /dev/pts/0..63 */
    devfs_register_dir("/dev/pts");
    for (int i = 0; i < PTY_MAX; i++) {
        char name[32];
        snprintf(name, sizeof(name), "/dev/pts/%d", i);
        devfs_register_node(name, &pts_ops, (void *)(intptr_t)i);
    }

    pr_info("pty: initialized (%d pairs max)\n", PTY_MAX);
    return 0;
}
