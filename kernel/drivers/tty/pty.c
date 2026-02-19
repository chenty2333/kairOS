/**
 * kernel/drivers/tty/pty.c - Pseudo-terminal (PTY) implementation
 */

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

extern int devfs_register_node(const char *path, struct file_ops *ops,
                               void *priv);
extern int devfs_register_dir(const char *path);
extern void *devfs_get_priv(struct vnode *vn);

#define PTY_MAX 64

static struct tty_struct *pty_masters[PTY_MAX];
static struct tty_struct *pty_slaves[PTY_MAX];
static bool pty_allocated[PTY_MAX];
static spinlock_t pty_lock = SPINLOCK_INIT;

static int pty_master_open(struct tty_struct *tty) {
    (void)tty;
    return 0;
}

static void pty_master_close(struct tty_struct *tty) {
    (void)tty;
}

static ssize_t pty_master_write(struct tty_struct *tty, const uint8_t *buf,
                                 size_t count) {
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
    .open    = pty_master_open,
    .close   = pty_master_close,
    .write   = pty_master_write,
    .put_char = pty_master_put_char,
    .hangup  = pty_master_hangup,
};

static int pty_slave_open(struct tty_struct *tty) {
    (void)tty;
    return 0;
}

static void pty_slave_close(struct tty_struct *tty) {
    (void)tty;
}

/* Slave write → push to master's input_rb (screen output path) */
static ssize_t pty_slave_write(struct tty_struct *tty, const uint8_t *buf,
                                size_t count) {
    struct tty_struct *master = tty->link;
    if (!master)
        return -EIO;

    bool irq_state = arch_irq_save();
    spin_lock(&master->lock);
    for (size_t i = 0; i < count; i++)
        ringbuf_push(&master->input_rb, (char)buf[i], true);
    spin_unlock(&master->lock);
    arch_irq_restore(irq_state);

    /* Wake master readers */
    if (master->vnode)
        vfs_poll_wake(master->vnode, POLLIN);
    return (ssize_t)count;
}

static void pty_slave_put_char(struct tty_struct *tty, uint8_t ch) {
    pty_slave_write(tty, &ch, 1);
}

static void pty_slave_hangup(struct tty_struct *tty) {
    struct tty_struct *master = tty->link;
    if (master)
        tty_hangup(master);
}

static const struct tty_driver_ops pty_slave_ops = {
    .open    = pty_slave_open,
    .close   = pty_slave_close,
    .write   = pty_slave_write,
    .put_char = pty_slave_put_char,
    .hangup  = pty_slave_hangup,
};

/* ── Driver structs ──────────────────────────────────────────────── */

struct tty_driver pty_master_driver = {
    .name        = "ptm",
    .major       = 5,
    .minor_start = 2,
    .num         = PTY_MAX,
    .ops         = &pty_master_ops,
};

struct tty_driver pty_slave_driver = {
    .name        = "pts",
    .major       = 136,
    .minor_start = 0,
    .num         = PTY_MAX,
    .ops         = &pty_slave_ops,
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

        if (got > 0)
            return (ssize_t)got;
        if (tty->link && (tty->link->flags & TTY_HUPPED))
            return 0;  /* slave hung up → EOF */
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
    (void)flags;
    if (!tty || !tty->driver || !tty->driver->ops || !tty->driver->ops->write)
        return -EIO;
    return tty->driver->ops->write(tty, buf, count);
}

static int pty_master_ldisc_poll(struct tty_struct *tty, uint32_t events) {
    uint32_t revents = 0;
    bool irq_state = arch_irq_save();
    spin_lock(&tty->lock);
    if (!ringbuf_empty(&tty->input_rb))
        revents |= POLLIN;
    spin_unlock(&tty->lock);
    arch_irq_restore(irq_state);
    revents |= POLLOUT;
    return (int)(revents & events);
}

static const struct tty_ldisc_ops pty_master_ldisc_ops = {
    .open         = pty_master_ldisc_open,
    .close        = pty_master_ldisc_close,
    .read         = pty_master_ldisc_read,
    .write        = pty_master_ldisc_write,
    .poll         = pty_master_ldisc_poll,
};

/* ── PTY pair allocation ─────────────────────────────────────────── */

static int pty_alloc_pair(struct tty_struct **master_out,
                           struct tty_struct **slave_out) {
    int idx = -1;

    spin_lock(&pty_lock);
    for (int i = 0; i < PTY_MAX; i++) {
        if (!pty_allocated[i]) {
            pty_allocated[i] = true;
            idx = i;
            break;
        }
    }
    spin_unlock(&pty_lock);

    if (idx < 0)
        return -ENOSPC;

    struct tty_struct *master = tty_alloc(&pty_master_driver, idx);
    if (!master) {
        spin_lock(&pty_lock);
        pty_allocated[idx] = false;
        spin_unlock(&pty_lock);
        return -ENOMEM;
    }

    struct tty_struct *slave = tty_alloc(&pty_slave_driver, idx);
    if (!slave) {
        tty_free(master);
        spin_lock(&pty_lock);
        pty_allocated[idx] = false;
        spin_unlock(&pty_lock);
        return -ENOMEM;
    }

    master->link = slave;
    slave->link = master;
    master->flags |= TTY_PTY_MASTER;
    master->ldisc.ops = &pty_master_ldisc_ops;

    pty_masters[idx] = master;
    pty_slaves[idx] = slave;

    *master_out = master;
    *slave_out = slave;
    return idx;
}

static void pty_free_pair(int idx) {
    if (idx < 0 || idx >= PTY_MAX)
        return;

    spin_lock(&pty_lock);
    struct tty_struct *master = pty_masters[idx];
    struct tty_struct *slave = pty_slaves[idx];
    pty_masters[idx] = NULL;
    pty_slaves[idx] = NULL;
    pty_allocated[idx] = false;
    spin_unlock(&pty_lock);

    if (master) {
        master->link = NULL;
        tty_free(master);
    }
    if (slave) {
        slave->link = NULL;
        tty_free(slave);
    }
}

/* ── /dev/ptmx ───────────────────────────────────────────────────── */

/*
 * Track per-vnode PTY index. Since each open of /dev/ptmx shares the same
 * vnode, we use a small table mapping vnode → idx. Protected by pty_lock.
 */
#define PTMX_OPEN_MAX 16
static struct { struct vnode *vn; int idx; } ptmx_map[PTMX_OPEN_MAX];

static int ptmx_lookup(struct vnode *vn) {
    for (int i = 0; i < PTMX_OPEN_MAX; i++) {
        if (ptmx_map[i].vn == vn)
            return ptmx_map[i].idx;
    }
    return -1;
}

static int ptmx_ensure_alloc(struct vnode *vn) {
    spin_lock(&pty_lock);
    int idx = ptmx_lookup(vn);
    spin_unlock(&pty_lock);
    if (idx >= 0 && idx < PTY_MAX && pty_masters[idx])
        return idx;

    struct tty_struct *master, *slave;
    idx = pty_alloc_pair(&master, &slave);
    if (idx < 0)
        return idx;

    spin_lock(&pty_lock);
    for (int i = 0; i < PTMX_OPEN_MAX; i++) {
        if (!ptmx_map[i].vn) {
            ptmx_map[i].vn = vn;
            ptmx_map[i].idx = idx;
            break;
        }
    }
    spin_unlock(&pty_lock);

    master->vnode = vn;
    tty_open(master);
    tty_open(slave);
    return idx;
}

static ssize_t ptmx_read(struct vnode *vn, void *buf, size_t len,
                           off_t off, uint32_t flags) {
    (void)off;
    int idx = ptmx_ensure_alloc(vn);
    if (idx < 0)
        return idx;
    return tty_read(pty_masters[idx], (uint8_t *)buf, len, flags);
}

static ssize_t ptmx_write(struct vnode *vn, const void *buf, size_t len,
                            off_t off, uint32_t flags) {
    (void)off;
    int idx = ptmx_ensure_alloc(vn);
    if (idx < 0)
        return idx;
    return tty_write(pty_masters[idx], (const uint8_t *)buf, len, flags);
}

static int ptmx_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg) {
    int idx = ptmx_ensure_alloc(vn);
    if (idx < 0)
        return idx;
    return tty_ioctl(pty_masters[idx], cmd, arg);
}

static int ptmx_poll(struct vnode *vn, uint32_t events) {
    int idx = ptmx_ensure_alloc(vn);
    if (idx < 0)
        return POLLNVAL;
    return tty_poll(pty_masters[idx], events);
}

static int ptmx_close(struct vnode *vn) {
    spin_lock(&pty_lock);
    int idx = ptmx_lookup(vn);
    for (int i = 0; i < PTMX_OPEN_MAX; i++) {
        if (ptmx_map[i].vn == vn) {
            ptmx_map[i].vn = NULL;
            ptmx_map[i].idx = 0;
            break;
        }
    }
    spin_unlock(&pty_lock);

    if (idx >= 0 && idx < PTY_MAX)
        pty_free_pair(idx);
    return 0;
}

static struct file_ops ptmx_ops = {
    .read  = ptmx_read,
    .write = ptmx_write,
    .ioctl = ptmx_ioctl,
    .poll  = ptmx_poll,
    .close = ptmx_close,
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

static ssize_t pts_read(struct vnode *vn, void *buf, size_t len,
                         off_t off, uint32_t flags) {
    (void)off;
    int idx = pts_index_from_vnode(vn);
    if (idx < 0 || !pty_slaves[idx])
        return -EIO;
    struct tty_struct *slave = pty_slaves[idx];
    if (!slave->vnode)
        slave->vnode = vn;
    return tty_read(slave, (uint8_t *)buf, len, flags);
}

static ssize_t pts_write(struct vnode *vn, const void *buf, size_t len,
                          off_t off, uint32_t flags) {
    (void)off;
    int idx = pts_index_from_vnode(vn);
    if (idx < 0 || !pty_slaves[idx])
        return -EIO;
    return tty_write(pty_slaves[idx], (const uint8_t *)buf, len, flags);
}

static int pts_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg) {
    int idx = pts_index_from_vnode(vn);
    if (idx < 0 || !pty_slaves[idx])
        return -EIO;
    return tty_ioctl(pty_slaves[idx], cmd, arg);
}

static int pts_poll(struct vnode *vn, uint32_t events) {
    int idx = pts_index_from_vnode(vn);
    if (idx < 0 || !pty_slaves[idx])
        return POLLNVAL;
    return tty_poll(pty_slaves[idx], events);
}

static int pts_close(struct vnode *vn) {
    (void)vn;
    return 0;
}

static struct file_ops pts_ops = {
    .read  = pts_read,
    .write = pts_write,
    .ioctl = pts_ioctl,
    .poll  = pts_poll,
    .close = pts_close,
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