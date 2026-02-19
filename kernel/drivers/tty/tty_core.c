/**
 * kernel/drivers/tty/tty_core.c - TTY core infrastructure
 *
 * Implements tty_struct lifecycle, ioctl dispatch, and driver registration.
 * All read/write/poll calls are delegated to the line discipline.
 */

#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/process.h>
#include <kairos/signal.h>
#include <kairos/string.h>
#include <kairos/tty.h>
#include <kairos/tty_ldisc.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

static struct tty_driver *tty_drivers[TTY_MAX_DRIVERS];
static int tty_driver_count;

int tty_register_driver(struct tty_driver *driver) {
    if (!driver || tty_driver_count >= TTY_MAX_DRIVERS)
        return -ENOMEM;
    tty_drivers[tty_driver_count++] = driver;
    return 0;
}

void tty_unregister_driver(struct tty_driver *driver) {
    for (int i = 0; i < tty_driver_count; i++) {
        if (tty_drivers[i] == driver) {
            tty_drivers[i] = tty_drivers[--tty_driver_count];
            return;
        }
    }
}

/* --- */

struct tty_struct *tty_alloc(struct tty_driver *driver, int index) {
    struct tty_struct *tty = kzalloc(sizeof(*tty));
    if (!tty)
        return NULL;

    tty->index = index;
    tty->driver = driver;

    spin_init(&tty->lock);
    ringbuf_init(&tty->input_rb, tty->input_buf, TTY_INPUT_BUF_SIZE);

    /* termios needs explicit non-zero defaults */
    memset(&tty->termios, 0, sizeof(tty->termios));
    tty->termios.c_iflag = ICRNL;
    tty->termios.c_oflag = OPOST | ONLCR;
    tty->termios.c_lflag = ISIG | ICANON | ECHO | ECHOCTL;
    tty->termios.c_cc[VINTR]  = 3;
    tty->termios.c_cc[VQUIT]  = 28;
    tty->termios.c_cc[VERASE] = 127;
    tty->termios.c_cc[VKILL]  = 21;
    tty->termios.c_cc[VEOF]   = 4;
    tty->termios.c_cc[VTIME]  = 0;
    tty->termios.c_cc[VMIN]   = 1;
    tty->termios.c_cc[VSUSP]  = 26;

    tty->winsize.ws_row = 24;
    tty->winsize.ws_col = 80;

    n_tty_init(tty);

    return tty;
}

void tty_free(struct tty_struct *tty) {
    if (!tty)
        return;
    if (tty->ldisc.ops && tty->ldisc.ops->close)
        tty->ldisc.ops->close(tty);
    kfree(tty);
}

int tty_open(struct tty_struct *tty) {
    if (!tty)
        return -EINVAL;
    tty->count++;
    if (tty->driver && tty->driver->ops && tty->driver->ops->open) {
        int ret = tty->driver->ops->open(tty);
        if (ret < 0) {
            tty->count--;
            return ret;
        }
    }
    if (tty->ldisc.ops && tty->ldisc.ops->open)
        tty->ldisc.ops->open(tty);
    return 0;
}

void tty_close(struct tty_struct *tty) {
    if (!tty)
        return;
    if (--tty->count <= 0) {
        if (tty->ldisc.ops && tty->ldisc.ops->close)
            tty->ldisc.ops->close(tty);
        if (tty->driver && tty->driver->ops && tty->driver->ops->close)
            tty->driver->ops->close(tty);
    }
}

/* --- */

ssize_t tty_read(struct tty_struct *tty, uint8_t *buf, size_t count,
                 uint32_t flags) {
    if (!tty || !tty->ldisc.ops || !tty->ldisc.ops->read)
        return -EIO;
    return tty->ldisc.ops->read(tty, buf, count, flags);
}

ssize_t tty_write(struct tty_struct *tty, const uint8_t *buf, size_t count,
                  uint32_t flags) {
    if (!tty || !tty->ldisc.ops || !tty->ldisc.ops->write)
        return -EIO;
    return tty->ldisc.ops->write(tty, buf, count, flags);
}

int tty_poll(struct tty_struct *tty, uint32_t events) {
    if (!tty || !tty->ldisc.ops || !tty->ldisc.ops->poll)
        return POLLNVAL;
    return tty->ldisc.ops->poll(tty, events);
}

void tty_hangup(struct tty_struct *tty) {
    if (!tty)
        return;
    tty->flags |= TTY_HUPPED;
    if (tty->driver && tty->driver->ops && tty->driver->ops->hangup)
        tty->driver->ops->hangup(tty);
}

void tty_receive_buf(struct tty_struct *tty, const uint8_t *buf, size_t count) {
    if (!tty || !tty->ldisc.ops || !tty->ldisc.ops->receive_buf)
        return;

    bool pushed = false;
    uint32_t sig_mask = 0;

    bool irq_state = arch_irq_save();
    spin_lock(&tty->lock);
    tty->ldisc.ops->receive_buf(tty, buf, count, &pushed, &sig_mask);
    pid_t fg = tty->fg_pgrp;
    struct vnode *vn = tty->vnode;
    spin_unlock(&tty->lock);
    arch_irq_restore(irq_state);

    if (sig_mask) {
        if (fg > 0) {
            for (int s = 1; s < 32; s++) {
                if (sig_mask & (1U << s))
                    signal_send_pgrp(fg, s);
            }
        } else {
            struct process *p = proc_current();
            if (p) {
                for (int s = 1; s < 32; s++) {
                    if (sig_mask & (1U << s))
                        signal_send(p->pid, s);
                }
            }
        }
    }
    if (pushed && vn)
        vfs_poll_wake(vn, POLLIN);
}

/* --- */

void tty_port_init(struct tty_port *port, const struct tty_port_ops *ops) {
    if (!port)
        return;
    memset(port, 0, sizeof(*port));
    port->ops = ops;
}

/* --- */

int tty_ioctl(struct tty_struct *tty, uint64_t cmd, uint64_t arg) {
    if (!tty)
        return -EINVAL;

    switch (cmd) {
    case TCGETS: {
        if (!arg)
            return -EFAULT;
        if (copy_to_user((void *)arg, &tty->termios,
                         sizeof(tty->termios)) < 0)
            return -EFAULT;
        return 0;
    }
    case TCSETS:
    case TCSETSW:
    case TCSETSF: {
        if (!arg)
            return -EFAULT;
        struct termios t;
        if (copy_from_user(&t, (void *)arg, sizeof(t)) < 0)
            return -EFAULT;
        struct termios old;
        bool wake = false;
        bool irq_state = arch_irq_save();
        spin_lock(&tty->lock);
        old = tty->termios;
        bool was_empty = ringbuf_empty(&tty->input_rb);
        /* ICANON→!ICANON: flush canon_buf into ringbuf */
        if ((tty->termios.c_lflag & ICANON) &&
            !(t.c_lflag & ICANON) && tty->canon_len > 0) {
            size_t avail = ringbuf_avail(&tty->input_rb);
            if (avail >= tty->canon_len) {
                for (uint32_t i = 0; i < tty->canon_len; i++)
                    ringbuf_push(&tty->input_rb, tty->canon_buf[i], false);
            } else {
                for (uint32_t i = 0; i < tty->canon_len; i++)
                    ringbuf_push(&tty->input_rb, tty->canon_buf[i], true);
            }
            tty->canon_len = 0;
            wake = was_empty && !ringbuf_empty(&tty->input_rb);
        }
        if (cmd == TCSETSF) {
            ringbuf_reset(&tty->input_rb);
            tty->canon_len = 0;
            tty->eof_pending = false;
            wake = false;
        }
        tty->termios = t;
        struct vnode *wake_vn = tty->vnode;
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);
        if (tty->driver && tty->driver->ops && tty->driver->ops->set_termios)
            tty->driver->ops->set_termios(tty, &old);
        if (wake && wake_vn)
            vfs_poll_wake(wake_vn, POLLIN);
        return 0;
    }
    case TIOCGPGRP: {
        if (!arg)
            return -EFAULT;
        pid_t pgrp = tty->fg_pgrp;
        if (copy_to_user((void *)arg, &pgrp, sizeof(pgrp)) < 0)
            return -EFAULT;
        return 0;
    }
    case TIOCSPGRP: {
        if (!arg)
            return -EFAULT;
        pid_t pgrp;
        if (copy_from_user(&pgrp, (void *)arg, sizeof(pgrp)) < 0)
            return -EFAULT;
        bool irq_state = arch_irq_save();
        spin_lock(&tty->lock);
        tty->fg_pgrp = pgrp;
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);
        return 0;
    }
    case TIOCSCTTY: {
        struct process *p = proc_current();
        if (!p)
            return -ESRCH;
        if (p->pid != p->sid)
            return -EPERM;
        if (p->ctty)
            return -EPERM;
        if (tty->session != 0 && tty->session != p->sid)
            return -EPERM;
        bool irq_state = arch_irq_save();
        spin_lock(&tty->lock);
        tty->session = p->sid;
        tty->fg_pgrp = p->pgid;
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);
        p->ctty = tty;
        return 0;
    }
    case TIOCNOTTY: {
        struct process *p = proc_current();
        if (!p || p->ctty != tty)
            return -ENOTTY;
        p->ctty = NULL;
        if (p->pid == p->sid) {
            bool irq_state = arch_irq_save();
            spin_lock(&tty->lock);
            tty->session = 0;
            tty->fg_pgrp = 0;
            spin_unlock(&tty->lock);
            arch_irq_restore(irq_state);
        }
        return 0;
    }
    case TIOCGWINSZ: {
        if (!arg)
            return -EFAULT;
        if (copy_to_user((void *)arg, &tty->winsize,
                         sizeof(tty->winsize)) < 0)
            return -EFAULT;
        return 0;
    }
    case TIOCSWINSZ: {
        if (!arg)
            return -EFAULT;
        if (copy_from_user(&tty->winsize, (void *)arg,
                           sizeof(tty->winsize)) < 0)
            return -EFAULT;
        return 0;
    }
    case TIOCGSID: {
        if (!arg)
            return -EFAULT;
        pid_t sid = tty->session;
        if (copy_to_user((void *)arg, &sid, sizeof(sid)) < 0)
            return -EFAULT;
        return 0;
    }
    case FIONREAD: {
        if (!arg)
            return -EFAULT;
        int avail = 0;
        bool irq_state = arch_irq_save();
        spin_lock(&tty->lock);
        avail = (int)ringbuf_len(&tty->input_rb);
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);
        if (copy_to_user((void *)arg, &avail, sizeof(avail)) < 0)
            return -EFAULT;
        return 0;
    }
    case TCFLSH: {
        if (arg == 0 || arg == 2) {
            if (tty->ldisc.ops && tty->ldisc.ops->flush_buffer)
                tty->ldisc.ops->flush_buffer(tty);
        }
        return 0;
    }
    case TCSBRK:
    case TCSBRKP:
        return 0;
    default:
        return -ENOTTY;
    }
}
