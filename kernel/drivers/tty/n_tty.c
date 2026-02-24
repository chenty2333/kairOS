/**
 * kernel/drivers/tty/n_tty.c - N_TTY line discipline
 */

#include <kairos/arch.h>
#include <kairos/poll.h>
#include <kairos/process.h>
#include <kairos/ringbuf.h>
#include <kairos/signal.h>
#include <kairos/tty.h>
#include <kairos/tty_ldisc.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

/* ── Echo helpers ─────────────────────────────────────────────────── */

static void n_tty_echo_char(struct tty_struct *tty, char c) {
    if (!(tty->termios.c_lflag & ECHO))
        return;
    if ((tty->termios.c_lflag & ECHOCTL) &&
        (unsigned char)c < 0x20 && c != '\n' && c != '\t') {
        if (tty->driver && tty->driver->ops && tty->driver->ops->put_char) {
            tty->driver->ops->put_char(tty, '^');
            tty->driver->ops->put_char(tty, c + '@');
        }
        return;
    }
    if ((tty->termios.c_oflag & OPOST) &&
        (tty->termios.c_oflag & ONLCR) && c == '\n') {
        if (tty->driver && tty->driver->ops && tty->driver->ops->put_char)
            tty->driver->ops->put_char(tty, '\r');
    }
    if (tty->driver && tty->driver->ops && tty->driver->ops->put_char)
        tty->driver->ops->put_char(tty, (uint8_t)c);
}

static int n_tty_echo_width(struct tty_struct *tty, char c) {
    if ((tty->termios.c_lflag & ECHOCTL) &&
        (unsigned char)c < 0x20 && c != '\n' && c != '\t')
        return 2;  /* ^X */
    return 1;
}

static void n_tty_erase_char(struct tty_struct *tty, char erased) {
    if (!(tty->termios.c_lflag & ECHO))
        return;
    if (!tty->driver || !tty->driver->ops || !tty->driver->ops->put_char)
        return;
    int cols = n_tty_echo_width(tty, erased);
    for (int i = 0; i < cols; i++) {
        tty->driver->ops->put_char(tty, '\b');
        tty->driver->ops->put_char(tty, ' ');
        tty->driver->ops->put_char(tty, '\b');
    }
}

/* ── Canon buffer helpers (called under tty->lock) ────────────────── */

static bool n_tty_canon_commit(struct tty_struct *tty) {
    size_t avail = ringbuf_avail(&tty->input_rb);
    if (avail < tty->canon_len) {
        if (tty->driver && tty->driver->ops && tty->driver->ops->put_char)
            tty->driver->ops->put_char(tty, '\a');
        return false;
    }
    for (uint32_t i = 0; i < tty->canon_len; i++)
        ringbuf_push(&tty->input_rb, tty->canon_buf[i], false);
    tty->canon_len = 0;
    return true;
}

static void n_tty_flush_input(struct tty_struct *tty) {
    ringbuf_reset(&tty->input_rb);
    tty->canon_len = 0;
    tty->eof_pending = false;
}

/* ── Process one input character (called under tty->lock) ────────── */

static void n_tty_handle_char(struct tty_struct *tty, char c,
                               bool *pushed, uint32_t *sig_mask) {
    /* Input translation (POSIX order: IGNCR before ICRNL) */
    if ((tty->termios.c_iflag & IGNCR) && c == '\r')
        return;
    if ((tty->termios.c_iflag & ICRNL) && c == '\r')
        c = '\n';
    else if ((tty->termios.c_iflag & INLCR) && c == '\n')
        c = '\r';

    /* ISIG: signal characters (independent of ICANON per POSIX) */
    if (tty->termios.c_lflag & ISIG) {
        char intr = tty->termios.c_cc[VINTR]
                        ? (char)tty->termios.c_cc[VINTR] : (char)0x03;
        char quit = tty->termios.c_cc[VQUIT]
                        ? (char)tty->termios.c_cc[VQUIT] : (char)0x1c;

        if (c == intr || c == quit) {
            tty->canon_len = 0;
            n_tty_echo_char(tty, c);
            n_tty_echo_char(tty, '\n');
            *sig_mask |= (1U << ((c == intr) ? SIGINT : SIGQUIT));
            return;
        }

        char susp = tty->termios.c_cc[VSUSP]
                        ? (char)tty->termios.c_cc[VSUSP] : (char)0x1a;
        if (c == susp) {
            n_tty_echo_char(tty, c);
            n_tty_echo_char(tty, '\n');
            *sig_mask |= (1U << SIGTSTP);
            return;
        }
    }

    /* ICANON mode: line editing */
    if (tty->termios.c_lflag & ICANON) {
        char veof = tty->termios.c_cc[VEOF]
                        ? (char)tty->termios.c_cc[VEOF] : (char)0x04;
        if (c == veof) {
            if (tty->canon_len > 0) {
                if (n_tty_canon_commit(tty)) {
                    if (pushed) *pushed = true;
                }
            } else {
                tty->eof_pending = true;
                if (pushed) *pushed = true;
            }
            return;
        }

        char erase = tty->termios.c_cc[VERASE]
                         ? (char)tty->termios.c_cc[VERASE] : (char)0x7f;
        char kill = tty->termios.c_cc[VKILL]
                        ? (char)tty->termios.c_cc[VKILL] : (char)0x15;

        if (c == erase || c == '\b') {
            if (tty->canon_len > 0) {
                char erased = tty->canon_buf[--tty->canon_len];
                n_tty_erase_char(tty, erased);
            }
            return;
        }

        if (c == kill) {
            if (tty->termios.c_lflag & ECHO) {
                while (tty->canon_len > 0) {
                    char erased = tty->canon_buf[--tty->canon_len];
                    n_tty_erase_char(tty, erased);
                }
            } else {
                tty->canon_len = 0;
            }
            return;
        }

        if (tty->canon_len < TTY_CANON_BUF_SIZE) {
            tty->canon_buf[tty->canon_len++] = c;
        } else {
            if (tty->driver && tty->driver->ops && tty->driver->ops->put_char)
                tty->driver->ops->put_char(tty, '\a');
            return;
        }
        n_tty_echo_char(tty, c);
        if (c == '\n') {
            if (n_tty_canon_commit(tty)) {
                if (pushed) *pushed = true;
            }
        }
        return;
    }

    /* Raw mode: push directly to ringbuf */
    ringbuf_push(&tty->input_rb, c, false);
    n_tty_echo_char(tty, c);
    if (pushed) *pushed = true;
}

/* ── Ldisc ops ────────────────────────────────────────────────────── */

static int n_tty_open(struct tty_struct *tty) {
    tty->canon_len = 0;
    tty->eof_pending = false;
    return 0;
}

static void n_tty_close(struct tty_struct *tty) {
    ringbuf_reset(&tty->input_rb);
    tty->canon_len = 0;
    tty->eof_pending = false;
}

static void n_tty_receive_buf(struct tty_struct *tty, const uint8_t *buf,
                               size_t count, bool *pushed,
                               uint32_t *sig_mask) {
    for (size_t i = 0; i < count; i++)
        n_tty_handle_char(tty, (char)buf[i], pushed, sig_mask);
}

static ssize_t n_tty_read(struct tty_struct *tty, uint8_t *buf, size_t count,
                           uint32_t flags) {
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
        bool is_canon = tty->termios.c_lflag & ICANON;
        while (got < count && ringbuf_pop(&tty->input_rb, &ch)) {
            buf[got++] = (uint8_t)ch;
            /* In canonical mode, return at most one line */
            if (is_canon && ch == '\n')
                break;
        }
        bool eof = false;
        if (got == 0 && tty->eof_pending) {
            tty->eof_pending = false;
            eof = true;
        }
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);

        if (got > 0)
            return (ssize_t)got;
        if (eof)
            return 0;
        if (flags & O_NONBLOCK)
            return -EAGAIN;

        /* Block waiting for input */
        if (!vn)
            return -EIO;

        /* Check once more under lock before sleeping */
        irq_state = arch_irq_save();
        spin_lock(&tty->lock);
        bool has_data = !ringbuf_empty(&tty->input_rb) || tty->eof_pending;
        spin_unlock(&tty->lock);
        arch_irq_restore(irq_state);
        if (has_data)
            continue;

        int rc = proc_sleep_on(&tty->read_wait, &tty->read_wait, true);
        if (rc == -EINTR)
            return -EINTR;
    }
}

static ssize_t n_tty_write(struct tty_struct *tty, const uint8_t *buf,
                            size_t count, uint32_t flags) {
    if (!tty || !buf)
        return -EINVAL;
    if (!tty->driver || !tty->driver->ops || !tty->driver->ops->write)
        return -EIO;

    bool do_opost = (tty->termios.c_oflag & OPOST) &&
                    (tty->termios.c_oflag & ONLCR);

    if (!do_opost) {
        ssize_t ret = tty->driver->ops->write(tty, buf, count, flags);
        if (ret < 0)
            return ret;
        return ret;
    }

    /* OPOST with ONLCR: write per-byte to preserve non-blocking semantics. */
    size_t in_done = 0;
    for (; in_done < count; in_done++) {
        uint8_t out[2];
        size_t out_len = 1;
        if (buf[in_done] == '\n') {
            out[0] = '\r';
            out[1] = '\n';
            out_len = 2;
        } else {
            out[0] = buf[in_done];
        }

        for (size_t oi = 0; oi < out_len; oi++) {
            ssize_t wr = tty->driver->ops->write(tty, &out[oi], 1, flags);
            if (wr < 0)
                return in_done ? (ssize_t)in_done : wr;
            if (wr == 0)
                return (ssize_t)in_done;
        }
    }
    return (ssize_t)in_done;
}

static int n_tty_poll(struct tty_struct *tty, uint32_t events) {
    uint32_t revents = 0;
    bool irq_state = arch_irq_save();
    spin_lock(&tty->lock);
    if (!ringbuf_empty(&tty->input_rb) || tty->eof_pending)
        revents |= POLLIN;
    spin_unlock(&tty->lock);
    arch_irq_restore(irq_state);
    revents |= POLLOUT;  /* output always ready (no output buffer) */
    return (int)(revents & events);
}

static void n_tty_flush(struct tty_struct *tty) {
    bool irq_state = arch_irq_save();
    spin_lock(&tty->lock);
    n_tty_flush_input(tty);
    spin_unlock(&tty->lock);
    arch_irq_restore(irq_state);
}

/* ── Ops table ────────────────────────────────────────────────────── */

const struct tty_ldisc_ops n_tty_ops = {
    .open         = n_tty_open,
    .close        = n_tty_close,
    .read         = n_tty_read,
    .write        = n_tty_write,
    .receive_buf  = n_tty_receive_buf,
    .poll         = n_tty_poll,
    .flush_buffer = n_tty_flush,
};

void n_tty_init(struct tty_struct *tty) {
    tty->ldisc.ops = &n_tty_ops;
}
