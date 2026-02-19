/**
 * kernel/drivers/char/console.c - Simple console device
 */

#include <kairos/arch.h>
#include <kairos/console.h>
#include <kairos/ioctl.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/process.h>
#include <kairos/signal.h>
#include <kairos/spinlock.h>
#include <kairos/ringbuf.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

/* Simple console input buffer with minimal line discipline. */
#define CONSOLE_BUF_SIZE  1024
#define CANON_BUF_SIZE    256

struct console_state {
    spinlock_t lock;
    struct ringbuf in_rb;
    char in_storage[CONSOLE_BUF_SIZE];
    char canon_buf[CANON_BUF_SIZE];
    uint32_t canon_len;
    bool eof_pending;
    struct vnode *vnode;
    pid_t fg_pgrp;              /* foreground process group */
    struct winsize winsize;
    struct termios termios;
};

static struct console_state console_state = {
    .lock = SPINLOCK_INIT,
    .winsize = {.ws_row = 24, .ws_col = 80},
    .termios = {
    .c_iflag = ICRNL,
    .c_oflag = OPOST | ONLCR,
    .c_lflag = ISIG | ICANON | ECHO | ECHOCTL,
    .c_cc = {
        [VINTR] = 3,   /* ^C */
        [VQUIT] = 28,  /* ^\ */
        [VERASE] = 127,/* DEL */
        [VKILL] = 21,  /* ^U */
        [VEOF] = 4,    /* ^D */
        [VTIME] = 0,
        [VMIN] = 1,
        [VSUSP] = 26,  /* ^Z */
    },
    },
};

static inline bool console_lock_irqsave(void) {
    bool irq_state = arch_irq_save();
    spin_lock(&console_state.lock);
    return irq_state;
}

static inline void console_unlock_irqrestore(bool irq_state) {
    spin_unlock(&console_state.lock);
    arch_irq_restore(irq_state);
}

/*
 * One-time init.  Double-init is idempotent (ringbuf_init writes head=tail=0,
 * canon_len and eof_pending are zeroed).  Only called at boot on a single core,
 * so no atomics needed for the `initialized` flag.
 */
static void console_state_init_once(void) {
    static bool initialized;
    if (initialized)
        return;
    ringbuf_init(&console_state.in_rb, console_state.in_storage,
                 CONSOLE_BUF_SIZE);
    console_state.canon_len = 0;
    console_state.eof_pending = false;
    initialized = true;
}

void console_attach_vnode(struct vnode *vn) {
    console_state_init_once();
    bool irq_state = console_lock_irqsave();
    console_state.vnode = vn;
    console_unlock_irqrestore(irq_state);
}

/* Echo helper — called under lock.  Safe with IRQs off: SBI ecall holds no kernel locks. */
static void console_echo_char(char c) {
    if (!(console_state.termios.c_lflag & ECHO))
        return;
    if ((console_state.termios.c_lflag & ECHOCTL) &&
        (unsigned char)c < 0x20 && c != '\n' && c != '\t') {
        arch_early_putchar('^');
        arch_early_putchar(c + '@');
        return;
    }
    if ((console_state.termios.c_oflag & OPOST) &&
        (console_state.termios.c_oflag & ONLCR) && c == '\n') {
        arch_early_putchar('\r');
    }
    arch_early_putchar(c);
}

/* Return the display width of a character as echoed by console_echo_char. */
static int console_echo_width(char c) {
    if ((console_state.termios.c_lflag & ECHOCTL) &&
        (unsigned char)c < 0x20 && c != '\n' && c != '\t')
        return 2;  /* ^X */
    return 1;
}

static bool console_canon_commit(void) {
    size_t avail = ringbuf_avail(&console_state.in_rb);
    if (avail < console_state.canon_len) {
        arch_early_putchar('\a');  /* BEL - no room, keep canon_buf for retry */
        return false;
    }
    for (uint32_t i = 0; i < console_state.canon_len; i++)
        ringbuf_push(&console_state.in_rb, console_state.canon_buf[i], false);
    console_state.canon_len = 0;
    return true;
}

static void console_flush_input(void) {
    ringbuf_reset(&console_state.in_rb);
    console_state.canon_len = 0;
    console_state.eof_pending = false;
}

/*
 * Process one input character under console_state.lock (irqsave).
 * Signal delivery is deferred via *sig_mask (bitmask) to keep proc locks
 * out of the critical section.  *pushed is set when data enters the ringbuf.
 */
static void console_handle_input_char(char c, bool *pushed, uint32_t *sig_mask) {
    if (console_state.termios.c_iflag & ICRNL) {
        if (c == '\r')
            c = '\n';
    } else if (console_state.termios.c_iflag & INLCR) {
        if (c == '\n')
            c = '\r';
    } else if (console_state.termios.c_iflag & IGNCR) {
        if (c == '\r')
            return;
    }

    /* ISIG is independent of ICANON (POSIX). */
    if (console_state.termios.c_lflag & ISIG) {
        char intr = console_state.termios.c_cc[VINTR]
                        ? (char)console_state.termios.c_cc[VINTR]
                        : (char)0x03;
        char quit = console_state.termios.c_cc[VQUIT]
                        ? (char)console_state.termios.c_cc[VQUIT]
                        : (char)0x1c;

        if (c == intr || c == quit) {
            console_state.canon_len = 0;
            if (console_state.termios.c_lflag & ECHO) {
                if (console_state.termios.c_lflag & ECHOCTL) {
                    arch_early_putchar('^');
                    arch_early_putchar(c + '@');
                }
                console_echo_char('\n');
            }
            *sig_mask |= (1U << ((c == intr) ? SIGINT : SIGQUIT));
            return;
        }

        char susp = console_state.termios.c_cc[VSUSP]
                        ? (char)console_state.termios.c_cc[VSUSP]
                        : (char)0x1a;
        if (c == susp) {
            if (console_state.termios.c_lflag & ECHO) {
                if (console_state.termios.c_lflag & ECHOCTL) {
                    arch_early_putchar('^');
                    arch_early_putchar(c + '@');
                }
                console_echo_char('\n');
            }
            *sig_mask |= (1U << SIGTSTP);
            return;
        }
    }

    if (console_state.termios.c_lflag & ICANON) {
        char veof = console_state.termios.c_cc[VEOF]
                        ? (char)console_state.termios.c_cc[VEOF]
                        : (char)0x04;
        if (c == veof) {
            if (console_state.canon_len > 0) {
                if (console_canon_commit()) {
                    if (pushed) *pushed = true;
                }
            } else {
                console_state.eof_pending = true;
                if (pushed) *pushed = true;  /* wake reader */
            }
            return;
        }

        char erase = console_state.termios.c_cc[VERASE]
                         ? (char)console_state.termios.c_cc[VERASE]
                         : (char)0x7f;
        char kill = console_state.termios.c_cc[VKILL]
                        ? (char)console_state.termios.c_cc[VKILL]
                        : (char)0x15;

        if (c == erase || c == '\b') {
            if (console_state.canon_len > 0) {
                char erased = console_state.canon_buf[--console_state.canon_len];
                if (console_state.termios.c_lflag & ECHO) {
                    int cols = console_echo_width(erased);
                    for (int i = 0; i < cols; i++) {
                        arch_early_putchar('\b');
                        arch_early_putchar(' ');
                        arch_early_putchar('\b');
                    }
                }
            }
            return;
        }

        if (c == kill) {
            if (console_state.termios.c_lflag & ECHO) {
                while (console_state.canon_len > 0) {
                    char erased = console_state.canon_buf[--console_state.canon_len];
                    int cols = console_echo_width(erased);
                    for (int i = 0; i < cols; i++) {
                        arch_early_putchar('\b');
                        arch_early_putchar(' ');
                        arch_early_putchar('\b');
                    }
                }
            } else {
                console_state.canon_len = 0;
            }
            return;
        }

        if (console_state.canon_len < CANON_BUF_SIZE) {
            console_state.canon_buf[console_state.canon_len++] = c;
        } else {
            arch_early_putchar('\a');  /* BEL - buffer full */
            return;
        }
        console_echo_char(c);
        if (c == '\n') {
            if (console_canon_commit()) {
                if (pushed)
                    *pushed = true;
            }
        }
        return;
    }

    /* Raw mode: drop when full to preserve oldest unread data. */
    ringbuf_push(&console_state.in_rb, c, false);
    console_echo_char(c);
    if (pushed)
        *pushed = true;
}

/*
 * Drain UART into the input pipeline.  Reads up to 32 chars from the UART
 * inside the lock to prevent SMP races on the read-to-clear RHR register.
 * Returns the number of characters consumed (0 = nothing ready).
 */
static int console_try_fill_batch(void) {
    console_state_init_once();

    bool pushed = false;
    uint32_t sig_mask = 0;
    int count = 0;

    bool irq_state = console_lock_irqsave();
    while (count < 32) {
        int ch = arch_early_getchar_nb();
        if (ch < 0)
            break;
        console_handle_input_char((char)ch, &pushed, &sig_mask);
        count++;
    }
    struct vnode *vn = console_state.vnode;
    pid_t fg = console_state.fg_pgrp;
    console_unlock_irqrestore(irq_state);

    if (count == 0)
        return 0;

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
    return count;
}

void console_poll_input(void) {
    console_state_init_once();
    if (!console_state.vnode)
        return;
    while (console_try_fill_batch() > 0) {
    }
}

static int console_wait_for_input(struct vnode *vn, struct process *p) {
    struct poll_waiter waiter = {0};
    INIT_LIST_HEAD(&waiter.entry.node);
    waiter.entry.proc = p;

    bool irq_state = console_lock_irqsave();
    if (!ringbuf_empty(&console_state.in_rb) || console_state.eof_pending) {
        console_unlock_irqrestore(irq_state);
        return 0;
    }
    console_unlock_irqrestore(irq_state);

    poll_wait_add(&vn->pollers, &waiter);

    console_try_fill_batch();
    irq_state = console_lock_irqsave();
    bool has_data = !ringbuf_empty(&console_state.in_rb) ||
                    console_state.eof_pending;
    console_unlock_irqrestore(irq_state);
    if (has_data) {
        poll_wait_remove(&waiter);
        return 0;
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

    /*
     * Close the add->sleep race: once waiter+sleeping are visible, re-check
     * input once before yielding.
     */
    console_try_fill_batch();
    irq_state = console_lock_irqsave();
    has_data = !ringbuf_empty(&console_state.in_rb) ||
               console_state.eof_pending;
    console_unlock_irqrestore(irq_state);
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
    return 0;
}

ssize_t console_read(struct vnode *vn, void *buf, size_t len,
                     off_t off __attribute__((unused)),
                     uint32_t flags) {
    if (!vn || !buf)
        return -EINVAL;
    if (len == 0)
        return 0;

    console_state_init_once();

    for (;;) {
        console_try_fill_batch();

        bool irq_state = console_lock_irqsave();
        size_t got = 0;
        char *dst = (char *)buf;
        char ch;
        while (got < len && ringbuf_pop(&console_state.in_rb, &ch))
            dst[got++] = ch;
        bool eof = false;
        if (got == 0 && console_state.eof_pending) {
            console_state.eof_pending = false;
            eof = true;
        }
        console_unlock_irqrestore(irq_state);

        if (got > 0)
            return (ssize_t)got;
        if (eof)
            return 0;
        if (flags & O_NONBLOCK)
            return -EAGAIN;

        struct process *p = proc_current();
        if (!p)
            return -EAGAIN;

        int rc = console_wait_for_input(vn, p);
        if (rc == -EINTR)
            return -EINTR;
    }
}

#define CONSOLE_WRITE_CHUNK 64

ssize_t console_write(struct vnode *vn, const void *buf, size_t len,
                      off_t off __attribute__((unused)),
                      uint32_t flags __attribute__((unused))) {
    if (!vn || !buf)
        return -EINVAL;
    console_state_init_once();
    const char *p = buf;
    for (size_t i = 0; i < len; ) {
        size_t end = i + CONSOLE_WRITE_CHUNK;
        if (end > len) end = len;
        bool irq_state = console_lock_irqsave();
        for (; i < end; i++) {
            if ((console_state.termios.c_oflag & OPOST) &&
                (console_state.termios.c_oflag & ONLCR) && p[i] == '\n')
                arch_early_putchar('\r');
            arch_early_putchar(p[i]);
        }
        console_unlock_irqrestore(irq_state);
    }
    if (console_state.vnode)
        vfs_poll_wake(console_state.vnode, POLLOUT);
    return (ssize_t)len;
}

int console_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg) {
    if (!vn)
        return -EINVAL;
    console_state_init_once();
    switch (cmd) {
    case TCGETS: {
        if (!arg)
            return -EFAULT;
        if (copy_to_user((void *)arg, &console_state.termios,
                         sizeof(console_state.termios)) < 0)
            return -EFAULT;
        return 0;
    }
    case TCSETS:
    case TCSETSW:  /* No output buffer, so drain is a no-op — same as TCSETS */
    case TCSETSF: {
        if (!arg)
            return -EFAULT;
        struct termios t;
        if (copy_from_user(&t, (void *)arg, sizeof(t)) < 0)
            return -EFAULT;
        bool wake = false;
        bool irq_state = console_lock_irqsave();
        bool was_empty = ringbuf_empty(&console_state.in_rb);
        if ((console_state.termios.c_lflag & ICANON) &&
            !(t.c_lflag & ICANON) && console_state.canon_len > 0) {
            if (!console_canon_commit()) {
                /* Force-flush canon_buf on mode switch */
                for (uint32_t i = 0; i < console_state.canon_len; i++)
                    ringbuf_push(&console_state.in_rb,
                                 console_state.canon_buf[i], true);
                console_state.canon_len = 0;
            }
            wake = was_empty && !ringbuf_empty(&console_state.in_rb);
        }
        if (cmd == TCSETSF) {
            console_flush_input();
            wake = false;
        }
        console_state.termios = t;
        struct vnode *wake_vn = console_state.vnode;
        console_unlock_irqrestore(irq_state);
        if (wake && wake_vn)
            vfs_poll_wake(wake_vn, POLLIN);
        return 0;
    }
    case TIOCGPGRP: {
        if (!arg)
            return -EFAULT;
        pid_t pgrp = console_state.fg_pgrp;
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
        bool irq_state = console_lock_irqsave();
        console_state.fg_pgrp = pgrp;
        console_unlock_irqrestore(irq_state);
        return 0;
    }
    case TIOCSCTTY: {
        struct process *p = proc_current();
        if (p) {
            bool irq_state = console_lock_irqsave();
            if (console_state.fg_pgrp == 0)
                console_state.fg_pgrp = p->pgid;
            console_unlock_irqrestore(irq_state);
        }
        return 0;
    }
    case TIOCGWINSZ: {
        if (!arg)
            return -EFAULT;
        if (copy_to_user((void *)arg, &console_state.winsize,
                         sizeof(console_state.winsize)) < 0)
            return -EFAULT;
        return 0;
    }
    case TIOCSWINSZ: {
        if (!arg)
            return -EFAULT;
        if (copy_from_user(&console_state.winsize, (void *)arg,
                           sizeof(console_state.winsize)) < 0)
            return -EFAULT;
        return 0;
    }
    case FIONREAD: {
        if (!arg)
            return -EFAULT;
        int avail = 0;
        bool irq_state = console_lock_irqsave();
        avail = (int)ringbuf_len(&console_state.in_rb);
        console_unlock_irqrestore(irq_state);
        if (copy_to_user((void *)arg, &avail, sizeof(avail)) < 0)
            return -EFAULT;
        return 0;
    }
    case TIOCNOTTY:
        return 0;
    case TIOCGSID: {
        if (!arg)
            return -EFAULT;
        struct process *sp = proc_current();
        pid_t sid = sp ? sp->sid : 0;
        if (copy_to_user((void *)arg, &sid, sizeof(sid)) < 0)
            return -EFAULT;
        return 0;
    }
    case TCFLSH: {
        bool irq_state = console_lock_irqsave();
        if (arg == 0 || arg == 2) {
            /* Flush input */
            console_flush_input();
        }
        /* arg == 1 or 2: flush output (no output buffer to flush) */
        console_unlock_irqrestore(irq_state);
        return 0;
    }
    case TCSBRK:
    case TCSBRKP:
        /* No physical serial line - no-op */
        return 0;
    default:
        return -ENOTTY;
    }
}

int console_poll(struct vnode *vn, uint32_t events) {
    if (!vn)
        return POLLNVAL;
    uint32_t revents = 0;
    console_state_init_once();
    console_try_fill_batch();
    bool irq_state = console_lock_irqsave();
    if (!ringbuf_empty(&console_state.in_rb) || console_state.eof_pending)
        revents |= POLLIN;
    console_unlock_irqrestore(irq_state);
    revents |= POLLOUT;
    return (int)(revents & events);
}
