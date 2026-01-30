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
#include <kairos/types.h>
#include <kairos/ringbuf.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

/* Simple console input buffer with minimal line discipline. */
#define CONSOLE_BUF_SIZE 128

struct console_state {
    spinlock_t lock;
    struct ringbuf in_rb;
    char in_storage[CONSOLE_BUF_SIZE];
    char canon_buf[CONSOLE_BUF_SIZE];
    uint32_t canon_len;
    struct vnode *vnode;
    struct winsize winsize;
    struct termios termios;
};

static struct console_state console_state = {
    .lock = SPINLOCK_INIT,
    .winsize = {.ws_row = 24, .ws_col = 80},
    .termios = {
    .c_iflag = ICRNL,
    .c_oflag = OPOST | ONLCR,
    .c_lflag = ISIG | ICANON | ECHO,
    .c_cc = {
        [VINTR] = 3,   /* ^C */
        [VQUIT] = 28,  /* ^\ */
        [VERASE] = 127,/* DEL */
        [VKILL] = 21,  /* ^U */
        [VEOF] = 4,    /* ^D */
        [VTIME] = 0,
        [VMIN] = 1,
    },
    },
};

static void console_state_init_once(void) {
    static bool initialized;
    if (initialized)
        return;
    ringbuf_init(&console_state.in_rb, console_state.in_storage,
                 CONSOLE_BUF_SIZE);
    console_state.canon_len = 0;
    initialized = true;
}

void console_attach_vnode(struct vnode *vn) {
    console_state_init_once();
    spin_lock(&console_state.lock);
    console_state.vnode = vn;
    spin_unlock(&console_state.lock);
}

static void console_echo_char(char c) {
    if (!(console_state.termios.c_lflag & ECHO))
        return;
    if ((console_state.termios.c_oflag & OPOST) &&
        (console_state.termios.c_oflag & ONLCR) && c == '\n') {
        arch_early_putchar('\r');
    }
    arch_early_putchar(c);
}

static void console_canon_commit(void) {
    for (uint32_t i = 0; i < console_state.canon_len; i++) {
        ringbuf_push(&console_state.in_rb, console_state.canon_buf[i], true);
    }
    console_state.canon_len = 0;
}

static void console_flush_input(void) {
    console_state.in_rb.head = 0;
    console_state.in_rb.tail = 0;
    console_state.canon_len = 0;
}

static void console_handle_input_char(char c, bool *pushed) {
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

    if (console_state.termios.c_lflag & ICANON) {
        char erase = console_state.termios.c_cc[VERASE]
                         ? (char)console_state.termios.c_cc[VERASE]
                         : (char)0x7f;
        char kill = console_state.termios.c_cc[VKILL]
                        ? (char)console_state.termios.c_cc[VKILL]
                        : (char)0x15;
        char intr = console_state.termios.c_cc[VINTR]
                        ? (char)console_state.termios.c_cc[VINTR]
                        : (char)0x03;
        char quit = console_state.termios.c_cc[VQUIT]
                        ? (char)console_state.termios.c_cc[VQUIT]
                        : (char)0x1c;

        if ((console_state.termios.c_lflag & ISIG) &&
            (c == intr || c == quit)) {
            console_state.canon_len = 0;
            if (console_state.termios.c_lflag & ECHO) {
                arch_early_putchar('^');
                arch_early_putchar(c == intr ? 'C' : '\\');
                console_echo_char('\n');
            }
            struct process *p = proc_current();
            if (p)
                signal_send(p->pid, c == intr ? SIGINT : SIGQUIT);
            return;
        }

        if (c == erase || c == '\b') {
            if (console_state.canon_len > 0) {
                console_state.canon_len--;
                if (console_state.termios.c_lflag & ECHO) {
                    arch_early_putchar('\b');
                    arch_early_putchar(' ');
                    arch_early_putchar('\b');
                }
            }
            return;
        }

        if (c == kill) {
            if (console_state.termios.c_lflag & ECHO) {
                while (console_state.canon_len > 0) {
                    arch_early_putchar('\b');
                    arch_early_putchar(' ');
                    arch_early_putchar('\b');
                    console_state.canon_len--;
                }
            } else {
                console_state.canon_len = 0;
            }
            return;
        }

        if (console_state.canon_len < CONSOLE_BUF_SIZE) {
            console_state.canon_buf[console_state.canon_len++] = c;
        }
        console_echo_char(c);
        if (c == '\n') {
            console_canon_commit();
            if (pushed)
                *pushed = true;
        }
        return;
    }

    ringbuf_push(&console_state.in_rb, c, true);
    console_echo_char(c);
    if (pushed)
        *pushed = true;
}

static bool console_try_fill(void) {
    console_state_init_once();
    int ch = arch_early_getchar_nb();
    if (ch < 0)
        return false;
    bool was_empty;
    bool pushed = false;
    spin_lock(&console_state.lock);
    was_empty = ringbuf_empty(&console_state.in_rb);
    console_handle_input_char((char)ch, &pushed);
    struct vnode *vn = console_state.vnode;
    spin_unlock(&console_state.lock);
    if (pushed && was_empty && vn)
        vfs_poll_wake(vn, POLLIN);
    return true;
}

void console_poll_input(void) {
    console_state_init_once();
    if (!console_state.vnode)
        return;
    while (console_try_fill()) {
    }
}

ssize_t console_read(struct vnode *vn, void *buf, size_t len,
                     off_t off __attribute__((unused))) {
    if (!vn || !buf)
        return -EINVAL;
    if (len == 0)
        return 0;

    console_state_init_once();
    char ch;
    for (;;) {
        spin_lock(&console_state.lock);
        if (ringbuf_pop(&console_state.in_rb, &ch)) {
            spin_unlock(&console_state.lock);
            ((char *)buf)[0] = ch;
            return 1;
        }
        spin_unlock(&console_state.lock);

        if (console_try_fill())
            continue;

        struct process *p = proc_current();
        if (!p)
            return -EAGAIN;

        struct poll_waiter waiter = {0};
        INIT_LIST_HEAD(&waiter.entry.node);
        waiter.entry.proc = p;
        poll_wait_add(&vn->pollers, &waiter);
        if (console_try_fill()) {
            poll_wait_remove(&waiter);
            continue;
        }
        proc_sleep(&waiter);
        poll_wait_remove(&waiter);
    }
}

ssize_t console_write(struct vnode *vn, const void *buf, size_t len,
                      off_t off __attribute__((unused))) {
    if (!vn || !buf)
        return -EINVAL;
    console_state_init_once();
    const char *p = buf;
    for (size_t i = 0; i < len; i++) {
        if ((console_state.termios.c_oflag & OPOST) &&
            (console_state.termios.c_oflag & ONLCR) && p[i] == '\n') {
            arch_early_putchar('\r');
        }
        arch_early_putchar(p[i]);
    }
    if (console_state.vnode)
        vfs_poll_wake(console_state.vnode, POLLIN | POLLOUT);
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
    case TCSETSW:
    case TCSETSF: {
        if (!arg)
            return -EFAULT;
        struct termios t;
        if (copy_from_user(&t, (void *)arg, sizeof(t)) < 0)
            return -EFAULT;
        bool wake = false;
        spin_lock(&console_state.lock);
        bool was_empty = ringbuf_empty(&console_state.in_rb);
        if ((console_state.termios.c_lflag & ICANON) &&
            !(t.c_lflag & ICANON) && console_state.canon_len > 0) {
            console_canon_commit();
            wake = was_empty && !ringbuf_empty(&console_state.in_rb);
        }
        if (cmd == TCSETSF) {
            console_flush_input();
            wake = false;
        }
        console_state.termios = t;
        struct vnode *wake_vn = console_state.vnode;
        spin_unlock(&console_state.lock);
        if (wake && wake_vn)
            vfs_poll_wake(wake_vn, POLLIN);
        return 0;
    }
    case TIOCGPGRP: {
        if (!arg)
            return -EFAULT;
        pid_t pgrp = 0;
        struct process *p = proc_current();
        if (p)
            pgrp = p->pid;
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
        return 0;
    }
    case TIOCSCTTY:
        return 0;
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
        spin_lock(&console_state.lock);
        avail = (int)ringbuf_len(&console_state.in_rb);
        spin_unlock(&console_state.lock);
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
        spin_lock(&console_state.lock);
        if (arg == 0 || arg == 2) {
            /* Flush input */
            console_flush_input();
        }
        /* arg == 1 or 2: flush output (no output buffer to flush) */
        spin_unlock(&console_state.lock);
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
    console_try_fill();
    spin_lock(&console_state.lock);
    if (!ringbuf_empty(&console_state.in_rb))
        revents |= POLLIN;
    spin_unlock(&console_state.lock);
    revents |= POLLOUT;
    return (int)(revents & events);
}
