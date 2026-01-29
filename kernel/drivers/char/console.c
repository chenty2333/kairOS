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
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

/* Simple console input buffer with minimal line discipline. */
#define CONSOLE_BUF_SIZE 128
static char console_buf[CONSOLE_BUF_SIZE];
static unsigned int console_head;
static unsigned int console_tail;
static spinlock_t console_lock = SPINLOCK_INIT;
static struct vnode *console_vnode;

static struct winsize console_winsize = {.ws_row = 24, .ws_col = 80};
static struct termios console_termios = {
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
};
static char console_canon_buf[CONSOLE_BUF_SIZE];
static unsigned int console_canon_len;

void console_attach_vnode(struct vnode *vn) {
    console_vnode = vn;
}

static inline bool console_buf_empty(void) {
    return console_head == console_tail;
}

static inline bool console_buf_full(void) {
    return ((console_head + 1) % CONSOLE_BUF_SIZE) == console_tail;
}

static size_t console_buf_len(void) {
    if (console_head >= console_tail)
        return console_head - console_tail;
    return CONSOLE_BUF_SIZE - console_tail + console_head;
}

static void console_buf_put(char c) {
    if (console_buf_full()) {
        console_tail = (console_tail + 1) % CONSOLE_BUF_SIZE;
    }
    console_buf[console_head] = c;
    console_head = (console_head + 1) % CONSOLE_BUF_SIZE;
}

static bool console_buf_get(char *out) {
    if (console_buf_empty())
        return false;
    *out = console_buf[console_tail];
    console_tail = (console_tail + 1) % CONSOLE_BUF_SIZE;
    return true;
}

static void console_echo_char(char c) {
    if (!(console_termios.c_lflag & ECHO))
        return;
    if ((console_termios.c_oflag & OPOST) &&
        (console_termios.c_oflag & ONLCR) && c == '\n') {
        arch_early_putchar('\r');
    }
    arch_early_putchar(c);
}

static void console_canon_commit(void) {
    for (unsigned int i = 0; i < console_canon_len; i++) {
        console_buf_put(console_canon_buf[i]);
    }
    console_canon_len = 0;
}

static void console_flush_input(void) {
    console_head = console_tail = 0;
    console_canon_len = 0;
}

static void console_handle_input_char(char c, bool *pushed) {
    if (console_termios.c_iflag & ICRNL) {
        if (c == '\r')
            c = '\n';
    } else if (console_termios.c_iflag & INLCR) {
        if (c == '\n')
            c = '\r';
    } else if (console_termios.c_iflag & IGNCR) {
        if (c == '\r')
            return;
    }

    if (console_termios.c_lflag & ICANON) {
        char erase = console_termios.c_cc[VERASE]
                         ? (char)console_termios.c_cc[VERASE]
                         : (char)0x7f;
        char kill = console_termios.c_cc[VKILL]
                        ? (char)console_termios.c_cc[VKILL]
                        : (char)0x15;
        char intr = console_termios.c_cc[VINTR]
                        ? (char)console_termios.c_cc[VINTR]
                        : (char)0x03;
        char quit = console_termios.c_cc[VQUIT]
                        ? (char)console_termios.c_cc[VQUIT]
                        : (char)0x1c;

        if ((console_termios.c_lflag & ISIG) &&
            (c == intr || c == quit)) {
            console_canon_len = 0;
            if (console_termios.c_lflag & ECHO) {
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
            if (console_canon_len > 0) {
                console_canon_len--;
                if (console_termios.c_lflag & ECHO) {
                    arch_early_putchar('\b');
                    arch_early_putchar(' ');
                    arch_early_putchar('\b');
                }
            }
            return;
        }

        if (c == kill) {
            if (console_termios.c_lflag & ECHO) {
                while (console_canon_len > 0) {
                    arch_early_putchar('\b');
                    arch_early_putchar(' ');
                    arch_early_putchar('\b');
                    console_canon_len--;
                }
            } else {
                console_canon_len = 0;
            }
            return;
        }

        if (console_canon_len < CONSOLE_BUF_SIZE) {
            console_canon_buf[console_canon_len++] = c;
        }
        console_echo_char(c);
        if (c == '\n') {
            console_canon_commit();
            if (pushed)
                *pushed = true;
        }
        return;
    }

    console_buf_put(c);
    console_echo_char(c);
    if (pushed)
        *pushed = true;
}

static bool console_try_fill(void) {
    int ch = arch_early_getchar_nb();
    if (ch < 0)
        return false;
    bool was_empty;
    bool pushed = false;
    spin_lock(&console_lock);
    was_empty = console_buf_empty();
    console_handle_input_char((char)ch, &pushed);
    spin_unlock(&console_lock);
    if (pushed && was_empty && console_vnode)
        vfs_poll_wake(console_vnode, POLLIN);
    return true;
}

void console_poll_input(void) {
    if (!console_vnode)
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

    char ch;
    for (;;) {
        spin_lock(&console_lock);
        if (console_buf_get(&ch)) {
            spin_unlock(&console_lock);
            ((char *)buf)[0] = ch;
            return 1;
        }
        spin_unlock(&console_lock);

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
    const char *p = buf;
    for (size_t i = 0; i < len; i++) {
        if ((console_termios.c_oflag & OPOST) &&
            (console_termios.c_oflag & ONLCR) && p[i] == '\n') {
            arch_early_putchar('\r');
        }
        arch_early_putchar(p[i]);
    }
    if (console_vnode)
        vfs_poll_wake(console_vnode, POLLIN | POLLOUT);
    return (ssize_t)len;
}

int console_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg) {
    if (!vn)
        return -EINVAL;
    switch (cmd) {
    case TCGETS: {
        if (!arg)
            return -EFAULT;
        if (copy_to_user((void *)arg, &console_termios,
                         sizeof(console_termios)) < 0)
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
        spin_lock(&console_lock);
        bool was_empty = console_buf_empty();
        if ((console_termios.c_lflag & ICANON) &&
            !(t.c_lflag & ICANON) && console_canon_len > 0) {
            console_canon_commit();
            wake = was_empty && !console_buf_empty();
        }
        if (cmd == TCSETSF) {
            console_flush_input();
            wake = false;
        }
        console_termios = t;
        spin_unlock(&console_lock);
        if (wake && console_vnode)
            vfs_poll_wake(console_vnode, POLLIN);
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
        if (copy_to_user((void *)arg, &console_winsize,
                         sizeof(console_winsize)) < 0)
            return -EFAULT;
        return 0;
    }
    case TIOCSWINSZ: {
        if (!arg)
            return -EFAULT;
        if (copy_from_user(&console_winsize, (void *)arg,
                           sizeof(console_winsize)) < 0)
            return -EFAULT;
        return 0;
    }
    case FIONREAD: {
        if (!arg)
            return -EFAULT;
        int avail = 0;
        spin_lock(&console_lock);
        avail = (int)console_buf_len();
        spin_unlock(&console_lock);
        if (copy_to_user((void *)arg, &avail, sizeof(avail)) < 0)
            return -EFAULT;
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

int console_poll(struct vnode *vn, uint32_t events) {
    if (!vn)
        return POLLNVAL;
    uint32_t revents = 0;
    console_try_fill();
    spin_lock(&console_lock);
    if (!console_buf_empty())
        revents |= POLLIN;
    spin_unlock(&console_lock);
    revents |= POLLOUT;
    return (int)(revents & events);
}
