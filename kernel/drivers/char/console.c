/**
 * kernel/drivers/char/console.c - Console VFS shim
 *
 * Thin adapter between devfs and the TTY layer. All line discipline,
 * termios, and ioctl logic now lives in tty_core.c / n_tty.c.
 * This file only handles:
 *   1. VFS file_ops → tty_read/write/ioctl/poll delegation
 *   2. UART polling (arch_early_getchar_nb → tty_receive_buf)
 *   3. Vnode attachment for poll wakeups
 */

#include <kairos/arch.h>
#include <kairos/console.h>
#include <kairos/poll.h>
#include <kairos/tty.h>
#include <kairos/tty_driver.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

/* ── Helpers ─────────────────────────────────────────────────────── */

static struct tty_struct *console_get_tty(void) {
    return console_tty_get();
}

/* ── Vnode attachment ────────────────────────────────────────────── */

static bool console_initialized;

void console_attach_vnode(struct vnode *vn) {
    struct tty_struct *tty = console_get_tty();
    if (!tty) {
        /* TTY layer not yet initialized — defer.
         * console_tty_driver_init() will be called before first use. */
        console_tty_driver_init();
        tty = console_get_tty();
    }
    if (tty)
        tty->vnode = vn;
    console_initialized = true;
}

/* ── Input polling ───────────────────────────────────────────────── */

/*
 * Drain UART into the TTY input pipeline.
 * Reads up to 32 chars per call from the hardware.
 */
static int console_try_fill_batch(void) {
    struct tty_struct *tty = console_get_tty();
    if (!tty)
        return 0;

    uint8_t batch[32];
    int count = 0;
    while (count < 32) {
        int ch = arch_early_getchar_nb();
        if (ch < 0)
            break;
        batch[count++] = (uint8_t)ch;
    }
    if (count > 0)
        tty_receive_buf(tty, batch, (size_t)count);
    return count;
}

void console_poll_input(void) {
    if (!console_initialized)
        return;
    while (console_try_fill_batch() > 0)
        ;
}

/* ── VFS entry points ────────────────────────────────────────────── */

ssize_t console_read(struct vnode *vn, void *buf, size_t len,
                     off_t off __attribute__((unused)),
                     uint32_t flags) {
    (void)vn;
    struct tty_struct *tty = console_get_tty();
    if (!tty || !buf)
        return -EINVAL;
    if (len == 0)
        return 0;

    /* Pump UART before reading */
    console_try_fill_batch();
    return tty_read(tty, (uint8_t *)buf, len, flags);
}

ssize_t console_write(struct vnode *vn, const void *buf, size_t len,
                      off_t off __attribute__((unused)),
                      uint32_t flags) {
    (void)vn;
    struct tty_struct *tty = console_get_tty();
    if (!tty || !buf)
        return -EINVAL;
    return tty_write(tty, (const uint8_t *)buf, len, flags);
}

int console_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg) {
    (void)vn;
    struct tty_struct *tty = console_get_tty();
    if (!tty)
        return -EINVAL;
    return tty_ioctl(tty, cmd, arg);
}

int console_poll(struct vnode *vn, uint32_t events) {
    (void)vn;
    struct tty_struct *tty = console_get_tty();
    if (!tty)
        return POLLNVAL;
    console_try_fill_batch();
    return tty_poll(tty, events);
}