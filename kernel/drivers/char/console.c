/**
 * kernel/drivers/char/console.c - Console VFS shim
 */

#include <kairos/arch.h>
#include <kairos/console.h>
#include <kairos/poll.h>
#include <kairos/tty.h>
#include <kairos/tty_driver.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

static bool console_initialized;

void console_attach_vnode(struct vnode *vn) {
    struct tty_struct *tty = console_tty_get();
    if (tty)
        tty->vnode = vn;
    console_initialized = true;
}

static int console_try_fill_batch(void) {
    struct tty_struct *tty = console_tty_get();
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

ssize_t console_read(struct vnode *vn, void *buf, size_t len,
                     off_t off, uint32_t flags) {
    (void)vn; (void)off;
    struct tty_struct *tty = console_tty_get();
    if (!tty || !buf)
        return -EINVAL;
    if (len == 0)
        return 0;
    console_try_fill_batch();
    return tty_read(tty, (uint8_t *)buf, len, flags);
}

ssize_t console_write(struct vnode *vn, const void *buf, size_t len,
                      off_t off, uint32_t flags) {
    (void)vn; (void)off;
    struct tty_struct *tty = console_tty_get();
    if (!tty || !buf)
        return -EINVAL;
    return tty_write(tty, (const uint8_t *)buf, len, flags);
}

int console_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg) {
    (void)vn;
    struct tty_struct *tty = console_tty_get();
    if (!tty)
        return -EINVAL;
    return tty_ioctl(tty, cmd, arg);
}

int console_poll(struct vnode *vn, uint32_t events) {
    (void)vn;
    struct tty_struct *tty = console_tty_get();
    if (!tty)
        return POLLNVAL;
    console_try_fill_batch();
    return tty_poll(tty, events);
}
