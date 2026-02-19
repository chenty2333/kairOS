/**
 * kernel/drivers/tty/tty_dev.c - /dev/tty device
 */

#include <kairos/poll.h>
#include <kairos/process.h>
#include <kairos/tty.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

extern int devfs_register_node(const char *path, struct file_ops *ops,
                               void *priv);

static struct tty_struct *dev_tty_resolve(void) {
    struct process *p = proc_current();
    return p ? p->ctty : NULL;
}

static ssize_t dev_tty_read(struct vnode *vn, void *buf, size_t len,
                             off_t off, uint32_t flags) {
    (void)vn; (void)off;
    struct tty_struct *tty = dev_tty_resolve();
    if (!tty)
        return -ENXIO;
    return tty_read(tty, (uint8_t *)buf, len, flags);
}

static ssize_t dev_tty_write(struct vnode *vn, const void *buf, size_t len,
                              off_t off, uint32_t flags) {
    (void)vn; (void)off;
    struct tty_struct *tty = dev_tty_resolve();
    if (!tty)
        return -ENXIO;
    return tty_write(tty, (const uint8_t *)buf, len, flags);
}

static int dev_tty_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg) {
    (void)vn;
    struct tty_struct *tty = dev_tty_resolve();
    if (!tty)
        return -ENXIO;
    return tty_ioctl(tty, cmd, arg);
}

static int dev_tty_poll(struct vnode *vn, uint32_t events) {
    (void)vn;
    struct tty_struct *tty = dev_tty_resolve();
    if (!tty)
        return POLLNVAL;
    return tty_poll(tty, events);
}

static int dev_tty_close(struct vnode *vn) {
    (void)vn;
    return 0;
}

static struct file_ops dev_tty_ops = {
    .read  = dev_tty_read,
    .write = dev_tty_write,
    .ioctl = dev_tty_ioctl,
    .poll  = dev_tty_poll,
    .close = dev_tty_close,
};

int dev_tty_init(void) {
    return devfs_register_node("/dev/tty", &dev_tty_ops, NULL);
}
