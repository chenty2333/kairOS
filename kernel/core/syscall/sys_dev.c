/**
 * kernel/core/syscall/sys_dev.c - Device-related syscalls
 */

#include <kairos/ioctl.h>
#include <kairos/process.h>
#include <kairos/sync.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

/* Network ioctl handler (kernel/net/net_ioctl.c) */
int net_ioctl(struct file *f, uint64_t cmd, uint64_t arg);

int64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;

    if (cmd == FIONBIO) {
        if (!arg) {
            file_put(f);
            return -EFAULT;
        }
        int on = 0;
        if (copy_from_user(&on, (void *)arg, sizeof(on)) < 0) {
            file_put(f);
            return -EFAULT;
        }
        mutex_lock(&f->lock);
        if (on)
            f->flags |= O_NONBLOCK;
        else
            f->flags &= ~O_NONBLOCK;
        mutex_unlock(&f->lock);
        file_put(f);
        return 0;
    }

    /* Route network ioctls (0x8900-0x89FF) to net_ioctl */
    if (cmd >= 0x8900 && cmd <= 0x89FF) {
        int64_t ret = net_ioctl(f, cmd, arg);
        file_put(f);
        return ret;
    }

    int64_t ret = vfs_ioctl(f, cmd, arg);
    file_put(f);
    return ret;
}
