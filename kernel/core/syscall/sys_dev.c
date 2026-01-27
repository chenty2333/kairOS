/**
 * kernel/core/syscall/sys_dev.c - Device-related syscalls
 */

#include <kairos/ioctl.h>
#include <kairos/process.h>
#include <kairos/sync.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

int64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;

    if (cmd == FIONBIO) {
        if (!arg)
            return -EFAULT;
        int on = 0;
        if (copy_from_user(&on, (void *)arg, sizeof(on)) < 0)
            return -EFAULT;
        mutex_lock(&f->lock);
        if (on)
            f->flags |= O_NONBLOCK;
        else
            f->flags &= ~O_NONBLOCK;
        mutex_unlock(&f->lock);
        return 0;
    }

    return vfs_ioctl(f, cmd, arg);
}
