/**
 * kernel/core/syscall/sys_fs_io.c - IO-related syscalls
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

static int64_t sys_read_write(uint64_t fd, uint64_t buf, uint64_t count,
                              bool is_write) {
    struct file *f = fd_get(proc_current(), (int)fd);
    uint8_t kbuf[512];
    size_t done = 0;

    if (!f) {
        if (is_write && (fd == 1 || fd == 2)) {
            while (done < count) {
                size_t chunk = (count - done > sizeof(kbuf))
                                   ? sizeof(kbuf)
                                   : (size_t)(count - done);
                if (copy_from_user(kbuf, (const void *)(buf + done), chunk) < 0)
                    return done ? (int64_t)done : -EFAULT;
                for (size_t i = 0; i < chunk; i++)
                    arch_early_putchar((char)kbuf[i]);
                done += chunk;
            }
            return (int64_t)done;
        }
        return -EBADF;
    }
    int accmode = (int)(f->flags & O_ACCMODE);
    if (!is_write && accmode == O_WRONLY)
        return -EBADF;
    if (is_write && accmode == O_RDONLY)
        return -EBADF;

    while (done < count) {
        size_t chunk = (count - done > sizeof(kbuf)) ? sizeof(kbuf)
                                                     : (size_t)(count - done);
        if (is_write) {
            if (copy_from_user(kbuf, (const void *)(buf + done), chunk) < 0)
                return done ? (int64_t)done : -EFAULT;
            ssize_t n = vfs_write(f, kbuf, chunk);
            if (n < 0)
                return done ? (int64_t)done : (int64_t)n;
            if (n == 0)
                break;
            done += (size_t)n;
        } else {
            ssize_t n = vfs_read(f, kbuf, chunk);
            if (n < 0)
                return done ? (int64_t)done : (int64_t)n;
            if (n == 0)
                break;
            if (copy_to_user((void *)(buf + done), kbuf, (size_t)n) < 0)
                return done ? (int64_t)done : -EFAULT;
            done += (size_t)n;
        }
    }
    return (int64_t)done;
}

int64_t sys_read(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, false);
}

int64_t sys_write(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_read_write(a0, a1, a2, true);
}

int64_t sys_close(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_close(proc_current(), (int)fd);
}

int64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    if (f->vnode && f->vnode->type == VNODE_PIPE)
        return -ESPIPE;
    return (int64_t)vfs_seek(f, (off_t)offset, (int)whence);
}
