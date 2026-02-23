/**
 * kernel/core/syscall/sys_fs_io.c - IO-related syscalls
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/poll.h>
#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#define RWF_HIPRI   0x00000001U
#define RWF_DSYNC   0x00000002U
#define RWF_SYNC    0x00000004U
#define RWF_NOWAIT  0x00000008U

/**
 * sys_read_write_file - perform IO on an already-resolved file pointer.
 * Caller holds a reference on @f; this function does NOT release it.
 */
static int64_t sys_read_write_file(struct file *f, uint64_t buf, uint64_t count,
                                   bool is_write) {
    uint8_t kbuf[512];
    size_t done = 0;

    int accmode = (int)(f->flags & O_ACCMODE);
    if (!is_write && accmode == O_WRONLY)
        return -EBADF;
    if (is_write && accmode == O_RDONLY)
        return -EBADF;

    if (!is_write && (f->flags & O_NONBLOCK)) {
        if (!(vfs_poll(f, POLLIN) & POLLIN))
            return -EAGAIN;
    }

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
            if ((size_t)n < chunk)
                break;
        }
    }
    return (int64_t)done;
}

static int64_t sys_read_write(uint64_t fd, uint64_t buf, uint64_t count,
                              bool is_write) {
    struct file *f = fd_get(proc_current(), (int)fd);

    if (!f) {
        /* Fallback: early console for stdout/stderr without file */
        if (is_write && (fd == 1 || fd == 2)) {
            uint8_t kbuf[512];
            size_t done = 0;
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

    int64_t ret = sys_read_write_file(f, buf, count, is_write);
    file_put(f);
    return ret;
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
    if (f->vnode && f->vnode->type == VNODE_PIPE) {
        file_put(f);
        return -ESPIPE;
    }
    int64_t ret = (int64_t)vfs_seek(f, (off_t)offset, (int)whence);
    file_put(f);
    return ret;
}

static int64_t sys_pread_write(uint64_t fd, uint64_t buf, uint64_t count,
                               uint64_t offset, bool is_write) {
    if ((int64_t)offset < 0)
        return -EINVAL;

    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    if (!f->vnode || f->vnode->type == VNODE_PIPE) {
        file_put(f);
        return -ESPIPE;
    }
    if (f->vnode->type == VNODE_DIR) {
        file_put(f);
        return -EISDIR;
    }

    int accmode = (int)(f->flags & O_ACCMODE);
    if (!is_write && accmode == O_WRONLY) {
        file_put(f);
        return -EBADF;
    }
    if (is_write && accmode == O_RDONLY) {
        file_put(f);
        return -EBADF;
    }

    if (!is_write && (f->flags & O_NONBLOCK)) {
        if (!(vfs_poll(f, POLLIN) & POLLIN)) {
            file_put(f);
            return -EAGAIN;
        }
    }

    if (!f->vnode->ops ||
        (!is_write && !f->vnode->ops->read) ||
        (is_write && !f->vnode->ops->write)) {
        file_put(f);
        return -EINVAL;
    }

    uint8_t kbuf[512];
    size_t done = 0;
    off_t off = (off_t)offset;
    while (done < count) {
        size_t chunk = (count - done > sizeof(kbuf)) ? sizeof(kbuf)
                                                     : (size_t)(count - done);
        if (is_write) {
            if (copy_from_user(kbuf, (const void *)(buf + done), chunk) < 0) {
                file_put(f);
                return done ? (int64_t)done : -EFAULT;
            }
            rwlock_write_lock(&f->vnode->lock);
            ssize_t n = f->vnode->ops->write(f->vnode, kbuf, chunk, off, f->flags);
            rwlock_write_unlock(&f->vnode->lock);
            if (n < 0) {
                file_put(f);
                return done ? (int64_t)done : (int64_t)n;
            }
            if (n == 0)
                break;
            off += n;
            done += (size_t)n;
            if ((size_t)n < chunk)
                break;
        } else {
            rwlock_read_lock(&f->vnode->lock);
            ssize_t n = f->vnode->ops->read(f->vnode, kbuf, chunk, off, f->flags);
            rwlock_read_unlock(&f->vnode->lock);
            if (n < 0) {
                file_put(f);
                return done ? (int64_t)done : (int64_t)n;
            }
            if (n == 0)
                break;
            if (copy_to_user((void *)(buf + done), kbuf, (size_t)n) < 0) {
                file_put(f);
                return done ? (int64_t)done : -EFAULT;
            }
            off += n;
            done += (size_t)n;
            if ((size_t)n < chunk)
                break;
        }
    }

    file_put(f);
    return (int64_t)done;
}

int64_t sys_pread64(uint64_t fd, uint64_t buf, uint64_t count,
                    uint64_t offset, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    return sys_pread_write(fd, buf, count, offset, false);
}

int64_t sys_pwrite64(uint64_t fd, uint64_t buf, uint64_t count,
                     uint64_t offset, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    return sys_pread_write(fd, buf, count, offset, true);
}

struct iovec {
    void *iov_base;
    size_t iov_len;
};

int64_t sys_writev(uint64_t fd, uint64_t iov_ptr, uint64_t iovcnt, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (iovcnt == 0)
        return 0;
    if (iovcnt > 1024)
        return -EINVAL;

    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f) {
        /* Fallback for stdout/stderr without file — delegate per-iov */
        if (fd != 1 && fd != 2)
            return -EBADF;
        size_t total = 0;
        for (size_t i = 0; i < iovcnt; i++) {
            struct iovec iov;
            if (copy_from_user(&iov,
                               (void *)(iov_ptr + i * sizeof(struct iovec)),
                               sizeof(iov)) < 0)
                return total ? (int64_t)total : -EFAULT;
            if (iov.iov_len == 0)
                continue;
            int64_t ret = sys_read_write(fd, (uint64_t)iov.iov_base,
                                         iov.iov_len, true);
            if (ret < 0)
                return total ? (int64_t)total : ret;
            total += (size_t)ret;
            if ((size_t)ret < iov.iov_len)
                break;
        }
        return (int64_t)total;
    }

    size_t total = 0;
    for (size_t i = 0; i < iovcnt; i++) {
        struct iovec iov;
        if (copy_from_user(&iov, (void *)(iov_ptr + i * sizeof(struct iovec)),
                           sizeof(iov)) < 0) {
            file_put(f);
            return total ? (int64_t)total : -EFAULT;
        }
        if (iov.iov_len == 0)
            continue;
        int64_t ret = sys_read_write_file(f, (uint64_t)iov.iov_base,
                                          iov.iov_len, true);
        if (ret < 0) {
            file_put(f);
            return total ? (int64_t)total : ret;
        }
        total += (size_t)ret;
        if ((size_t)ret < iov.iov_len)
            break;
    }
    file_put(f);
    return (int64_t)total;
}

int64_t sys_readv(uint64_t fd, uint64_t iov_ptr, uint64_t iovcnt, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (iovcnt == 0)
        return 0;
    if (iovcnt > 1024)
        return -EINVAL;

    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;

    size_t total = 0;
    for (size_t i = 0; i < iovcnt; i++) {
        struct iovec iov;
        if (copy_from_user(&iov, (void *)(iov_ptr + i * sizeof(struct iovec)),
                           sizeof(iov)) < 0) {
            file_put(f);
            return total ? (int64_t)total : -EFAULT;
        }
        if (iov.iov_len == 0)
            continue;
        int64_t ret = sys_read_write_file(f, (uint64_t)iov.iov_base,
                                          iov.iov_len, false);
        if (ret < 0) {
            file_put(f);
            return total ? (int64_t)total : ret;
        }
        total += (size_t)ret;
        if ((size_t)ret < iov.iov_len)
            break;
    }
    file_put(f);
    return (int64_t)total;
}

static int64_t sys_pread_writev(uint64_t fd, uint64_t iov_ptr, uint64_t iovcnt,
                                uint64_t offset, bool is_write) {
    if ((int64_t)offset < 0)
        return -EINVAL;
    if (iovcnt == 0)
        return 0;
    if (iovcnt > 1024)
        return -EINVAL;

    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    if (!f->vnode || f->vnode->type == VNODE_PIPE) {
        file_put(f);
        return -ESPIPE;
    }
    if (f->vnode->type == VNODE_DIR) {
        file_put(f);
        return -EISDIR;
    }

    int accmode = (int)(f->flags & O_ACCMODE);
    if (!is_write && accmode == O_WRONLY) {
        file_put(f);
        return -EBADF;
    }
    if (is_write && accmode == O_RDONLY) {
        file_put(f);
        return -EBADF;
    }

    if (!is_write && (f->flags & O_NONBLOCK)) {
        if (!(vfs_poll(f, POLLIN) & POLLIN)) {
            file_put(f);
            return -EAGAIN;
        }
    }

    if (!f->vnode->ops ||
        (!is_write && !f->vnode->ops->read) ||
        (is_write && !f->vnode->ops->write)) {
        file_put(f);
        return -EINVAL;
    }

    uint8_t kbuf[512];
    size_t total = 0;
    off_t off = (off_t)offset;
    for (size_t i = 0; i < iovcnt; i++) {
        struct iovec iov;
        if (copy_from_user(&iov, (void *)(iov_ptr + i * sizeof(struct iovec)),
                           sizeof(iov)) < 0) {
            file_put(f);
            return total ? (int64_t)total : -EFAULT;
        }
        if (iov.iov_len == 0)
            continue;
        size_t done = 0;
        while (done < iov.iov_len) {
            size_t chunk = (iov.iov_len - done > sizeof(kbuf))
                               ? sizeof(kbuf)
                               : (size_t)(iov.iov_len - done);
            if (is_write) {
                if (copy_from_user(kbuf,
                                   (const void *)((uint64_t)iov.iov_base + done),
                                   chunk) < 0) {
                    file_put(f);
                    return total ? (int64_t)total : -EFAULT;
                }
                rwlock_write_lock(&f->vnode->lock);
                ssize_t n = f->vnode->ops->write(f->vnode, kbuf, chunk, off, f->flags);
                rwlock_write_unlock(&f->vnode->lock);
                if (n < 0) {
                    file_put(f);
                    return total ? (int64_t)total : (int64_t)n;
                }
                if (n == 0)
                    break;
                off += n;
                done += (size_t)n;
                total += (size_t)n;
                if ((size_t)n < chunk)
                    break;
            } else {
                rwlock_read_lock(&f->vnode->lock);
                ssize_t n = f->vnode->ops->read(f->vnode, kbuf, chunk, off, f->flags);
                rwlock_read_unlock(&f->vnode->lock);
                if (n < 0) {
                    file_put(f);
                    return total ? (int64_t)total : (int64_t)n;
                }
                if (n == 0)
                    break;
                if (copy_to_user((void *)((uint64_t)iov.iov_base + done), kbuf,
                                 (size_t)n) < 0) {
                    file_put(f);
                    return total ? (int64_t)total : -EFAULT;
                }
                off += n;
                done += (size_t)n;
                total += (size_t)n;
                if ((size_t)n < chunk)
                    break;
            }
        }
    }
    file_put(f);
    return (int64_t)total;
}

static uint64_t sysfs_linux_split_off(uint64_t pos_l, uint64_t pos_h) {
    return (pos_l & 0xffffffffULL) | (pos_h << 32);
}

int64_t sys_preadv(uint64_t fd, uint64_t iov_ptr, uint64_t iovcnt,
                   uint64_t pos_l, uint64_t pos_h, uint64_t a5) {
    (void)a5;
    uint64_t offset = sysfs_linux_split_off(pos_l, pos_h);
    return sys_pread_writev(fd, iov_ptr, iovcnt, offset, false);
}

int64_t sys_pwritev(uint64_t fd, uint64_t iov_ptr, uint64_t iovcnt,
                    uint64_t pos_l, uint64_t pos_h, uint64_t a5) {
    (void)a5;
    uint64_t offset = sysfs_linux_split_off(pos_l, pos_h);
    return sys_pread_writev(fd, iov_ptr, iovcnt, offset, true);
}

int64_t sys_preadv2(uint64_t fd, uint64_t iov_ptr, uint64_t iovcnt,
                    uint64_t pos_l, uint64_t pos_h, uint64_t flags) {
    const uint64_t supported = RWF_HIPRI | RWF_NOWAIT;
    if (flags & ~supported)
        return -EOPNOTSUPP;
    uint64_t offset = sysfs_linux_split_off(pos_l, pos_h);
    if (offset == UINT64_MAX)
        return sys_readv(fd, iov_ptr, iovcnt, 0, 0, 0);
    return sys_pread_writev(fd, iov_ptr, iovcnt, offset, false);
}

int64_t sys_pwritev2(uint64_t fd, uint64_t iov_ptr, uint64_t iovcnt,
                     uint64_t pos_l, uint64_t pos_h, uint64_t flags) {
    const uint64_t supported = RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT;
    if (flags & ~supported)
        return -EOPNOTSUPP;
    uint64_t offset = sysfs_linux_split_off(pos_l, pos_h);
    if (offset == UINT64_MAX)
        return sys_writev(fd, iov_ptr, iovcnt, 0, 0, 0);
    return sys_pread_writev(fd, iov_ptr, iovcnt, offset, true);
}

int64_t sys_fsync(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    int64_t ret = vfs_fsync(f, 0);
    file_put(f);
    return ret;
}

int64_t sys_fdatasync(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;
    int64_t ret = vfs_fsync(f, 1);
    file_put(f);
    return ret;
}
