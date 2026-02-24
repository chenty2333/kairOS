/**
 * kernel/core/syscall/sys_fs_fd.c - FD-related syscalls
 */

#include <kairos/config.h>
#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/time.h>
#include <kairos/uaccess.h>
#include <kairos/pipe.h>
#include <kairos/vfs.h>

/* Linux fcntl commands we need for busybox/ash */
#define F_DUPFD            0
#define F_GETFD            1
#define F_SETFD            2
#define F_GETFL            3
#define F_SETFL            4
#define F_DUPFD_CLOEXEC    1030
#define CLOSE_RANGE_UNSHARE (1U << 1)
#define CLOSE_RANGE_CLOEXEC (1U << 2)

static inline int sysfs_fd_int(uint64_t fd) {
    return (int32_t)(uint32_t)fd;
}

static int fdtable_unshare_current(void) {
    struct process *p = proc_current();
    if (!p || !p->fdtable)
        return -EINVAL;
    if (atomic_read(&p->fdtable->refcount) <= 1)
        return 0;

    struct fdtable *new_fdt = fdtable_copy(p->fdtable);
    if (!new_fdt)
        return -ENOMEM;

    struct fdtable *old_fdt = p->fdtable;
    p->fdtable = new_fdt;
    fdtable_put(old_fdt);
    return 0;
}

int64_t sys_dup2(uint64_t oldfd, uint64_t newfd, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    int koldfd = sysfs_fd_int(oldfd);
    int knewfd = sysfs_fd_int(newfd);
    return (int64_t)fd_dup2(proc_current(), koldfd, knewfd);
}

int64_t sys_dup(uint64_t oldfd, uint64_t a1, uint64_t a2, uint64_t a3,
                uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_dup(proc_current(), sysfs_fd_int(oldfd));
}

int64_t sys_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int koldfd = sysfs_fd_int(oldfd);
    int knewfd = sysfs_fd_int(newfd);
    uint32_t uflags = (uint32_t)flags;
    if (uflags & ~O_CLOEXEC)
        return -EINVAL;
    if (koldfd == knewfd)
        return -EINVAL;
    uint32_t fd_flags = (uflags & O_CLOEXEC) ? FD_CLOEXEC : 0;
    return (int64_t)fd_dup2_flags(proc_current(), koldfd, knewfd,
                                  fd_flags);
}

static int pipe_create_fds(uint64_t fd_array, uint32_t flags) {
    struct file *rf = NULL, *wf = NULL;
    int fds[2] = {-1, -1}, ret = 0;

    if ((ret = pipe_create(&rf, &wf)) < 0)
        return ret;

    if (flags & O_NONBLOCK) {
        mutex_lock(&rf->lock);
        rf->flags |= O_NONBLOCK;
        mutex_unlock(&rf->lock);
        mutex_lock(&wf->lock);
        wf->flags |= O_NONBLOCK;
        mutex_unlock(&wf->lock);
    }

    uint32_t fd_flags = (flags & O_CLOEXEC) ? FD_CLOEXEC : 0;
    if ((fds[0] = fd_alloc_flags(proc_current(), rf, fd_flags)) < 0) {
        ret = -EMFILE;
        goto err;
    }
    if ((fds[1] = fd_alloc_flags(proc_current(), wf, fd_flags)) < 0) {
        ret = -EMFILE;
        goto err;
    }
    if (copy_to_user((void *)fd_array, fds, sizeof(fds)) < 0) {
        ret = -EFAULT;
        goto err;
    }
    return 0;
err:
    if (fds[0] >= 0) {
        fd_close(proc_current(), fds[0]);
    } else if (rf) {
        vfs_close(rf);
    }
    if (fds[1] >= 0) {
        fd_close(proc_current(), fds[1]);
    } else if (wf) {
        vfs_close(wf);
    }
    return ret;
}

int64_t sys_pipe(uint64_t fd_array, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)pipe_create_fds(fd_array, 0);
}

int64_t sys_pipe2(uint64_t fd_array, uint64_t flags, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    uint32_t allowed = O_NONBLOCK | O_CLOEXEC;
    uint32_t uflags = (uint32_t)flags;
    if (uflags & ~allowed)
        return -EINVAL;
    return (int64_t)pipe_create_fds(fd_array, uflags);
}

int64_t sys_close_range(uint64_t first, uint64_t last, uint64_t flags,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    uint32_t uflags = (uint32_t)flags;
    if (uflags & ~(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC))
        return -EINVAL;

    uint32_t from = (uint32_t)first;
    uint32_t to = (uint32_t)last;
    if (from > to)
        return -EINVAL;

    if (uflags & CLOSE_RANGE_UNSHARE) {
        int ret = fdtable_unshare_current();
        if (ret < 0)
            return ret;
    }

    struct process *p = proc_current();
    if (!p || !p->fdtable)
        return -EINVAL;
    if (from >= CONFIG_MAX_FILES_PER_PROC)
        return 0;

    if (to >= CONFIG_MAX_FILES_PER_PROC)
        to = CONFIG_MAX_FILES_PER_PROC - 1;

    struct fdtable *fdt = p->fdtable;
    if (uflags & CLOSE_RANGE_CLOEXEC) {
        mutex_lock(&fdt->lock);
        for (uint32_t fd = from; fd <= to; fd++) {
            if (fdt->files[fd])
                fdt->fd_flags[fd] |= FD_CLOEXEC;
        }
        mutex_unlock(&fdt->lock);
        return 0;
    }

    struct file *to_close[CONFIG_MAX_FILES_PER_PROC];
    int close_count = 0;
    mutex_lock(&fdt->lock);
    for (uint32_t fd = from; fd <= to; fd++) {
        struct file *f = fdt->files[fd];
        if (!f)
            continue;
        fdt->files[fd] = NULL;
        fdt->fd_flags[fd] = 0;
        to_close[close_count++] = f;
    }
    mutex_unlock(&fdt->lock);

    for (int i = 0; i < close_count; i++)
        vfs_close(to_close[i]);
    return 0;
}

int64_t sys_fcntl(uint64_t fd, uint64_t cmd, uint64_t arg, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    int kfd = sysfs_fd_int(fd);
    uint32_t ucmd = (uint32_t)cmd;
    uint32_t uarg = (uint32_t)arg;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    struct file *f = fd_get(p, kfd);
    if (!f)
        return -EBADF;

    switch ((int32_t)ucmd) {
    case F_DUPFD: {
        int64_t ret = (int64_t)fd_dup_min_flags(p, kfd, (int32_t)uarg, 0);
        file_put(f);
        return ret;
    }
    case F_DUPFD_CLOEXEC: {
        int64_t ret =
            (int64_t)fd_dup_min_flags(p, kfd, (int32_t)uarg, FD_CLOEXEC);
        file_put(f);
        return ret;
    }
    case F_GETFD: {
        int flags = 0;
        struct fdtable *fdt = p->fdtable;
        if (!fdt) {
            file_put(f);
            return -EBADF;
        }
        mutex_lock(&fdt->lock);
        if (kfd < 0 || kfd >= CONFIG_MAX_FILES_PER_PROC || !fdt->files[kfd]) {
            mutex_unlock(&fdt->lock);
            file_put(f);
            return -EBADF;
        }
        if (fdt->fd_flags[kfd] & FD_CLOEXEC)
            flags |= FD_CLOEXEC;
        mutex_unlock(&fdt->lock);
        file_put(f);
        return flags;
    }
    case F_SETFD: {
        if (uarg & ~FD_CLOEXEC) {
            file_put(f);
            return -EINVAL;
        }
        struct fdtable *fdt = p->fdtable;
        if (!fdt) {
            file_put(f);
            return -EBADF;
        }
        mutex_lock(&fdt->lock);
        if (kfd < 0 || kfd >= CONFIG_MAX_FILES_PER_PROC || !fdt->files[kfd]) {
            mutex_unlock(&fdt->lock);
            file_put(f);
            return -EBADF;
        }
        fdt->fd_flags[kfd] = uarg & FD_CLOEXEC;
        mutex_unlock(&fdt->lock);
        file_put(f);
        return 0;
    }
    case F_GETFL: {
        mutex_lock(&f->lock);
        int flags = (int)f->flags;
        mutex_unlock(&f->lock);
        file_put(f);
        return flags;
    }
    case F_SETFL: {
        uint32_t setmask = O_NONBLOCK | O_APPEND;
        mutex_lock(&f->lock);
        f->flags = (f->flags & ~setmask) | (uarg & setmask);
        mutex_unlock(&f->lock);
        file_put(f);
        return 0;
    }
    default:
        file_put(f);
        return -EINVAL;
    }
}

int64_t sys_ftruncate(uint64_t fd, uint64_t length, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if ((int64_t)length < 0)
        return -EINVAL;
    struct file *f = fd_get(proc_current(), sysfs_fd_int(fd));
    if (!f || !f->vnode) {
        if (f) file_put(f);
        return -EBADF;
    }
    if (f->vnode->type == VNODE_DIR) {
        file_put(f);
        return -EISDIR;
    }
    if (!f->vnode->ops || !f->vnode->ops->truncate) {
        file_put(f);
        return -EINVAL;
    }
    rwlock_write_lock(&f->vnode->lock);
    int ret = f->vnode->ops->truncate(f->vnode, (off_t)length);
    rwlock_write_unlock(&f->vnode->lock);
    file_put(f);
    return ret;
}

int64_t sys_fchmod(uint64_t fd, uint64_t mode, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), sysfs_fd_int(fd));
    if (!f || !f->vnode) {
        if (f)
            file_put(f);
        return -EBADF;
    }
    rwlock_write_lock(&f->vnode->lock);
    f->vnode->mode = (f->vnode->mode & S_IFMT) | ((mode_t)mode & 07777);
    f->vnode->ctime = time_now_sec();
    if (f->vnode->mount && f->vnode->mount->ops &&
        f->vnode->mount->ops->chmod) {
        f->vnode->mount->ops->chmod(f->vnode, f->vnode->mode);
    }
    rwlock_write_unlock(&f->vnode->lock);
    file_put(f);
    return 0;
}

int64_t sys_fchown(uint64_t fd, uint64_t owner, uint64_t group, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    uint32_t uowner = (uint32_t)owner;
    uint32_t ugroup = (uint32_t)group;
    struct file *f = fd_get(proc_current(), sysfs_fd_int(fd));
    if (!f || !f->vnode) {
        if (f) file_put(f);
        return -EBADF;
    }
    rwlock_write_lock(&f->vnode->lock);
    if (uowner != UINT32_MAX)
        f->vnode->uid = (uid_t)uowner;
    if (ugroup != UINT32_MAX)
        f->vnode->gid = (gid_t)ugroup;
    f->vnode->ctime = time_now_sec();
    if (f->vnode->mount && f->vnode->mount->ops &&
        f->vnode->mount->ops->chown) {
        f->vnode->mount->ops->chown(f->vnode, f->vnode->uid, f->vnode->gid);
    }
    rwlock_write_unlock(&f->vnode->lock);
    file_put(f);
    return 0;
}
