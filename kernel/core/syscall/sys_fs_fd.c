/**
 * kernel/core/syscall/sys_fs_fd.c - FD-related syscalls
 */

#include <kairos/config.h>
#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

int64_t sys_dup2(uint64_t oldfd, uint64_t newfd, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_dup2(proc_current(), (int)oldfd, (int)newfd);
}

int64_t sys_dup(uint64_t oldfd, uint64_t a1, uint64_t a2, uint64_t a3,
                uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)fd_dup(proc_current(), (int)oldfd);
}

int64_t sys_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (flags & ~O_CLOEXEC)
        return -EINVAL;
    if (oldfd == newfd)
        return -EINVAL;
    return (int64_t)fd_dup2(proc_current(), (int)oldfd, (int)newfd);
}

static int pipe_create_fds(uint64_t fd_array, uint32_t flags) {
    struct file *rf = NULL, *wf = NULL;
    int fds[2] = {-1, -1}, ret = 0;
    extern int pipe_create(struct file **read_pipe, struct file **write_pipe);

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

    if ((fds[0] = fd_alloc(proc_current(), rf)) < 0) {
        ret = -EMFILE;
        goto err;
    }
    if ((fds[1] = fd_alloc(proc_current(), wf)) < 0) {
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
    if (flags & ~allowed)
        return -EINVAL;
    return (int64_t)pipe_create_fds(fd_array, (uint32_t)flags);
}

int64_t sys_fcntl(uint64_t fd, uint64_t cmd, uint64_t arg, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct file *f = fd_get(proc_current(), (int)fd);
    if (!f)
        return -EBADF;

    switch ((int)cmd) {
    case F_GETFL: {
        mutex_lock(&f->lock);
        int flags = (int)f->flags;
        mutex_unlock(&f->lock);
        return flags;
    }
    case F_SETFL: {
        uint32_t setmask = O_NONBLOCK | O_APPEND;
        mutex_lock(&f->lock);
        f->flags = (f->flags & ~setmask) | ((uint32_t)arg & setmask);
        mutex_unlock(&f->lock);
        return 0;
    }
    default:
        return -EINVAL;
    }
}
