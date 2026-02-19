/**
 * kernel/core/proc/fd.c - File Descriptor Management
 *
 * Manages file descriptor tables for processes.
 */

#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/spinlock.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

/* fdtable helpers */

struct fdtable *fdtable_alloc(void) {
    struct fdtable *fdt = kzalloc(sizeof(*fdt));
    if (!fdt)
        return NULL;
    mutex_init(&fdt->lock, "fdtable");
    atomic_init(&fdt->refcount, 1);
    return fdt;
}

struct fdtable *fdtable_copy(struct fdtable *src) {
    if (!src)
        return fdtable_alloc();
    struct fdtable *fdt = kzalloc(sizeof(*fdt));
    if (!fdt)
        return NULL;
    mutex_init(&fdt->lock, "fdtable");
    atomic_init(&fdt->refcount, 1);
    mutex_lock(&src->lock);
    for (int i = 0; i < CONFIG_MAX_FILES_PER_PROC; i++) {
        struct file *f = src->files[i];
        if (f) {
            atomic_inc(&f->refcount);
            fdt->files[i] = f;
            fdt->fd_flags[i] = src->fd_flags[i];
        }
    }
    mutex_unlock(&src->lock);
    return fdt;
}

void fdtable_get(struct fdtable *fdt) {
    if (fdt)
        atomic_inc(&fdt->refcount);
}

void fdtable_put(struct fdtable *fdt) {
    if (!fdt)
        return;
    if (atomic_dec_return(&fdt->refcount) == 0) {
        for (int i = 0; i < CONFIG_MAX_FILES_PER_PROC; i++) {
            if (fdt->files[i]) {
                vfs_close(fdt->files[i]);
                fdt->files[i] = NULL;
            }
        }
        kfree(fdt);
    }
}

/* fd operations — all go through p->fdtable */

int fd_alloc(struct process *p, struct file *file) {
    return fd_alloc_flags(p, file, 0);
}

int fd_alloc_flags(struct process *p, struct file *file, uint32_t fd_flags) {
    if (!p || !file || !p->fdtable)
        return -EINVAL;

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (!fdt->files[fd]) {
            fdt->files[fd] = file;
            fdt->fd_flags[fd] = fd_flags;
            mutex_unlock(&fdt->lock);
            return fd;
        }
    }
    mutex_unlock(&fdt->lock);
    return -EMFILE;
}

struct file *fd_get(struct process *p, int fd) {
    if (!p || !p->fdtable || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC)
        return NULL;
    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    struct file *file = fdt->files[fd];
    if (file)
        atomic_inc(&file->refcount);
    mutex_unlock(&fdt->lock);
    return file;
}

int fd_close(struct process *p, int fd) {
    struct file *file;

    if (!p || !p->fdtable || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC)
        return -EBADF;

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    if (!(file = fdt->files[fd])) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }

    fdt->files[fd] = NULL;
    fdt->fd_flags[fd] = 0;
    mutex_unlock(&fdt->lock);
    return vfs_close(file);
}

int fd_dup(struct process *p, int oldfd) {
    struct file *file;
    if (!p || !p->fdtable)
        return -EINVAL;
    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    file = (oldfd >= 0 && oldfd < CONFIG_MAX_FILES_PER_PROC) ? fdt->files[oldfd] : NULL;
    if (!file) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }

    file_get(file);
    mutex_unlock(&fdt->lock);
    return fd_alloc(p, file);
}

int fd_dup2(struct process *p, int oldfd, int newfd) {
    return fd_dup2_flags(p, oldfd, newfd, 0);
}

int fd_dup2_flags(struct process *p, int oldfd, int newfd, uint32_t fd_flags) {
    struct file *file;
    struct file *old_new;

    if (!p || !p->fdtable)
        return -EINVAL;
    if (newfd < 0 || newfd >= CONFIG_MAX_FILES_PER_PROC)
        return -EBADF;

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    file = (oldfd >= 0 && oldfd < CONFIG_MAX_FILES_PER_PROC) ? fdt->files[oldfd] : NULL;
    if (!file) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }

    if (oldfd == newfd) {
        mutex_unlock(&fdt->lock);
        return newfd;
    }

    old_new = fdt->files[newfd];
    fdt->files[newfd] = file;
    fdt->fd_flags[newfd] = fd_flags;
    file_get(file);
    mutex_unlock(&fdt->lock);

    if (old_new)
        vfs_close(old_new);

    return newfd;
}

int fd_dup_min_flags(struct process *p, int oldfd, int minfd,
                     uint32_t fd_flags) {
    struct file *file;
    if (!p || !p->fdtable)
        return -EINVAL;
    if (minfd < 0)
        return -EINVAL;
    if (minfd >= CONFIG_MAX_FILES_PER_PROC)
        return -EMFILE;

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    file = (oldfd >= 0 && oldfd < CONFIG_MAX_FILES_PER_PROC)
               ? fdt->files[oldfd]
               : NULL;
    if (!file) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }

    for (int fd = minfd; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (!fdt->files[fd]) {
            fdt->files[fd] = file;
            fdt->fd_flags[fd] = fd_flags;
            file_get(file);
            mutex_unlock(&fdt->lock);
            return fd;
        }
    }
    mutex_unlock(&fdt->lock);
    return -EMFILE;
}

void fd_close_all(struct process *p) {
    if (!p)
        return;

    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        fd_close(p, fd);
    }
}

void fd_close_cloexec(struct process *p) {
    if (!p || !p->fdtable)
        return;

    struct file *to_close[CONFIG_MAX_FILES_PER_PROC];
    int count = 0;
    struct fdtable *fdt = p->fdtable;

    mutex_lock(&fdt->lock);
    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (fdt->files[fd] && (fdt->fd_flags[fd] & FD_CLOEXEC)) {
            to_close[count++] = fdt->files[fd];
            fdt->files[fd] = NULL;
            fdt->fd_flags[fd] = 0;
        }
    }
    mutex_unlock(&fdt->lock);

    for (int i = 0; i < count; i++) {
        vfs_close(to_close[i]);
    }
}
