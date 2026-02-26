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

static uint32_t fd_rights_default_from_file(const struct file *file) {
    uint32_t rights = FD_RIGHT_IOCTL | FD_RIGHT_DUP;
    if (!file)
        return rights;

    uint32_t accmode = file->flags & O_ACCMODE;
    if (accmode != O_WRONLY)
        rights |= FD_RIGHT_READ;
    if (accmode != O_RDONLY)
        rights |= FD_RIGHT_WRITE;
    return rights;
}

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
            fdt->fd_rights[i] = src->fd_rights[i];
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
                fdt->fd_rights[i] = 0;
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
    return fd_alloc_rights(p, file, fd_flags, 0);
}

int fd_alloc_rights(struct process *p, struct file *file, uint32_t fd_flags,
                    uint32_t fd_rights) {
    if (!p || !file || !p->fdtable)
        return -EINVAL;

    uint32_t rights = fd_rights;
    if (rights == 0) {
        rights = fd_rights_default_from_file(file);
    } else {
        if (rights & ~FD_RIGHTS_ALL)
            return -EINVAL;
        rights &= fd_rights_default_from_file(file);
        if (rights == 0)
            return -EACCES;
    }

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (!fdt->files[fd]) {
            fdt->files[fd] = file;
            fdt->fd_flags[fd] = fd_flags;
            fdt->fd_rights[fd] = rights;
            mutex_unlock(&fdt->lock);
            return fd;
        }
    }
    mutex_unlock(&fdt->lock);
    return -EMFILE;
}

struct file *fd_get(struct process *p, int fd) {
    struct file *file = NULL;
    if (fd_get_required(p, fd, 0, &file) < 0)
        return NULL;
    return file;
}

int fd_get_required(struct process *p, int fd, uint32_t required_rights,
                    struct file **out_file) {
    if (out_file)
        *out_file = NULL;
    if (!p || !p->fdtable || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC)
        return -EBADF;

    if (required_rights & ~FD_RIGHTS_ALL)
        return -EINVAL;

    if (!out_file)
        return -EINVAL;

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    struct file *file = fdt->files[fd];
    if (!file) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }
    uint32_t rights = fdt->fd_rights[fd];
    if ((rights & required_rights) != required_rights) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }
    atomic_inc(&file->refcount);
    mutex_unlock(&fdt->lock);
    *out_file = file;
    return 0;
}

int fd_get_rights(struct process *p, int fd, uint32_t *out_rights) {
    if (out_rights)
        *out_rights = 0;
    if (!p || !p->fdtable || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC)
        return -EBADF;
    if (!out_rights)
        return -EINVAL;

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    if (!fdt->files[fd]) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }
    *out_rights = fdt->fd_rights[fd];
    mutex_unlock(&fdt->lock);
    return 0;
}

int fd_limit_rights(struct process *p, int fd, uint32_t rights_mask,
                    uint32_t *out_rights) {
    if (out_rights)
        *out_rights = 0;
    if (!p || !p->fdtable || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC)
        return -EBADF;
    if (rights_mask & ~FD_RIGHTS_ALL)
        return -EINVAL;

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    if (!fdt->files[fd]) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }
    uint32_t new_rights = fdt->fd_rights[fd] & rights_mask;
    fdt->fd_rights[fd] = new_rights;
    mutex_unlock(&fdt->lock);
    if (out_rights)
        *out_rights = new_rights;
    return 0;
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
    fdt->fd_rights[fd] = 0;
    mutex_unlock(&fdt->lock);
    return vfs_close(file);
}

int fd_dup(struct process *p, int oldfd) {
    if (!p || !p->fdtable)
        return -EINVAL;
    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    struct file *file =
        (oldfd >= 0 && oldfd < CONFIG_MAX_FILES_PER_PROC) ? fdt->files[oldfd] : NULL;
    if (!file) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }
    uint32_t rights = fdt->fd_rights[oldfd];
    if ((rights & FD_RIGHT_DUP) == 0) {
        mutex_unlock(&fdt->lock);
        return -EPERM;
    }

    file_get(file);
    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (!fdt->files[fd]) {
            fdt->files[fd] = file;
            fdt->fd_flags[fd] = 0;
            fdt->fd_rights[fd] = rights;
            mutex_unlock(&fdt->lock);
            return fd;
        }
    }
    mutex_unlock(&fdt->lock);
    file_put(file);
    return -EMFILE;
}

int fd_dup2(struct process *p, int oldfd, int newfd) {
    return fd_dup2_flags(p, oldfd, newfd, 0);
}

int fd_dup2_flags(struct process *p, int oldfd, int newfd, uint32_t fd_flags) {
    if (!p || !p->fdtable)
        return -EINVAL;
    if (newfd < 0 || newfd >= CONFIG_MAX_FILES_PER_PROC)
        return -EBADF;

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    struct file *file =
        (oldfd >= 0 && oldfd < CONFIG_MAX_FILES_PER_PROC) ? fdt->files[oldfd] : NULL;
    if (!file) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }

    if (oldfd == newfd) {
        mutex_unlock(&fdt->lock);
        return newfd;
    }

    uint32_t rights = fdt->fd_rights[oldfd];
    if ((rights & FD_RIGHT_DUP) == 0) {
        mutex_unlock(&fdt->lock);
        return -EPERM;
    }

    struct file *old_new = fdt->files[newfd];
    fdt->files[newfd] = file;
    fdt->fd_flags[newfd] = fd_flags;
    fdt->fd_rights[newfd] = rights;
    file_get(file);
    mutex_unlock(&fdt->lock);

    if (old_new)
        vfs_close(old_new);

    return newfd;
}

int fd_dup_min_flags(struct process *p, int oldfd, int minfd,
                     uint32_t fd_flags) {
    if (!p || !p->fdtable)
        return -EINVAL;
    if (minfd < 0)
        return -EINVAL;
    if (minfd >= CONFIG_MAX_FILES_PER_PROC)
        return -EMFILE;

    struct fdtable *fdt = p->fdtable;
    mutex_lock(&fdt->lock);
    struct file *file = (oldfd >= 0 && oldfd < CONFIG_MAX_FILES_PER_PROC)
               ? fdt->files[oldfd]
               : NULL;
    if (!file) {
        mutex_unlock(&fdt->lock);
        return -EBADF;
    }
    uint32_t rights = fdt->fd_rights[oldfd];
    if ((rights & FD_RIGHT_DUP) == 0) {
        mutex_unlock(&fdt->lock);
        return -EPERM;
    }

    for (int fd = minfd; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (!fdt->files[fd]) {
            fdt->files[fd] = file;
            fdt->fd_flags[fd] = fd_flags;
            fdt->fd_rights[fd] = rights;
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
            fdt->fd_rights[fd] = 0;
        }
    }
    mutex_unlock(&fdt->lock);

    for (int i = 0; i < count; i++) {
        vfs_close(to_close[i]);
    }
}
