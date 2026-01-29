/**
 * kernel/core/proc/fd.c - File Descriptor Management
 *
 * Manages file descriptor tables for processes.
 */

#include <kairos/process.h>
#include <kairos/syscall.h>
#include <kairos/spinlock.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

/**
 * fd_alloc - Allocate a file descriptor for a process
 */
int fd_alloc(struct process *p, struct file *file) {
    return fd_alloc_flags(p, file, 0);
}

int fd_alloc_flags(struct process *p, struct file *file, uint32_t fd_flags) {
    if (!p || !file) {
        return -EINVAL;
    }

    mutex_lock(&p->files_lock);
    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (!p->files[fd]) {
            p->files[fd] = file;
            p->fd_flags[fd] = fd_flags;
            mutex_unlock(&p->files_lock);
            return fd;
        }
    }
    mutex_unlock(&p->files_lock);
    return -EMFILE;
}

/**
 * fd_get - Get file structure from file descriptor
 */
struct file *fd_get(struct process *p, int fd) {
    if (!p || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC) {
        return NULL;
    }
    mutex_lock(&p->files_lock);
    struct file *file = p->files[fd];
    mutex_unlock(&p->files_lock);
    return file;
}

/**
 * fd_close - Close a file descriptor
 */
int fd_close(struct process *p, int fd) {
    struct file *file;

    if (!p || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC) {
        return -EBADF;
    }

    mutex_lock(&p->files_lock);
    if (!(file = p->files[fd])) {
        mutex_unlock(&p->files_lock);
        return -EBADF;
    }

    p->files[fd] = NULL;
    p->fd_flags[fd] = 0;
    mutex_unlock(&p->files_lock);
    return vfs_close(file);
}

static inline void file_get(struct file *file) {
    mutex_lock(&file->lock);
    file->refcount++;
    mutex_unlock(&file->lock);
}

/**
 * fd_dup - Duplicate a file descriptor
 */
int fd_dup(struct process *p, int oldfd) {
    struct file *file;
    mutex_lock(&p->files_lock);
    file = (oldfd >= 0 && oldfd < CONFIG_MAX_FILES_PER_PROC) ? p->files[oldfd] : NULL;
    if (!file) {
        mutex_unlock(&p->files_lock);
        return -EBADF;
    }

    file_get(file);
    mutex_unlock(&p->files_lock);
    return fd_alloc(p, file);
}

/**
 * fd_dup2 - Duplicate a file descriptor to a specific fd
 */
int fd_dup2(struct process *p, int oldfd, int newfd) {
    return fd_dup2_flags(p, oldfd, newfd, 0);
}

int fd_dup2_flags(struct process *p, int oldfd, int newfd, uint32_t fd_flags) {
    struct file *file;
    struct file *old_new;

    if (newfd < 0 || newfd >= CONFIG_MAX_FILES_PER_PROC) {
        return -EBADF;
    }

    mutex_lock(&p->files_lock);
    file = (oldfd >= 0 && oldfd < CONFIG_MAX_FILES_PER_PROC) ? p->files[oldfd] : NULL;
    if (!file) {
        mutex_unlock(&p->files_lock);
        return -EBADF;
    }

    if (oldfd == newfd) {
        mutex_unlock(&p->files_lock);
        return newfd;
    }

    old_new = p->files[newfd];
    p->files[newfd] = file;
    p->fd_flags[newfd] = fd_flags;
    file_get(file);
    mutex_unlock(&p->files_lock);

    if (old_new)
        vfs_close(old_new);

    return newfd;
}

int fd_dup_min_flags(struct process *p, int oldfd, int minfd,
                     uint32_t fd_flags) {
    struct file *file;
    if (!p)
        return -EINVAL;
    if (minfd < 0)
        return -EINVAL;
    if (minfd >= CONFIG_MAX_FILES_PER_PROC)
        return -EMFILE;

    mutex_lock(&p->files_lock);
    file = (oldfd >= 0 && oldfd < CONFIG_MAX_FILES_PER_PROC)
               ? p->files[oldfd]
               : NULL;
    if (!file) {
        mutex_unlock(&p->files_lock);
        return -EBADF;
    }

    for (int fd = minfd; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (!p->files[fd]) {
            p->files[fd] = file;
            p->fd_flags[fd] = fd_flags;
            file_get(file);
            mutex_unlock(&p->files_lock);
            return fd;
        }
    }
    mutex_unlock(&p->files_lock);
    return -EMFILE;
}

/**
 * fd_close_all - Close all file descriptors for a process
 */
void fd_close_all(struct process *p) {
    if (!p) {
        return;
    }

    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        fd_close(p, fd);
    }
}

void fd_close_cloexec(struct process *p) {
    if (!p) {
        return;
    }

    struct file *to_close[CONFIG_MAX_FILES_PER_PROC];
    int count = 0;

    mutex_lock(&p->files_lock);
    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (p->files[fd] && (p->fd_flags[fd] & FD_CLOEXEC)) {
            to_close[count++] = p->files[fd];
            p->files[fd] = NULL;
            p->fd_flags[fd] = 0;
        }
    }
    mutex_unlock(&p->files_lock);

    for (int i = 0; i < count; i++) {
        vfs_close(to_close[i]);
    }
}
