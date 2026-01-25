/**
 * kernel/core/proc/fd.c - File Descriptor Management
 *
 * Manages file descriptor tables for processes.
 */

#include <kairos/process.h>
#include <kairos/spinlock.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

/**
 * fd_alloc - Allocate a file descriptor for a process
 */
int fd_alloc(struct process *p, struct file *file) {
    if (!p || !file) {
        return -EINVAL;
    }

    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (!p->files[fd]) {
            p->files[fd] = file;
            return fd;
        }
    }

    return -EMFILE;
}

/**
 * fd_get - Get file structure from file descriptor
 */
struct file *fd_get(struct process *p, int fd) {
    if (!p || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC) {
        return NULL;
    }
    return p->files[fd];
}

/**
 * fd_close - Close a file descriptor
 */
int fd_close(struct process *p, int fd) {
    struct file *file;

    if (!p || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC) {
        return -EBADF;
    }

    if (!(file = p->files[fd])) {
        return -EBADF;
    }

    p->files[fd] = NULL;
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
    struct file *file = fd_get(p, oldfd);
    if (!file) {
        return -EBADF;
    }

    file_get(file);
    return fd_alloc(p, file);
}

/**
 * fd_dup2 - Duplicate a file descriptor to a specific fd
 */
int fd_dup2(struct process *p, int oldfd, int newfd) {
    struct file *file;

    if (newfd < 0 || newfd >= CONFIG_MAX_FILES_PER_PROC) {
        return -EBADF;
    }

    if (!(file = fd_get(p, oldfd))) {
        return -EBADF;
    }

    if (oldfd == newfd) {
        return newfd;
    }

    fd_close(p, newfd);
    file_get(file);
    p->files[newfd] = file;

    return newfd;
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