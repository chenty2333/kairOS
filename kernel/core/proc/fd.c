/**
 * fd.c - File Descriptor Management
 *
 * Manages file descriptor tables for processes.
 */

#include <kairos/process.h>
#include <kairos/vfs.h>
#include <kairos/types.h>
#include <kairos/spinlock.h>

/**
 * fd_alloc - Allocate a file descriptor for a process
 *
 * @p: Process
 * @file: Open file structure
 *
 * Returns file descriptor number, or negative error code.
 */
int fd_alloc(struct process *p, struct file *file)
{
    if (!p || !file) {
        return -EINVAL;
    }

    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (!p->files[fd]) {
            p->files[fd] = file;
            return fd;
        }
    }

    return -EMFILE;  /* Too many open files */
}

/**
 * fd_get - Get file structure from file descriptor
 *
 * @p: Process
 * @fd: File descriptor
 *
 * Returns file structure, or NULL if invalid.
 */
struct file *fd_get(struct process *p, int fd)
{
    if (!p || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC) {
        return NULL;
    }

    return p->files[fd];
}

/**
 * fd_close - Close a file descriptor
 *
 * @p: Process
 * @fd: File descriptor to close
 *
 * Returns 0 on success, negative error on failure.
 */
int fd_close(struct process *p, int fd)
{
    struct file *file;

    if (!p || fd < 0 || fd >= CONFIG_MAX_FILES_PER_PROC) {
        return -EBADF;
    }

    file = p->files[fd];
    if (!file) {
        return -EBADF;
    }

    /* Close the file */
    p->files[fd] = NULL;
    return vfs_close(file);
}

/**
 * fd_dup - Duplicate a file descriptor
 *
 * @p: Process
 * @oldfd: File descriptor to duplicate
 *
 * Returns new file descriptor, or negative error code.
 */
int fd_dup(struct process *p, int oldfd)
{
    struct file *file;

    if (!p || oldfd < 0 || oldfd >= CONFIG_MAX_FILES_PER_PROC) {
        return -EBADF;
    }

    file = p->files[oldfd];
    if (!file) {
        return -EBADF;
    }

    /* Increment reference count */
    spin_lock(&file->lock);
    file->refcount++;
    spin_unlock(&file->lock);

    /* Allocate new fd */
    return fd_alloc(p, file);
}

/**
 * fd_dup2 - Duplicate a file descriptor to a specific fd
 *
 * @p: Process
 * @oldfd: File descriptor to duplicate
 * @newfd: Target file descriptor number
 *
 * Returns newfd on success, or negative error code.
 */
int fd_dup2(struct process *p, int oldfd, int newfd)
{
    struct file *file;

    if (!p || oldfd < 0 || oldfd >= CONFIG_MAX_FILES_PER_PROC ||
        newfd < 0 || newfd >= CONFIG_MAX_FILES_PER_PROC) {
        return -EBADF;
    }

    file = p->files[oldfd];
    if (!file) {
        return -EBADF;
    }

    /* If newfd is same as oldfd, do nothing */
    if (oldfd == newfd) {
        return newfd;
    }

    /* Close newfd if it's open */
    if (p->files[newfd]) {
        fd_close(p, newfd);
    }

    /* Increment reference count */
    spin_lock(&file->lock);
    file->refcount++;
    spin_unlock(&file->lock);

    /* Set newfd */
    p->files[newfd] = file;
    return newfd;
}

/**
 * fd_close_all - Close all file descriptors for a process
 *
 * @p: Process
 *
 * Called when process exits.
 */
void fd_close_all(struct process *p)
{
    if (!p) {
        return;
    }

    for (int fd = 0; fd < CONFIG_MAX_FILES_PER_PROC; fd++) {
        if (p->files[fd]) {
            vfs_close(p->files[fd]);
            p->files[fd] = NULL;
        }
    }
}
