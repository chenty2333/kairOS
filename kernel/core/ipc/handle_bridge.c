/**
 * kernel/core/ipc/handle_bridge.c - Internal fd<->kobj bridge helpers
 */

#include <kairos/handle.h>
#include <kairos/handle_bridge.h>
#include <kairos/process.h>
#include <kairos/vfs.h>

uint32_t handle_bridge_fd_to_krights(uint32_t fd_rights) {
    uint32_t rights = 0;
    if (fd_rights & FD_RIGHT_READ)
        rights |= KRIGHT_READ;
    if (fd_rights & FD_RIGHT_WRITE)
        rights |= KRIGHT_WRITE;
    if (fd_rights & FD_RIGHT_IOCTL)
        rights |= KRIGHT_MANAGE;
    if (fd_rights & FD_RIGHT_DUP)
        rights |= (KRIGHT_DUPLICATE | KRIGHT_TRANSFER);
    return rights;
}

uint32_t handle_bridge_krights_to_fd(uint32_t krights) {
    uint32_t rights = 0;
    if (krights & KRIGHT_READ)
        rights |= FD_RIGHT_READ;
    if (krights & KRIGHT_WRITE)
        rights |= FD_RIGHT_WRITE;
    if (krights & KRIGHT_MANAGE)
        rights |= FD_RIGHT_IOCTL;
    if (krights & KRIGHT_DUPLICATE)
        rights |= FD_RIGHT_DUP;
    return rights;
}

int handle_bridge_kobj_from_fd(struct process *p, int fd, uint32_t rights_mask,
                               struct kobj **out_obj, uint32_t *out_rights) {
    if (out_obj)
        *out_obj = NULL;
    if (out_rights)
        *out_rights = 0;
    if (!p || !out_obj)
        return -EINVAL;

    uint32_t fd_rights = 0;
    int rc = fd_get_rights(p, fd, &fd_rights);
    if (rc < 0)
        return rc;

    struct file *file = NULL;
    rc = fd_get_required(p, fd, 0, &file);
    if (rc < 0)
        return rc;

    uint32_t allowed = handle_bridge_fd_to_krights(fd_rights);
    uint32_t desired = rights_mask ? (allowed & rights_mask) : allowed;
    if (desired == 0) {
        file_put(file);
        return -EACCES;
    }

    struct kobj *obj = NULL;
    rc = kfile_create(file, &obj);
    file_put(file);
    if (rc < 0)
        return rc;

    *out_obj = obj;
    if (out_rights)
        *out_rights = desired;
    return 0;
}

int handle_bridge_fd_from_kobj(struct process *p, struct kobj *obj,
                               uint32_t krights, uint32_t fd_flags,
                               int *out_fd) {
    if (out_fd)
        *out_fd = -1;
    if (!p || !obj || !out_fd)
        return -EINVAL;

    struct file *file = NULL;
    int rc = kfile_get_file(obj, &file);
    if (rc < 0)
        return rc;

    uint32_t fd_rights = handle_bridge_krights_to_fd(krights);
    if (fd_rights == 0) {
        file_put(file);
        return -EACCES;
    }

    int fd = fd_alloc_rights(p, file, fd_flags, fd_rights);
    file_put(file);
    if (fd < 0)
        return fd;

    *out_fd = fd;
    return 0;
}

int handle_bridge_dup_fd(struct process *src, int src_fd, struct process *dst,
                         uint32_t fd_flags, int *out_fd) {
    if (out_fd)
        *out_fd = -1;
    if (!src || !dst || !out_fd)
        return -EINVAL;

    struct file *src_file = NULL;
    int rc = fd_get_required(src, src_fd, FD_RIGHT_DUP, &src_file);
    if (rc < 0)
        return rc;

    uint32_t src_rights = 0;
    rc = fd_get_rights(src, src_fd, &src_rights);
    if (rc < 0) {
        file_put(src_file);
        return rc;
    }

    int new_fd = fd_alloc_rights(dst, src_file, fd_flags, src_rights);
    if (new_fd < 0) {
        file_put(src_file);
        return new_fd;
    }

    *out_fd = new_fd;
    return 0;
}
