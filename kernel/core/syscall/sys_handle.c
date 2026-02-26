/**
 * kernel/core/syscall/sys_handle.c - Kairos capability handle and channel/port syscalls
 */

#include <kairos/handle.h>
#include <kairos/handle_bridge.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#define PORTFD_MAGIC 0x706f7266U
#define CHANFD_MAGIC 0x63686664U

struct portfd_ctx {
    uint32_t magic;
    struct kobj *port_obj;
    struct vnode *vnode;
};

struct channelfd_ctx {
    uint32_t magic;
    struct kobj *channel_obj;
    struct vnode *vnode;
    uint32_t rights;
};

static inline int32_t syshandle_abi_i32(uint64_t raw) {
    return (int32_t)(uint32_t)raw;
}

static uint32_t channelfd_krights_from_fd(uint32_t fd_rights) {
    uint32_t rights = 0;
    if (fd_rights & FD_RIGHT_READ)
        rights |= KRIGHT_READ;
    if (fd_rights & FD_RIGHT_WRITE)
        rights |= KRIGHT_WRITE;
    if (fd_rights & FD_RIGHT_DUP)
        rights |= (KRIGHT_DUPLICATE | KRIGHT_TRANSFER);
    return rights;
}

static uint32_t portfd_krights_from_fd(uint32_t fd_rights) {
    uint32_t rights = 0;
    if (fd_rights & FD_RIGHT_READ)
        rights |= KRIGHT_WAIT;
    if (fd_rights & FD_RIGHT_IOCTL)
        rights |= KRIGHT_MANAGE;
    if (fd_rights & FD_RIGHT_DUP)
        rights |= KRIGHT_DUPLICATE;
    return rights;
}

static void syshandle_restore_taken(struct process *p, const int32_t *user_handles,
                                    struct khandle_transfer *transfers,
                                    size_t count) {
    if (!p || !user_handles || !transfers)
        return;

    for (size_t i = 0; i < count; i++) {
        if (!transfers[i].obj)
            continue;
        int rc =
            khandle_restore(p, user_handles[i], transfers[i].obj, transfers[i].rights);
        if (rc < 0)
            khandle_transfer_drop(transfers[i].obj);
        transfers[i].obj = NULL;
    }
}

static void syshandle_close_installed(struct process *p, const int32_t *handles,
                                      size_t count) {
    if (!p || !handles)
        return;
    for (size_t i = 0; i < count; i++) {
        if (handles[i] >= 0)
            (void)khandle_close(p, handles[i]);
    }
}

static int portfd_close(struct vnode *vn) {
    if (!vn)
        return 0;

    struct portfd_ctx *ctx = (struct portfd_ctx *)vn->fs_data;
    if (ctx && ctx->magic == PORTFD_MAGIC) {
        if (ctx->port_obj && ctx->vnode)
            (void)kobj_poll_detach_vnode(ctx->port_obj, ctx->vnode);
        if (ctx->port_obj)
            kobj_put(ctx->port_obj);
        ctx->magic = 0;
        kfree(ctx);
    }

    kfree(vn);
    return 0;
}

static int portfd_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;

    struct portfd_ctx *ctx = (struct portfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != PORTFD_MAGIC || !ctx->port_obj)
        return POLLNVAL;

    uint32_t revents = 0;
    int rc = kobj_poll_revents(ctx->port_obj, events, &revents);
    if (rc < 0)
        return POLLERR;
    return (int)revents;
}

static ssize_t portfd_fread(struct file *file, void *buf, size_t len) {
    if (!file || !file->vnode || !buf)
        return -EINVAL;
    if (len < sizeof(struct kairos_port_packet_user))
        return -EINVAL;

    struct portfd_ctx *ctx = (struct portfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != PORTFD_MAGIC || !ctx->port_obj)
        return -EINVAL;

    struct kairos_port_packet_user pkt = {0};
    uint32_t opts = (file->flags & O_NONBLOCK) ? KPORT_WAIT_NONBLOCK : 0;
    int rc = kobj_wait(ctx->port_obj, &pkt, UINT64_MAX, opts);
    if (rc < 0)
        return rc;

    memcpy(buf, &pkt, sizeof(pkt));
    return (ssize_t)sizeof(pkt);
}

static int portfd_to_kobj(struct file *file, uint32_t fd_rights,
                          struct kobj **out_obj, uint32_t *out_rights) {
    if (out_obj)
        *out_obj = NULL;
    if (out_rights)
        *out_rights = 0;
    if (!file || !file->vnode || !out_obj)
        return -EINVAL;

    struct portfd_ctx *ctx = (struct portfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != PORTFD_MAGIC || !ctx->port_obj)
        return -EINVAL;

    uint32_t rights = portfd_krights_from_fd(fd_rights);
    if (rights == 0)
        return -EACCES;

    kobj_get(ctx->port_obj);
    *out_obj = ctx->port_obj;
    if (out_rights)
        *out_rights = rights;
    return 0;
}

static struct file_ops portfd_file_ops = {
    .close = portfd_close,
    .fread = portfd_fread,
    .poll = portfd_poll,
    .to_kobj = portfd_to_kobj,
};

static int portfd_create_file(struct kobj *obj, uint32_t rights,
                              uint32_t open_flags, struct file **out) {
    if (!obj || !out)
        return -EINVAL;
    *out = NULL;

    if (obj->type != KOBJ_TYPE_PORT)
        return -ENOTSUP;
    if ((rights & KRIGHT_WAIT) == 0)
        return -EACCES;

    struct portfd_ctx *ctx = kzalloc(sizeof(*ctx));
    struct vnode *vn = kzalloc(sizeof(*vn));
    struct file *file = vfs_file_alloc();
    if (!ctx || !vn || !file) {
        kfree(ctx);
        kfree(vn);
        if (file)
            vfs_file_free(file);
        return -ENOMEM;
    }

    ctx->magic = PORTFD_MAGIC;
    ctx->port_obj = obj;
    ctx->vnode = vn;
    kobj_get(obj);

    vn->type = VNODE_FILE;
    vn->mode = S_IFREG | 0;
    vn->ops = &portfd_file_ops;
    vn->fs_data = ctx;
    vn->size = 0;
    atomic_init(&vn->refcount, 1);
    rwlock_init(&vn->lock, "portfd_vnode");
    poll_wait_head_init(&vn->pollers);

    file->vnode = vn;
    file->dentry = NULL;
    file->offset = 0;
    file->flags = O_RDONLY | (open_flags & O_NONBLOCK);
    file->path[0] = '\0';

    int rc = kobj_poll_attach_vnode(obj, vn);
    if (rc < 0) {
        kobj_put(obj);
        vfs_file_free(file);
        kfree(vn);
        kfree(ctx);
        return rc;
    }

    *out = file;
    return 0;
}

static int channelfd_close(struct vnode *vn) {
    if (!vn)
        return 0;

    struct channelfd_ctx *ctx = (struct channelfd_ctx *)vn->fs_data;
    if (ctx && ctx->magic == CHANFD_MAGIC) {
        if (ctx->channel_obj && ctx->vnode)
            (void)kobj_poll_detach_vnode(ctx->channel_obj, ctx->vnode);
        if (ctx->channel_obj)
            kobj_put(ctx->channel_obj);
        ctx->magic = 0;
        kfree(ctx);
    }

    kfree(vn);
    return 0;
}

static int channelfd_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;

    struct channelfd_ctx *ctx = (struct channelfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != CHANFD_MAGIC || !ctx->channel_obj)
        return POLLNVAL;

    uint32_t revents = 0;
    int rc = kobj_poll_revents(ctx->channel_obj, events, &revents);
    if (rc < 0)
        return POLLERR;
    return (int)revents;
}

static ssize_t channelfd_fread(struct file *file, void *buf, size_t len) {
    if (!file || !file->vnode || !buf)
        return -EINVAL;
    if (len == 0)
        return 0;

    struct channelfd_ctx *ctx = (struct channelfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != CHANFD_MAGIC || !ctx->channel_obj)
        return -EINVAL;
    if ((ctx->rights & KRIGHT_READ) == 0)
        return -EBADF;

    size_t got_bytes = 0;
    size_t got_handles = 0;
    bool handles_truncated = false;
    struct khandle_transfer dropped[KCHANNEL_MAX_MSG_HANDLES] = {0};
    uint32_t opts = (file->flags & O_NONBLOCK) ? KCHANNEL_OPT_NONBLOCK : 0;
    int rc = kchannel_recv(ctx->channel_obj, buf, len, &got_bytes, dropped,
                           KCHANNEL_MAX_MSG_HANDLES, &got_handles,
                           &handles_truncated, opts);
    if (rc < 0)
        return rc;
    for (size_t i = 0; i < got_handles; i++) {
        if (dropped[i].obj) {
            khandle_transfer_drop(dropped[i].obj);
            dropped[i].obj = NULL;
        }
    }
    return (ssize_t)got_bytes;
}

static ssize_t channelfd_fwrite(struct file *file, const void *buf, size_t len) {
    if (!file || !file->vnode || (!buf && len > 0))
        return -EINVAL;
    if (len > KCHANNEL_MAX_MSG_BYTES)
        return -EMSGSIZE;

    struct channelfd_ctx *ctx = (struct channelfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != CHANFD_MAGIC || !ctx->channel_obj)
        return -EINVAL;
    if ((ctx->rights & KRIGHT_WRITE) == 0)
        return -EBADF;

    uint32_t opts = (file->flags & O_NONBLOCK) ? KCHANNEL_OPT_NONBLOCK : 0;
    int rc = kchannel_send(ctx->channel_obj, buf, len, NULL, 0, opts);
    if (rc < 0)
        return rc;
    return (ssize_t)len;
}

static int channelfd_to_kobj(struct file *file, uint32_t fd_rights,
                             struct kobj **out_obj, uint32_t *out_rights) {
    if (out_obj)
        *out_obj = NULL;
    if (out_rights)
        *out_rights = 0;
    if (!file || !file->vnode || !out_obj)
        return -EINVAL;

    struct channelfd_ctx *ctx = (struct channelfd_ctx *)file->vnode->fs_data;
    if (!ctx || ctx->magic != CHANFD_MAGIC || !ctx->channel_obj)
        return -EINVAL;

    uint32_t rights = channelfd_krights_from_fd(fd_rights);
    if (rights == 0)
        return -EACCES;

    kobj_get(ctx->channel_obj);
    *out_obj = ctx->channel_obj;
    if (out_rights)
        *out_rights = rights;
    return 0;
}

static struct file_ops channelfd_file_ops = {
    .close = channelfd_close,
    .fread = channelfd_fread,
    .fwrite = channelfd_fwrite,
    .poll = channelfd_poll,
    .to_kobj = channelfd_to_kobj,
};

static int channelfd_create_file(struct kobj *obj, uint32_t rights,
                                 uint32_t open_flags, struct file **out) {
    if (!obj || !out)
        return -EINVAL;
    *out = NULL;

    if (obj->type != KOBJ_TYPE_CHANNEL)
        return -ENOTSUP;

    bool can_read = (rights & KRIGHT_READ) != 0;
    bool can_write = (rights & KRIGHT_WRITE) != 0;
    if (!can_read && !can_write)
        return -EACCES;

    struct channelfd_ctx *ctx = kzalloc(sizeof(*ctx));
    struct vnode *vn = kzalloc(sizeof(*vn));
    struct file *file = vfs_file_alloc();
    if (!ctx || !vn || !file) {
        kfree(ctx);
        kfree(vn);
        if (file)
            vfs_file_free(file);
        return -ENOMEM;
    }

    ctx->magic = CHANFD_MAGIC;
    ctx->channel_obj = obj;
    ctx->vnode = vn;
    ctx->rights = rights;
    kobj_get(obj);

    vn->type = VNODE_FILE;
    vn->mode = S_IFREG | 0;
    vn->ops = &channelfd_file_ops;
    vn->fs_data = ctx;
    vn->size = 0;
    atomic_init(&vn->refcount, 1);
    rwlock_init(&vn->lock, "channelfd_vnode");
    poll_wait_head_init(&vn->pollers);

    file->vnode = vn;
    file->dentry = NULL;
    file->offset = 0;
    if (can_read && can_write)
        file->flags = O_RDWR;
    else if (can_write)
        file->flags = O_WRONLY;
    else
        file->flags = O_RDONLY;
    file->flags |= (open_flags & O_NONBLOCK);
    file->path[0] = '\0';

    int rc = kobj_poll_attach_vnode(obj, vn);
    if (rc < 0) {
        kobj_put(obj);
        vfs_file_free(file);
        kfree(vn);
        kfree(ctx);
        return rc;
    }

    *out = file;
    return 0;
}

int64_t sys_kairos_handle_close(uint64_t handle, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    return (int64_t)khandle_close(p, syshandle_abi_i32(handle));
}

int64_t sys_kairos_handle_duplicate(uint64_t handle, uint64_t rights_mask,
                                    uint64_t out_handle_ptr, uint64_t flags,
                                    uint64_t a4, uint64_t a5) {
    (void)a4;
    (void)a5;

    if ((uint32_t)flags != 0)
        return -EINVAL;
    if (!out_handle_ptr)
        return -EFAULT;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    int32_t new_handle = -1;
    int rc = khandle_duplicate(p, syshandle_abi_i32(handle), (uint32_t)rights_mask,
                               &new_handle);
    if (rc < 0)
        return rc;

    if (copy_to_user((void *)out_handle_ptr, &new_handle, sizeof(new_handle)) < 0) {
        (void)khandle_close(p, new_handle);
        return -EFAULT;
    }

    return 0;
}

int64_t sys_kairos_cap_rights_get(uint64_t fd, uint64_t out_rights_ptr,
                                  uint64_t a2, uint64_t a3, uint64_t a4,
                                  uint64_t a5) {
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    if (!out_rights_ptr)
        return -EFAULT;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    uint32_t rights = 0;
    int rc = fd_get_rights(p, syshandle_abi_i32(fd), &rights);
    if (rc < 0)
        return rc;

    uint64_t out = (uint64_t)rights;
    if (copy_to_user((void *)out_rights_ptr, &out, sizeof(out)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_kairos_cap_rights_limit(uint64_t fd, uint64_t rights_mask,
                                    uint64_t flags, uint64_t a3, uint64_t a4,
                                    uint64_t a5) {
    (void)a3;
    (void)a4;
    (void)a5;

    if ((uint32_t)flags != 0)
        return -EINVAL;
    if (rights_mask & ~(uint64_t)FD_RIGHTS_ALL)
        return -EINVAL;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    return fd_limit_rights(p, syshandle_abi_i32(fd), (uint32_t)rights_mask, NULL);
}

int64_t sys_kairos_handle_from_fd(uint64_t fd, uint64_t out_handle_ptr,
                                  uint64_t rights_mask, uint64_t flags,
                                  uint64_t a4, uint64_t a5) {
    (void)a4;
    (void)a5;

    if (!out_handle_ptr)
        return -EFAULT;
    if ((uint32_t)flags != 0)
        return -EINVAL;
    if (rights_mask & ~(uint64_t)(KRIGHT_READ | KRIGHT_WRITE | KRIGHT_TRANSFER |
                                  KRIGHT_DUPLICATE | KRIGHT_WAIT |
                                  KRIGHT_MANAGE))
        return -EINVAL;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    struct kobj *file_obj = NULL;
    uint32_t desired = 0;
    int rc = handle_bridge_kobj_from_fd(p, syshandle_abi_i32(fd),
                                        (uint32_t)rights_mask, &file_obj,
                                        &desired);
    if (rc < 0)
        return rc;

    int32_t handle = khandle_alloc(p, file_obj, desired);
    kobj_put(file_obj);
    if (handle < 0)
        return handle;

    if (copy_to_user((void *)out_handle_ptr, &handle, sizeof(handle)) < 0) {
        (void)khandle_close(p, handle);
        return -EFAULT;
    }
    return 0;
}

int64_t sys_kairos_fd_from_handle(uint64_t handle, uint64_t out_fd_ptr,
                                  uint64_t flags, uint64_t a3, uint64_t a4,
                                  uint64_t a5) {
    (void)a3;
    (void)a4;
    (void)a5;

    if (!out_fd_ptr)
        return -EFAULT;
    uint32_t open_flags = (uint32_t)flags;
    if (open_flags & ~(O_CLOEXEC | O_NONBLOCK))
        return -EINVAL;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    struct kobj *obj = NULL;
    uint32_t rights = 0;
    int rc = khandle_get(p, syshandle_abi_i32(handle), KRIGHT_DUPLICATE, &obj,
                         &rights);
    if (rc < 0)
        return rc;

    uint32_t fd_flags = (open_flags & O_CLOEXEC) ? FD_CLOEXEC : 0;
    int new_fd = -1;
    if (obj->type == KOBJ_TYPE_FILE) {
        if (open_flags & O_NONBLOCK) {
            rc = -EINVAL;
        } else {
            rc = handle_bridge_fd_from_kobj(p, obj, rights, fd_flags, &new_fd);
        }
    } else if (obj->type == KOBJ_TYPE_CHANNEL) {
        struct file *file = NULL;
        rc = channelfd_create_file(obj, rights, open_flags, &file);
        if (rc >= 0) {
            uint32_t fd_rights = 0;
            if (rights & KRIGHT_READ)
                fd_rights |= FD_RIGHT_READ;
            if (rights & KRIGHT_WRITE)
                fd_rights |= FD_RIGHT_WRITE;
            if (rights & KRIGHT_DUPLICATE)
                fd_rights |= FD_RIGHT_DUP;
            int fd = fd_alloc_rights(p, file, fd_flags, fd_rights);
            if (fd < 0) {
                vfs_close(file);
                rc = fd;
            } else {
                new_fd = fd;
                rc = 0;
            }
        }
    } else if (obj->type == KOBJ_TYPE_PORT) {
        struct file *file = NULL;
        rc = portfd_create_file(obj, rights, open_flags, &file);
        if (rc >= 0) {
            uint32_t fd_rights = FD_RIGHT_READ;
            if (rights & KRIGHT_MANAGE)
                fd_rights |= FD_RIGHT_IOCTL;
            if (rights & KRIGHT_DUPLICATE)
                fd_rights |= FD_RIGHT_DUP;
            int fd = fd_alloc_rights(p, file, fd_flags, fd_rights);
            if (fd < 0) {
                vfs_close(file);
                rc = fd;
            } else {
                new_fd = fd;
                rc = 0;
            }
        }
    } else {
        rc = -ENOTSUP;
    }
    kobj_put(obj);
    if (rc < 0)
        return rc;

    if (copy_to_user((void *)out_fd_ptr, &new_fd, sizeof(new_fd)) < 0) {
        (void)fd_close(p, new_fd);
        return -EFAULT;
    }
    return 0;
}

int64_t sys_kairos_channel_create(uint64_t out0_ptr, uint64_t out1_ptr,
                                  uint64_t flags, uint64_t a3, uint64_t a4,
                                  uint64_t a5) {
    (void)a3;
    (void)a4;
    (void)a5;

    if ((uint32_t)flags != 0)
        return -EINVAL;
    if (!out0_ptr || !out1_ptr)
        return -EFAULT;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    struct kobj *a = NULL;
    struct kobj *b = NULL;
    int rc = kchannel_create_pair(&a, &b);
    if (rc < 0)
        return rc;

    int ha = khandle_alloc(p, a, KRIGHT_CHANNEL_DEFAULT);
    if (ha < 0) {
        kobj_put(a);
        kobj_put(b);
        return ha;
    }

    int hb = khandle_alloc(p, b, KRIGHT_CHANNEL_DEFAULT);
    if (hb < 0) {
        (void)khandle_close(p, ha);
        kobj_put(a);
        kobj_put(b);
        return hb;
    }

    if (copy_to_user((void *)out0_ptr, &ha, sizeof(ha)) < 0 ||
        copy_to_user((void *)out1_ptr, &hb, sizeof(hb)) < 0) {
        (void)khandle_close(p, ha);
        (void)khandle_close(p, hb);
        kobj_put(a);
        kobj_put(b);
        return -EFAULT;
    }

    kobj_put(a);
    kobj_put(b);
    return 0;
}

int64_t sys_kairos_channel_send(uint64_t handle, uint64_t msg_ptr,
                                uint64_t options, uint64_t a3, uint64_t a4,
                                uint64_t a5) {
    (void)a3;
    (void)a4;
    (void)a5;

    if ((uint32_t)options &
        ~(KCHANNEL_OPT_NONBLOCK | KCHANNEL_OPT_RENDEZVOUS))
        return -EINVAL;
    if (!msg_ptr)
        return -EFAULT;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    struct kairos_channel_msg_user msg = {0};
    if (copy_from_user(&msg, (const void *)msg_ptr, sizeof(msg)) < 0)
        return -EFAULT;

    if (msg.num_bytes > KCHANNEL_MAX_MSG_BYTES ||
        msg.num_handles > KCHANNEL_MAX_MSG_HANDLES)
        return -EMSGSIZE;
    if (msg.num_bytes > 0 && msg.bytes == 0)
        return -EFAULT;
    if (msg.num_handles > 0 && msg.handles == 0)
        return -EFAULT;

    void *bytes = NULL;
    if (msg.num_bytes > 0) {
        bytes = kmalloc(msg.num_bytes);
        if (!bytes)
            return -ENOMEM;
        if (copy_from_user(bytes, (const void *)(uintptr_t)msg.bytes,
                           msg.num_bytes) < 0) {
            kfree(bytes);
            return -EFAULT;
        }
    }

    int32_t user_handles[KCHANNEL_MAX_MSG_HANDLES] = {0};
    struct khandle_transfer transfers[KCHANNEL_MAX_MSG_HANDLES] = {0};
    if (msg.num_handles > 0) {
        size_t bytes_len = (size_t)msg.num_handles * sizeof(int32_t);
        if (copy_from_user(user_handles, (const void *)(uintptr_t)msg.handles,
                           bytes_len) < 0) {
            kfree(bytes);
            return -EFAULT;
        }
    }

    struct kobj *channel_obj = NULL;
    int rc = khandle_get(p, syshandle_abi_i32(handle), KRIGHT_WRITE, &channel_obj,
                         NULL);
    if (rc < 0) {
        kfree(bytes);
        return rc;
    }

    size_t taken = 0;
    for (; taken < msg.num_handles; taken++) {
        rc = khandle_take(p, user_handles[taken], KRIGHT_TRANSFER,
                          &transfers[taken].obj, &transfers[taken].rights);
        if (rc < 0)
            break;
    }
    if (rc < 0) {
        syshandle_restore_taken(p, user_handles, transfers, taken);
        kobj_put(channel_obj);
        kfree(bytes);
        return rc;
    }

    rc = kchannel_send(channel_obj, bytes, msg.num_bytes, transfers, msg.num_handles,
                       (uint32_t)options);
    if (rc < 0) {
        syshandle_restore_taken(p, user_handles, transfers, msg.num_handles);
        kobj_put(channel_obj);
        kfree(bytes);
        return rc;
    }

    for (size_t i = 0; i < msg.num_handles; i++) {
        if (transfers[i].obj) {
            kobj_put(transfers[i].obj);
            transfers[i].obj = NULL;
        }
    }

    kobj_put(channel_obj);
    kfree(bytes);
    return 0;
}

int64_t sys_kairos_channel_recv(uint64_t handle, uint64_t msg_ptr,
                                uint64_t options, uint64_t a3, uint64_t a4,
                                uint64_t a5) {
    (void)a3;
    (void)a4;
    (void)a5;

    if ((uint32_t)options &
        ~(KCHANNEL_OPT_NONBLOCK | KCHANNEL_OPT_RENDEZVOUS))
        return -EINVAL;
    if (!msg_ptr)
        return -EFAULT;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    struct kairos_channel_msg_user msg = {0};
    if (copy_from_user(&msg, (const void *)msg_ptr, sizeof(msg)) < 0)
        return -EFAULT;

    if (msg.num_bytes > KCHANNEL_MAX_MSG_BYTES ||
        msg.num_handles > KCHANNEL_MAX_MSG_HANDLES)
        return -EMSGSIZE;
    if (msg.num_bytes > 0 && msg.bytes == 0)
        return -EFAULT;
    if (msg.num_handles > 0 && msg.handles == 0)
        return -EFAULT;

    void *bytes = NULL;
    if (msg.num_bytes > 0) {
        bytes = kmalloc(msg.num_bytes);
        if (!bytes)
            return -ENOMEM;
    }

    struct khandle_transfer transfers[KCHANNEL_MAX_MSG_HANDLES] = {0};
    int32_t installed[KCHANNEL_MAX_MSG_HANDLES];
    for (size_t i = 0; i < KCHANNEL_MAX_MSG_HANDLES; i++)
        installed[i] = -1;

    struct kobj *channel_obj = NULL;
    int rc = khandle_get(p, syshandle_abi_i32(handle), KRIGHT_READ, &channel_obj,
                         NULL);
    if (rc < 0) {
        kfree(bytes);
        return rc;
    }

    size_t got_bytes = 0;
    size_t got_handles = 0;
    bool trunc = false;

    rc = kchannel_recv(channel_obj, bytes, msg.num_bytes, &got_bytes, transfers,
                       msg.num_handles, &got_handles, &trunc, (uint32_t)options);
    if (rc == -EMSGSIZE) {
        msg.num_bytes = (uint32_t)got_bytes;
        msg.num_handles = (uint32_t)got_handles;
        if (copy_to_user((void *)msg_ptr, &msg, sizeof(msg)) < 0)
            rc = -EFAULT;
        kobj_put(channel_obj);
        kfree(bytes);
        return rc;
    }
    if (rc < 0) {
        kobj_put(channel_obj);
        kfree(bytes);
        return rc;
    }

    for (size_t i = 0; i < got_handles; i++) {
        rc = khandle_alloc(p, transfers[i].obj, transfers[i].rights);
        if (rc < 0) {
            syshandle_close_installed(p, installed, i);
            for (size_t j = i; j < got_handles; j++) {
                if (transfers[j].obj)
                    khandle_transfer_drop(transfers[j].obj);
            }
            kobj_put(channel_obj);
            kfree(bytes);
            return rc;
        }
        installed[i] = rc;
        khandle_transfer_drop(transfers[i].obj);
        transfers[i].obj = NULL;
    }

    if (got_bytes > 0 &&
        copy_to_user((void *)(uintptr_t)msg.bytes, bytes, got_bytes) < 0) {
        syshandle_close_installed(p, installed, got_handles);
        kobj_put(channel_obj);
        kfree(bytes);
        return -EFAULT;
    }

    if (got_handles > 0) {
        size_t handles_len = got_handles * sizeof(int32_t);
        if (copy_to_user((void *)(uintptr_t)msg.handles, installed, handles_len) <
            0) {
            syshandle_close_installed(p, installed, got_handles);
            kobj_put(channel_obj);
            kfree(bytes);
            return -EFAULT;
        }
    }

    msg.num_bytes = (uint32_t)got_bytes;
    msg.num_handles = (uint32_t)got_handles;
    if (copy_to_user((void *)msg_ptr, &msg, sizeof(msg)) < 0) {
        syshandle_close_installed(p, installed, got_handles);
        kobj_put(channel_obj);
        kfree(bytes);
        return -EFAULT;
    }

    kobj_put(channel_obj);
    kfree(bytes);
    return 0;
}

int64_t sys_kairos_port_create(uint64_t out_handle_ptr, uint64_t flags,
                               uint64_t a2, uint64_t a3, uint64_t a4,
                               uint64_t a5) {
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    if ((uint32_t)flags != 0)
        return -EINVAL;
    if (!out_handle_ptr)
        return -EFAULT;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    struct kobj *port_obj = NULL;
    int rc = kport_create(&port_obj);
    if (rc < 0)
        return rc;

    int h = khandle_alloc(p, port_obj, KRIGHT_PORT_DEFAULT);
    if (h < 0) {
        kobj_put(port_obj);
        return h;
    }

    if (copy_to_user((void *)out_handle_ptr, &h, sizeof(h)) < 0) {
        (void)khandle_close(p, h);
        kobj_put(port_obj);
        return -EFAULT;
    }

    kobj_put(port_obj);
    return 0;
}

int64_t sys_kairos_port_bind(uint64_t port_handle, uint64_t channel_handle,
                             uint64_t key, uint64_t signals, uint64_t flags,
                             uint64_t a5) {
    (void)a5;

    if ((uint32_t)flags != 0)
        return -EINVAL;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    struct kobj *port_obj = NULL;
    int rc = khandle_get(p, syshandle_abi_i32(port_handle), KRIGHT_MANAGE,
                         &port_obj, NULL);
    if (rc < 0)
        return rc;

    struct kobj *channel_obj = NULL;
    rc = khandle_get(p, syshandle_abi_i32(channel_handle), KRIGHT_READ,
                     &channel_obj, NULL);
    if (rc < 0) {
        kobj_put(port_obj);
        return rc;
    }

    rc = kport_bind_channel(port_obj, channel_obj, key, (uint32_t)signals);
    kobj_put(channel_obj);
    kobj_put(port_obj);
    return rc;
}

int64_t sys_kairos_port_wait(uint64_t port_handle, uint64_t packet_ptr,
                             uint64_t timeout_ns, uint64_t options, uint64_t a4,
                             uint64_t a5) {
    (void)a4;
    (void)a5;

    if (!packet_ptr)
        return -EFAULT;

    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    struct kobj *port_obj = NULL;
    int rc = khandle_get(p, syshandle_abi_i32(port_handle), KRIGHT_WAIT,
                         &port_obj, NULL);
    if (rc < 0)
        return rc;

    struct kairos_port_packet_user pkt = {0};
    rc = kobj_wait(port_obj, &pkt, timeout_ns, (uint32_t)options);
    kobj_put(port_obj);
    if (rc < 0)
        return rc;

    if (copy_to_user((void *)packet_ptr, &pkt, sizeof(pkt)) < 0)
        return -EFAULT;

    return 0;
}
