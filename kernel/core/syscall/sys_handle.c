/**
 * kernel/core/syscall/sys_handle.c - Kairos capability handle and channel/port syscalls
 */

#include <kairos/handle.h>
#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/uaccess.h>

static inline int32_t syshandle_abi_i32(uint64_t raw) {
    return (int32_t)(uint32_t)raw;
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

    if ((uint32_t)options & ~KCHANNEL_OPT_NONBLOCK)
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

    if ((uint32_t)options & ~KCHANNEL_OPT_NONBLOCK)
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
    rc = kport_wait(port_obj, &pkt, timeout_ns, (uint32_t)options);
    kobj_put(port_obj);
    if (rc < 0)
        return rc;

    if (copy_to_user((void *)packet_ptr, &pkt, sizeof(pkt)) < 0)
        return -EFAULT;

    return 0;
}
