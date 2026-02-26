/**
 * kernel/core/syscall/sys_socket.c - Socket syscall handlers
 */

#include <kairos/config.h>
#include <kairos/arch.h>
#include <kairos/handle.h>
#include <kairos/handle_bridge.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/process.h>
#include <kairos/socket.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/tracepoint.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#define SOCKET_MSG_IOV_MAX 1024
#define SOCKET_MSG_MAX_LEN 65536
#define SOCKET_MSG_INLINE_LEN 256
#define SOCKET_MSG_INLINE_IOV 8
#define MSG_WAITFORONE 0x10000
#define NS_PER_SEC 1000000000ULL
#define SCM_RIGHTS 1
#define SCM_CREDENTIALS 2

static inline int32_t syssock_abi_i32(uint64_t raw) {
    return (int32_t)(uint32_t)raw;
}

static inline uint32_t syssock_abi_u32(uint64_t raw) {
    return (uint32_t)raw;
}

struct socket_iovec {
    void *iov_base;
    size_t iov_len;
};

struct socket_msghdr {
    void *msg_name;
    uint32_t msg_namelen;
    uint32_t __pad0;
    void *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    uint32_t msg_flags;
    uint32_t __pad1;
};

struct socket_mmsghdr {
    struct socket_msghdr msg_hdr;
    uint32_t msg_len;
    uint32_t __pad;
};

struct socket_cmsghdr {
    size_t cmsg_len;
    int32_t cmsg_level;
    int32_t cmsg_type;
};

static size_t socket_cmsg_align(size_t len) {
    const size_t align = sizeof(size_t) - 1;
    return (len + align) & ~align;
}

static int socket_validate_send_control(uint64_t control_ptr, size_t controllen) {
    if (!controllen)
        return 0;
    if (!control_ptr)
        return -EFAULT;

    size_t off = 0;
    while (off < controllen) {
        if (controllen - off < sizeof(struct socket_cmsghdr))
            return -EINVAL;

        struct socket_cmsghdr hdr;
        if (copy_from_user(&hdr, (const void *)(control_ptr + off),
                           sizeof(hdr)) < 0)
            return -EFAULT;
        if (hdr.cmsg_len < sizeof(struct socket_cmsghdr))
            return -EINVAL;
        if (hdr.cmsg_len > controllen - off)
            return -EINVAL;

        size_t payload_len = hdr.cmsg_len - sizeof(struct socket_cmsghdr);
        if (hdr.cmsg_level == SOL_SOCKET) {
            switch (hdr.cmsg_type) {
            case SCM_RIGHTS:
                if (payload_len % sizeof(int32_t))
                    return -EINVAL;
                break;
            case SCM_CREDENTIALS:
                if (payload_len != sizeof(struct socket_ucred))
                    return -EINVAL;
                break;
            default:
                return -EOPNOTSUPP;
            }
        }

        size_t adv = socket_cmsg_align(hdr.cmsg_len);
        if (adv > controllen - off) {
            if (off + hdr.cmsg_len != controllen)
                return -EINVAL;
            off = controllen;
            break;
        }
        off += adv;
    }
    return 0;
}

static void socket_control_release(struct socket_control *control) {
    if (!control)
        return;
    for (size_t i = 0; i < control->rights_count && i < SOCKET_MAX_RIGHTS; i++) {
        if (control->rights[i]) {
            kobj_put(control->rights[i]);
            control->rights[i] = NULL;
        }
        control->rights_masks[i] = 0;
    }
    control->rights_count = 0;
    control->has_creds = false;
}

static int socket_parse_send_control(const struct socket_msghdr *msg,
                                     struct socket_control *control) {
    if (!control)
        return -EINVAL;
    memset(control, 0, sizeof(*control));

    if (!msg->msg_controllen)
        return 0;

    uint64_t control_ptr = (uint64_t)(uintptr_t)msg->msg_control;
    int rc = socket_validate_send_control(control_ptr, msg->msg_controllen);
    if (rc < 0)
        return rc;

    struct process *curr = proc_current();
    if (!curr)
        return -EINVAL;

    size_t off = 0;
    while (off < msg->msg_controllen) {
        struct socket_cmsghdr hdr;
        if (copy_from_user(&hdr, (const void *)(control_ptr + off),
                           sizeof(hdr)) < 0) {
            rc = -EFAULT;
            goto fail;
        }

        size_t payload_len = hdr.cmsg_len - sizeof(struct socket_cmsghdr);
        uint64_t payload_ptr = control_ptr + off + sizeof(struct socket_cmsghdr);

        if (hdr.cmsg_level == SOL_SOCKET && hdr.cmsg_type == SCM_RIGHTS) {
            size_t rights_nr = payload_len / sizeof(int32_t);
            if (rights_nr > SOCKET_MAX_RIGHTS ||
                control->rights_count > SOCKET_MAX_RIGHTS - rights_nr) {
                rc = -EINVAL;
                goto fail;
            }
            for (size_t i = 0; i < rights_nr; i++) {
                int32_t ufd = -1;
                if (copy_from_user(&ufd,
                                   (const void *)(payload_ptr +
                                                  i * sizeof(int32_t)),
                                   sizeof(ufd)) < 0) {
                    rc = -EFAULT;
                    goto fail;
                }
                struct kobj *obj = NULL;
                uint32_t rights = 0;
                int fr = handle_bridge_transfer_from_fd(curr, ufd, 0,
                                                        &obj, &rights);
                if (fr < 0) {
                    rc = fr;
                    goto fail;
                }
                control->rights[control->rights_count++] = obj;
                control->rights_masks[control->rights_count - 1] = rights;
            }
        } else if (hdr.cmsg_level == SOL_SOCKET &&
                   hdr.cmsg_type == SCM_CREDENTIALS) {
            struct socket_ucred ucred;
            if (copy_from_user(&ucred, (const void *)payload_ptr,
                               sizeof(ucred)) < 0) {
                rc = -EFAULT;
                goto fail;
            }
            control->has_creds = true;
            control->creds.pid = curr->pid;
            control->creds.uid = curr->uid;
            control->creds.gid = curr->gid;
        }

        size_t adv = socket_cmsg_align(hdr.cmsg_len);
        if (adv > msg->msg_controllen - off)
            off = msg->msg_controllen;
        else
            off += adv;
    }
    return 0;

fail:
    socket_control_release(control);
    return rc;
}

static void socket_close_installed_fds(struct process *p, const int *fds,
                                       size_t nr) {
    if (!p || !fds)
        return;
    for (size_t i = 0; i < nr; i++) {
        if (fds[i] >= 0)
            (void)fd_close(p, fds[i]);
    }
}

static int socket_copyout_recv_control(struct socket_msghdr *msg,
                                       struct socket_control *control,
                                       uint32_t recv_flags) {
    if (!msg || !control)
        return -EINVAL;

    size_t user_cap = msg->msg_controllen;
    uint64_t user_ptr = (uint64_t)(uintptr_t)msg->msg_control;
    size_t off = 0;
    uint32_t out_flags = msg->msg_flags;
    bool cloexec = (recv_flags & MSG_CMSG_CLOEXEC) != 0;
    struct process *curr = proc_current();
    if (!curr)
        return -EINVAL;

    if (control->truncated)
        out_flags |= MSG_CTRUNC;

    if (control->has_creds) {
        size_t cmsg_len = sizeof(struct socket_cmsghdr) +
                          sizeof(struct socket_ucred);
        if (user_ptr && user_cap - off >= cmsg_len) {
            struct socket_cmsghdr hdr = {
                .cmsg_len = cmsg_len,
                .cmsg_level = SOL_SOCKET,
                .cmsg_type = SCM_CREDENTIALS,
            };
            if (copy_to_user((void *)(user_ptr + off), &hdr, sizeof(hdr)) < 0)
                return -EFAULT;
            if (copy_to_user((void *)(user_ptr + off + sizeof(hdr)),
                             &control->creds, sizeof(control->creds)) < 0)
                return -EFAULT;
            size_t adv = socket_cmsg_align(cmsg_len);
            if (adv > user_cap - off)
                off += cmsg_len;
            else
                off += adv;
        } else {
            out_flags |= MSG_CTRUNC;
        }
    }

    size_t rights_nr = control->rights_count;
    if (rights_nr > SOCKET_MAX_RIGHTS)
        rights_nr = SOCKET_MAX_RIGHTS;
    if (rights_nr > 0) {
        size_t payload_len = rights_nr * sizeof(int32_t);
        size_t cmsg_len = sizeof(struct socket_cmsghdr) + payload_len;
        if (user_ptr && user_cap - off >= cmsg_len) {
            int installed[SOCKET_MAX_RIGHTS];
            int32_t rights_payload[SOCKET_MAX_RIGHTS];
            for (size_t i = 0; i < rights_nr; i++) {
                installed[i] = -1;
                rights_payload[i] = -1;
            }

            for (size_t i = 0; i < rights_nr; i++) {
                if (!control->rights[i]) {
                    socket_close_installed_fds(curr, installed, i);
                    return -EINVAL;
                }
                int fd = -1;
                int rc = handle_bridge_fd_from_kobj(curr, control->rights[i],
                                                    control->rights_masks[i],
                                                    cloexec ? FD_CLOEXEC : 0,
                                                    &fd);
                if (rc < 0) {
                    socket_close_installed_fds(curr, installed, i);
                    return rc;
                }
                installed[i] = fd;
                rights_payload[i] = fd;
                control->rights[i] = NULL;
            }

            struct socket_cmsghdr hdr = {
                .cmsg_len = cmsg_len,
                .cmsg_level = SOL_SOCKET,
                .cmsg_type = SCM_RIGHTS,
            };
            if (copy_to_user((void *)(user_ptr + off), &hdr, sizeof(hdr)) < 0 ||
                copy_to_user((void *)(user_ptr + off + sizeof(hdr)),
                             rights_payload, payload_len) < 0) {
                socket_close_installed_fds(curr, installed, rights_nr);
                return -EFAULT;
            }
            size_t adv = socket_cmsg_align(cmsg_len);
            if (adv > user_cap - off)
                off += cmsg_len;
            else
                off += adv;
        } else {
            out_flags |= MSG_CTRUNC;
        }
    }

    msg->msg_controllen = off;
    msg->msg_flags = out_flags;
    return 0;
}

static uint64_t socket_ns_to_sched_ticks(uint64_t ns) {
    if (ns == 0)
        return 0;
    uint64_t ticks = (ns * CONFIG_HZ + NS_PER_SEC - 1) / NS_PER_SEC;
    return ticks ? ticks : 1;
}

static int socket_copy_timeout_deadline(uint64_t timeout_ptr, bool *has_timeout,
                                        uint64_t *deadline_out) {
    if (!has_timeout || !deadline_out)
        return -EINVAL;

    *has_timeout = false;
    *deadline_out = 0;
    if (!timeout_ptr)
        return 0;

    struct timespec ts;
    if (copy_from_user(&ts, (const void *)timeout_ptr, sizeof(ts)) < 0)
        return -EFAULT;
    if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= (int64_t)NS_PER_SEC)
        return -EINVAL;

    uint64_t now = arch_timer_get_ticks();
    if (ts.tv_sec == 0 && ts.tv_nsec == 0) {
        *has_timeout = true;
        *deadline_out = now;
        return 0;
    }

    uint64_t sec = (uint64_t)ts.tv_sec;
    if (sec > UINT64_MAX / NS_PER_SEC)
        return -EINVAL;
    uint64_t ns = sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
    *has_timeout = true;
    *deadline_out = now + socket_ns_to_sched_ticks(ns);
    return 0;
}

static int socket_wait_readable(struct socket *sock, struct file *sock_file,
                                bool has_timeout, uint64_t deadline) {
    if (!sock || !sock_file)
        return -EINVAL;

    struct process *curr = proc_current();
    if (!curr)
        return -EINVAL;

    while (1) {
        uint32_t revents = (uint32_t)vfs_poll(sock_file, POLLIN | POLLERR | POLLHUP);
        if (revents & (POLLIN | POLLERR | POLLHUP))
            return 1;
        if (has_timeout && poll_deadline_expired(deadline))
            return 0;

        struct poll_waiter waiter = {0};
        INIT_LIST_HEAD(&waiter.entry.node);
        waiter.entry.proc = curr;
        poll_wait_add(&sock->pollers, &waiter);

        revents = (uint32_t)vfs_poll(sock_file, POLLIN | POLLERR | POLLHUP);
        if (revents & (POLLIN | POLLERR | POLLHUP)) {
            poll_wait_remove(&waiter);
            return 1;
        }
        if (has_timeout && poll_deadline_expired(deadline)) {
            poll_wait_remove(&waiter);
            return 0;
        }

        int rc = poll_block_current(has_timeout ? deadline : 0, sock);
        poll_wait_remove(&waiter);

        if (rc == -EINTR)
            return -EINTR;
        if (rc == -ETIMEDOUT)
            return 0;
        if (rc < 0)
            return rc;
    }
}

static struct socket *sock_from_fd(struct process *p, uint64_t fd_arg,
                                   uint32_t required_rights,
                                   struct file **filep) {
    int fd = syssock_abi_i32(fd_arg);
    struct file *f = NULL;
    int fr = handle_bridge_pin_fd(p, fd, required_rights, &f, NULL);
    if (fr < 0)
        return NULL;
    if (!f || !f->vnode) {
        if (f) file_put(f);
        return NULL;
    }
    struct socket *sock = sock_from_vnode(f->vnode);
    if (!sock) {
        file_put(f);
        return NULL;
    }
    *filep = f;
    return sock;
}

static uint32_t socket_effective_msg_flags(const struct file *sock_file,
                                           uint32_t flags) {
    if (sock_file && (sock_file->flags & O_NONBLOCK))
        flags |= MSG_DONTWAIT;
    return flags;
}

static int copy_sockaddr_from_user(struct sockaddr_storage *kaddr,
                                   uint64_t uaddr, uint64_t ulen) {
    if (!uaddr || !ulen) {
        return 0;
    }
    int len = syssock_abi_i32(ulen);
    if (len < 0 || (size_t)len > sizeof(*kaddr)) {
        return -EINVAL;
    }
    memset(kaddr, 0, sizeof(*kaddr));
    if (copy_from_user(kaddr, (const void *)uaddr, (size_t)len) < 0) {
        return -EFAULT;
    }
    return len;
}

static int socket_msg_load_iov(uint64_t iov_ptr, size_t iovcnt,
                               struct socket_iovec inline_iov[SOCKET_MSG_INLINE_IOV],
                               struct socket_iovec **iov_out,
                               bool *heap_out, size_t *total_out) {
    if (!iov_out || !heap_out || !total_out)
        return -EINVAL;
    *iov_out = NULL;
    *heap_out = false;
    *total_out = 0;
    if (!iovcnt)
        return 0;
    if (!iov_ptr)
        return -EFAULT;

    struct socket_iovec *iov = inline_iov;
    bool use_heap = iovcnt > SOCKET_MSG_INLINE_IOV;
    if (use_heap) {
        iov = kmalloc(iovcnt * sizeof(*iov));
        if (!iov)
            return -ENOMEM;
    }

    size_t total = 0;
    for (size_t i = 0; i < iovcnt; i++) {
        if (copy_from_user(&iov[i],
                           (const void *)(iov_ptr + i * sizeof(iov[i])),
                           sizeof(iov[i])) < 0) {
            if (use_heap)
                kfree(iov);
            return -EFAULT;
        }
        if (iov[i].iov_len > (size_t)-1 - total) {
            if (use_heap)
                kfree(iov);
            return -EINVAL;
        }
        total += iov[i].iov_len;
    }

    *iov_out = iov;
    *heap_out = use_heap;
    *total_out = total;
    return 0;
}

static int socket_msg_copyin_iov(const struct socket_iovec *iov, size_t iovcnt,
                                 void *dst, size_t max_len, size_t *copied_out) {
    size_t done = 0;
    for (size_t i = 0; i < iovcnt && done < max_len; i++) {
        if (!iov[i].iov_len) {
            continue;
        }
        size_t chunk = iov[i].iov_len;
        if (chunk > (max_len - done)) {
            chunk = max_len - done;
        }
        if (copy_from_user((uint8_t *)dst + done, iov[i].iov_base, chunk) < 0) {
            return -EFAULT;
        }
        done += chunk;
    }
    *copied_out = done;
    return 0;
}

static int socket_msg_copyout_iov(const struct socket_iovec *iov, size_t iovcnt,
                                  const void *src, size_t src_len) {
    size_t done = 0;
    for (size_t i = 0; i < iovcnt && done < src_len; i++) {
        if (!iov[i].iov_len) {
            continue;
        }
        size_t chunk = iov[i].iov_len;
        if (chunk > (src_len - done)) {
            chunk = src_len - done;
        }
        if (copy_to_user(iov[i].iov_base, (const uint8_t *)src + done, chunk) <
            0) {
            return -EFAULT;
        }
        done += chunk;
    }
    return 0;
}

static int64_t socket_sendmsg(struct socket *sock,
                              const struct socket_msghdr *msg, uint32_t flags,
                              uint32_t *sent_out) {
    if (!sock || !sock->ops || !sock->ops->sendto) {
        return -EOPNOTSUPP;
    }
    if (msg->msg_iovlen > SOCKET_MSG_IOV_MAX) {
        return -EINVAL;
    }
    struct socket_control control;
    int rc = socket_parse_send_control(msg, &control);
    if (rc < 0)
        return rc;
    bool has_control_payload = control.has_creds || control.rights_count > 0;
    if (has_control_payload && !sock->ops->sendmsg) {
        socket_control_release(&control);
        return -EOPNOTSUPP;
    }

    struct sockaddr_storage kaddr;
    struct sockaddr *destp = NULL;
    int dlen = 0;
    if (msg->msg_name) {
        dlen = copy_sockaddr_from_user(&kaddr, (uint64_t)(uintptr_t)msg->msg_name,
                                       msg->msg_namelen);
        if (dlen < 0) {
            socket_control_release(&control);
            return (int64_t)dlen;
        }
        destp = (struct sockaddr *)&kaddr;
    }

    uint64_t iov_ptr = (uint64_t)(uintptr_t)msg->msg_iov;
    struct socket_iovec iov_inline[SOCKET_MSG_INLINE_IOV];
    struct socket_iovec *iov = NULL;
    bool iov_heap = false;
    size_t total = 0;
    rc = socket_msg_load_iov(iov_ptr, msg->msg_iovlen, iov_inline, &iov,
                             &iov_heap, &total);
    if (rc < 0) {
        socket_control_release(&control);
        return rc;
    }
    if (total > SOCKET_MSG_MAX_LEN) {
        total = SOCKET_MSG_MAX_LEN;
    }
    if (!total) {
        ssize_t ret = has_control_payload
                          ? sock->ops->sendmsg(sock, NULL, 0, (int32_t)flags,
                                               destp, dlen, &control)
                          : sock->ops->sendto(sock, NULL, 0, (int32_t)flags,
                                              destp, dlen);
        if (iov_heap)
            kfree(iov);
        socket_control_release(&control);
        if (ret >= 0 && sent_out) {
            *sent_out = (ret > UINT32_MAX) ? UINT32_MAX : (uint32_t)ret;
        }
        return ret;
    }

    uint8_t inline_buf[SOCKET_MSG_INLINE_LEN];
    bool use_heap = total > sizeof(inline_buf);
    void *kbuf = use_heap ? kmalloc(total) : (void *)inline_buf;
    if (!kbuf) {
        if (iov_heap)
            kfree(iov);
        socket_control_release(&control);
        return -ENOMEM;
    }
    tracepoint_emit(use_heap ? TRACE_SOCKET_HEAP_BUF : TRACE_SOCKET_INLINE_BUF,
                    0, total, 0);
    size_t copied = 0;
    rc = socket_msg_copyin_iov(iov, msg->msg_iovlen, kbuf, total, &copied);
    if (rc < 0) {
        if (use_heap)
            kfree(kbuf);
        if (iov_heap)
            kfree(iov);
        socket_control_release(&control);
        return rc;
    }

    ssize_t ret = has_control_payload
                      ? sock->ops->sendmsg(sock, kbuf, copied, (int32_t)flags,
                                           destp, dlen, &control)
                      : sock->ops->sendto(sock, kbuf, copied, (int32_t)flags,
                                          destp, dlen);
    if (use_heap)
        kfree(kbuf);
    if (iov_heap)
        kfree(iov);
    socket_control_release(&control);
    if (ret >= 0 && sent_out) {
        *sent_out = (ret > UINT32_MAX) ? UINT32_MAX : (uint32_t)ret;
    }
    return ret;
}

static int64_t socket_recvmsg(struct socket *sock, struct socket_msghdr *msg,
                              uint32_t flags, uint32_t *recv_out) {
    if (!sock || !sock->ops || !sock->ops->recvfrom) {
        return -EOPNOTSUPP;
    }
    if (msg->msg_iovlen > SOCKET_MSG_IOV_MAX) {
        return -EINVAL;
    }
    if (msg->msg_controllen && !msg->msg_control)
        return -EFAULT;

    uint64_t iov_ptr = (uint64_t)(uintptr_t)msg->msg_iov;
    struct socket_iovec iov_inline[SOCKET_MSG_INLINE_IOV];
    struct socket_iovec *iov = NULL;
    bool iov_heap = false;
    size_t total = 0;
    int rc = socket_msg_load_iov(iov_ptr, msg->msg_iovlen, iov_inline, &iov,
                                 &iov_heap, &total);
    if (rc < 0) {
        return rc;
    }
    if (total > SOCKET_MSG_MAX_LEN) {
        total = SOCKET_MSG_MAX_LEN;
    }

    uint8_t inline_buf[SOCKET_MSG_INLINE_LEN];
    bool use_heap = total > sizeof(inline_buf);
    void *kbuf = NULL;
    if (total > 0) {
        kbuf = use_heap ? kmalloc(total) : (void *)inline_buf;
        if (!kbuf) {
            if (iov_heap)
                kfree(iov);
            return -ENOMEM;
        }
        tracepoint_emit(use_heap ? TRACE_SOCKET_HEAP_BUF
                                 : TRACE_SOCKET_INLINE_BUF,
                        0, total, 1);
    }

    uint32_t proto_flags = flags & ~MSG_CMSG_CLOEXEC;
    struct socket_control control = {0};
    struct sockaddr_storage kaddr;
    int alen = (int)sizeof(kaddr);
    ssize_t ret = sock->ops->recvmsg
                      ? sock->ops->recvmsg(sock, kbuf, total, (int32_t)proto_flags,
                                           msg->msg_name
                                               ? (struct sockaddr *)&kaddr
                                               : NULL,
                                           msg->msg_name ? &alen : NULL,
                                           &control)
                      : sock->ops->recvfrom(sock, kbuf, total,
                                            (int32_t)proto_flags,
                                            msg->msg_name
                                                ? (struct sockaddr *)&kaddr
                                                : NULL,
                                            msg->msg_name ? &alen : NULL);
    if (ret > 0) {
        rc = socket_msg_copyout_iov(iov, msg->msg_iovlen, kbuf, (size_t)ret);
        if (rc < 0) {
            if (use_heap)
                kfree(kbuf);
            if (iov_heap)
                kfree(iov);
            socket_control_release(&control);
            return rc;
        }
    }
    if (use_heap)
        kfree(kbuf);
    if (iov_heap)
        kfree(iov);

    if (ret >= 0 && msg->msg_name) {
        size_t user_len = (size_t)msg->msg_namelen;
        size_t klen = (alen < 0) ? 0 : (size_t)alen;
        size_t copylen = (klen < user_len) ? klen : user_len;
        if (copylen &&
            copy_to_user(msg->msg_name, &kaddr, copylen) < 0) {
            socket_control_release(&control);
            return -EFAULT;
        }
        msg->msg_namelen = (alen < 0) ? 0 : (uint32_t)alen;
    }
    if (ret >= 0) {
        msg->msg_flags = 0;
        rc = socket_copyout_recv_control(msg, &control, flags);
        if (rc < 0) {
            socket_control_release(&control);
            return rc;
        }
        if (recv_out) {
            *recv_out = (ret > UINT32_MAX) ? UINT32_MAX : (uint32_t)ret;
        }
    }
    socket_control_release(&control);
    return ret;
}

int64_t sys_socket(uint64_t domain, uint64_t type, uint64_t protocol,
                   uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p) {
        return -EINVAL;
    }

    int sock_domain = syssock_abi_i32(domain);
    int sock_type = syssock_abi_i32(type);
    int sock_protocol = syssock_abi_i32(protocol);
    int extra_flags = sock_type & (SOCK_NONBLOCK | SOCK_CLOEXEC);

    struct socket *sock = NULL;
    int ret = sock_create(sock_domain, sock_type, sock_protocol, &sock);
    if (ret < 0) {
        return (int64_t)ret;
    }

    struct file *file = vfs_file_alloc();
    if (!file) {
        sock_destroy(sock);
        return -ENOMEM;
    }
    file->vnode = sock->vnode;
    vnode_get(sock->vnode);
    file->flags = O_RDWR;
    if (extra_flags & SOCK_NONBLOCK) {
        file->flags |= O_NONBLOCK;
    }

    uint32_t fd_flags = (extra_flags & SOCK_CLOEXEC) ? FD_CLOEXEC : 0;
    int fd = fd_alloc_flags(p, file, fd_flags);
    if (fd < 0) {
        vfs_close(file);
        sock_destroy(sock);
        return -EMFILE;
    }
    return fd;
}

int64_t sys_bind(uint64_t fd, uint64_t addr, uint64_t addrlen,
                 uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, 0, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->bind) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }

    struct sockaddr_storage kaddr;
    int len = copy_sockaddr_from_user(&kaddr, addr, addrlen);
    if (len < 0) {
        file_put(sock_file);
        return (int64_t)len;
    }
    int64_t ret = (int64_t)sock->ops->bind(sock, (struct sockaddr *)&kaddr, len);
    file_put(sock_file);
    return ret;
}

int64_t sys_listen(uint64_t fd, uint64_t backlog, uint64_t a2,
                   uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    int kbacklog = syssock_abi_i32(backlog);
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, 0, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->listen) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }
    int64_t ret = (int64_t)sock->ops->listen(sock, kbacklog);
    file_put(sock_file);
    return ret;
}

static int64_t sys_accept_common(uint64_t fd, uint64_t addr,
                                 uint64_t addrlen_ptr, uint32_t flags) {
    if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC))
        return -EINVAL;
    if ((addr == 0) != (addrlen_ptr == 0))
        return -EFAULT;

    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, 0, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->accept) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }

    struct socket *newsock = NULL;
    uint32_t accept_flags = socket_effective_msg_flags(sock_file, 0);
    int ret = sock->ops->accept(sock, &newsock, (int)accept_flags);
    if (ret < 0) {
        file_put(sock_file);
        return (int64_t)ret;
    }

    /* Copy peer address to user if requested */
    if (addr && addrlen_ptr) {
        uint32_t ulen_raw = 0;
        if (copy_from_user(&ulen_raw, (const void *)addrlen_ptr,
                           sizeof(ulen_raw)) < 0) {
            sock_destroy(newsock);
            file_put(sock_file);
            return -EFAULT;
        }
        int ulen = (int32_t)ulen_raw;
        if (ulen < 0) {
            sock_destroy(newsock);
            file_put(sock_file);
            return -EINVAL;
        }
        if (newsock->ops && newsock->ops->getpeername) {
            struct sockaddr_storage kaddr;
            int klen = (int)sizeof(kaddr);
            int gp = newsock->ops->getpeername(newsock, (struct sockaddr *)&kaddr,
                                               &klen);
            if (gp < 0) {
                sock_destroy(newsock);
                file_put(sock_file);
                return (int64_t)gp;
            }
            int copylen = (klen < ulen) ? klen : ulen;
            if (copylen > 0 &&
                copy_to_user((void *)addr, &kaddr, (size_t)copylen) < 0) {
                sock_destroy(newsock);
                file_put(sock_file);
                return -EFAULT;
            }
            if (copy_to_user((void *)addrlen_ptr, &klen, sizeof(klen)) < 0) {
                sock_destroy(newsock);
                file_put(sock_file);
                return -EFAULT;
            }
        }
    }

    struct file *file = vfs_file_alloc();
    if (!file) {
        sock_destroy(newsock);
        file_put(sock_file);
        return -ENOMEM;
    }
    file->vnode = newsock->vnode;
    vnode_get(newsock->vnode);
    file->flags = O_RDWR;
    if (flags & SOCK_NONBLOCK)
        file->flags |= O_NONBLOCK;

    uint32_t fd_flags = (flags & SOCK_CLOEXEC) ? FD_CLOEXEC : 0;
    int newfd = fd_alloc_flags(p, file, fd_flags);
    if (newfd < 0) {
        vfs_close(file);
        sock_destroy(newsock);
        file_put(sock_file);
        return -EMFILE;
    }
    file_put(sock_file);
    return newfd;
}

int64_t sys_accept(uint64_t fd, uint64_t addr, uint64_t addrlen_ptr,
                   uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_accept_common(fd, addr, addrlen_ptr, 0);
}

int64_t sys_accept4(uint64_t fd, uint64_t addr, uint64_t addrlen_ptr,
                    uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    return sys_accept_common(fd, addr, addrlen_ptr, syssock_abi_u32(flags));
}

int64_t sys_connect(uint64_t fd, uint64_t addr, uint64_t addrlen,
                    uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, 0, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->connect) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }

    struct sockaddr_storage kaddr;
    int len = copy_sockaddr_from_user(&kaddr, addr, addrlen);
    if (len < 0) {
        file_put(sock_file);
        return (int64_t)len;
    }
    uint32_t connect_flags = socket_effective_msg_flags(sock_file, 0);
    int64_t ret =
        (int64_t)sock->ops->connect(sock, (struct sockaddr *)&kaddr, len,
                                    (int)connect_flags);
    file_put(sock_file);
    return ret;
}

int64_t sys_sendto(uint64_t fd, uint64_t buf, uint64_t len,
                   uint64_t flags, uint64_t dest, uint64_t addrlen) {
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, FD_RIGHT_WRITE, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->sendto) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }
    uint32_t uflags = socket_effective_msg_flags(sock_file, syssock_abi_u32(flags));

    struct sockaddr_storage kaddr;
    struct sockaddr *destp = NULL;
    int dlen = 0;
    if (dest) {
        dlen = copy_sockaddr_from_user(&kaddr, dest, addrlen);
        if (dlen < 0) {
            file_put(sock_file);
            return (int64_t)dlen;
        }
        destp = (struct sockaddr *)&kaddr;
    }

    /* Copy data from user */
    if (!len) {
        ssize_t ret =
            (int64_t)sock->ops->sendto(sock, NULL, 0, (int32_t)uflags, destp,
                                       dlen);
        file_put(sock_file);
        return ret;
    }
    size_t klen = (size_t)len;
    if (klen > 65536) {
        klen = 65536;
    }
    uint8_t inline_buf[SOCKET_MSG_INLINE_LEN];
    bool use_heap = klen > sizeof(inline_buf);
    void *kbuf = use_heap ? kmalloc(klen) : (void *)inline_buf;
    if (!kbuf) {
        file_put(sock_file);
        return -ENOMEM;
    }
    tracepoint_emit(use_heap ? TRACE_SOCKET_HEAP_BUF : TRACE_SOCKET_INLINE_BUF,
                    0, klen, 2);
    if (copy_from_user(kbuf, (const void *)buf, klen) < 0) {
        if (use_heap)
            kfree(kbuf);
        file_put(sock_file);
        return -EFAULT;
    }
    ssize_t ret = sock->ops->sendto(sock, kbuf, klen, (int32_t)uflags,
                                    destp, dlen);
    if (use_heap)
        kfree(kbuf);
    file_put(sock_file);
    return (int64_t)ret;
}

int64_t sys_recvfrom(uint64_t fd, uint64_t buf, uint64_t len,
                     uint64_t flags, uint64_t src, uint64_t addrlen_ptr) {
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, FD_RIGHT_READ, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->recvfrom) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }
    uint32_t uflags = socket_effective_msg_flags(sock_file, syssock_abi_u32(flags));

    size_t klen = (size_t)len;
    if (klen > 65536) {
        klen = 65536;
    }
    uint8_t inline_buf[SOCKET_MSG_INLINE_LEN];
    bool use_heap = klen > sizeof(inline_buf);
    void *kbuf = use_heap ? kmalloc(klen) : (void *)inline_buf;
    if (!kbuf) {
        file_put(sock_file);
        return -ENOMEM;
    }
    tracepoint_emit(use_heap ? TRACE_SOCKET_HEAP_BUF : TRACE_SOCKET_INLINE_BUF,
                    0, klen, 3);

    struct sockaddr_storage kaddr;
    int alen = (int)sizeof(kaddr);
    ssize_t ret = sock->ops->recvfrom(sock, kbuf, klen, (int32_t)uflags,
                                      src ? (struct sockaddr *)&kaddr : NULL,
                                      src ? &alen : NULL);
    if (ret > 0) {
        if (copy_to_user((void *)buf, kbuf, (size_t)ret) < 0) {
            if (use_heap)
                kfree(kbuf);
            file_put(sock_file);
            return -EFAULT;
        }
    }
    if (use_heap)
        kfree(kbuf);

    /* Copy source address to user */
    if (ret >= 0 && src && addrlen_ptr) {
        uint32_t ulen_raw = 0;
        if (copy_from_user(&ulen_raw, (const void *)addrlen_ptr,
                           sizeof(ulen_raw)) == 0) {
            int ulen = (int32_t)ulen_raw;
            if (ulen > 0) {
                int copylen = (alen < ulen) ? alen : ulen;
                copy_to_user((void *)src, &kaddr, (size_t)copylen);
            }
            copy_to_user((void *)addrlen_ptr, &alen, sizeof(alen));
        }
    }
    file_put(sock_file);
    return (int64_t)ret;
}

int64_t sys_shutdown(uint64_t fd, uint64_t how, uint64_t a2,
                     uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    int khow = syssock_abi_i32(how);
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, 0, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->shutdown) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }
    int64_t ret = (int64_t)sock->ops->shutdown(sock, khow);
    file_put(sock_file);
    return ret;
}

int64_t sys_sendmsg(uint64_t fd, uint64_t msg_ptr, uint64_t flags,
                    uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, FD_RIGHT_WRITE, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }

    struct socket_msghdr msg;
    if (copy_from_user(&msg, (const void *)msg_ptr, sizeof(msg)) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    uint32_t uflags = socket_effective_msg_flags(sock_file, syssock_abi_u32(flags));
    int64_t ret = socket_sendmsg(sock, &msg, uflags, NULL);
    file_put(sock_file);
    return ret;
}

int64_t sys_recvmsg(uint64_t fd, uint64_t msg_ptr, uint64_t flags,
                    uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, FD_RIGHT_READ, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }

    struct socket_msghdr msg;
    if (copy_from_user(&msg, (const void *)msg_ptr, sizeof(msg)) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    uint32_t uflags = socket_effective_msg_flags(sock_file, syssock_abi_u32(flags));
    int64_t ret = socket_recvmsg(sock, &msg, uflags, NULL);
    if (ret >= 0 &&
        copy_to_user((void *)msg_ptr, &msg, sizeof(msg)) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    file_put(sock_file);
    return ret;
}

int64_t sys_sendmmsg(uint64_t fd, uint64_t msgvec_ptr, uint64_t vlen,
                     uint64_t flags, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    uint32_t uflags = syssock_abi_u32(flags);
    uint32_t uvlen = syssock_abi_u32(vlen);
    if (!uvlen) {
        return 0;
    }
    if (uvlen > SOCKET_MSG_IOV_MAX) {
        return -EINVAL;
    }

    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, FD_RIGHT_WRITE, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    uflags = socket_effective_msg_flags(sock_file, uflags);

    int sent = 0;
    for (uint32_t i = 0; i < uvlen; i++) {
        uint64_t ent_ptr = msgvec_ptr + i * sizeof(struct socket_mmsghdr);
        struct socket_msghdr msg_hdr;
        if (copy_from_user(&msg_hdr, (const void *)ent_ptr,
                           sizeof(msg_hdr)) < 0) {
            file_put(sock_file);
            return sent ? sent : -EFAULT;
        }
        uint32_t msg_len = 0;
        int64_t ret =
            socket_sendmsg(sock, &msg_hdr, uflags, &msg_len);
        if (ret < 0) {
            file_put(sock_file);
            return sent ? sent : ret;
        }
        if (copy_to_user((void *)(ent_ptr + offsetof(struct socket_mmsghdr,
                                                     msg_len)),
                         &msg_len, sizeof(msg_len)) < 0) {
            file_put(sock_file);
            return sent ? sent : -EFAULT;
        }
        sent++;
    }

    file_put(sock_file);
    return sent;
}

int64_t sys_recvmmsg(uint64_t fd, uint64_t msgvec_ptr, uint64_t vlen,
                     uint64_t flags, uint64_t timeout_ptr, uint64_t a5) {
    (void)a5;
    uint32_t uflags = syssock_abi_u32(flags);
    uint32_t uvlen = syssock_abi_u32(vlen);
    if (!uvlen) {
        return 0;
    }
    if (uvlen > SOCKET_MSG_IOV_MAX) {
        return -EINVAL;
    }

    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, FD_RIGHT_READ, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    uflags = socket_effective_msg_flags(sock_file, uflags);

    bool has_timeout = false;
    uint64_t deadline = 0;
    int timeout_rc = socket_copy_timeout_deadline(timeout_ptr, &has_timeout,
                                                  &deadline);
    if (timeout_rc < 0) {
        file_put(sock_file);
        return timeout_rc;
    }

    int recved = 0;
    for (uint32_t i = 0; i < uvlen; i++) {
        uint64_t ent_ptr = msgvec_ptr + i * sizeof(struct socket_mmsghdr);
        struct socket_mmsghdr msg = {0};
        if (copy_from_user(&msg.msg_hdr, (const void *)ent_ptr,
                           sizeof(msg.msg_hdr)) < 0) {
            file_put(sock_file);
            return recved ? recved : -EFAULT;
        }
        uint32_t recv_flags = uflags;
        if (recved > 0 && (uflags & MSG_WAITFORONE)) {
            recv_flags |= MSG_DONTWAIT;
        }

        bool timeout_managed = has_timeout && !(recv_flags & MSG_DONTWAIT);
        if (timeout_managed)
            recv_flags |= MSG_DONTWAIT;

    retry_recv:
        if (timeout_managed && arch_timer_get_ticks() >= deadline) {
            file_put(sock_file);
            return recved;
        }

        int64_t ret = socket_recvmsg(sock, &msg.msg_hdr, recv_flags, &msg.msg_len);
        if (ret < 0) {
            if (ret == -EAGAIN && timeout_managed) {
                int wait_rc = socket_wait_readable(sock, sock_file, true, deadline);
                if (wait_rc > 0)
                    goto retry_recv;
                file_put(sock_file);
                if (wait_rc == 0)
                    return recved;
                return recved ? recved : wait_rc;
            }
            file_put(sock_file);
            return recved ? recved : ret;
        }
        if (copy_to_user((void *)ent_ptr, &msg.msg_hdr,
                         sizeof(msg.msg_hdr)) < 0 ||
            copy_to_user((void *)(ent_ptr + offsetof(struct socket_mmsghdr,
                                                     msg_len)),
                         &msg.msg_len, sizeof(msg.msg_len)) < 0) {
            file_put(sock_file);
            return recved ? recved : -EFAULT;
        }
        recved++;
    }

    file_put(sock_file);
    return recved;
}

int64_t sys_getsockname(uint64_t fd, uint64_t addr, uint64_t addrlen_ptr,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, FD_RIGHT_READ, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->getsockname) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }

    uint32_t ulen_raw = 0;
    if (copy_from_user(&ulen_raw, (const void *)addrlen_ptr,
                       sizeof(ulen_raw)) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    int ulen = (int32_t)ulen_raw;
    if (ulen < 0) {
        file_put(sock_file);
        return -EINVAL;
    }

    struct sockaddr_storage kaddr;
    int klen = (int)sizeof(kaddr);
    int ret = sock->ops->getsockname(sock, (struct sockaddr *)&kaddr, &klen);
    if (ret < 0) {
        file_put(sock_file);
        return (int64_t)ret;
    }

    int copylen = (klen < ulen) ? klen : ulen;
    if (copy_to_user((void *)addr, &kaddr, (size_t)copylen) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    if (copy_to_user((void *)addrlen_ptr, &klen, sizeof(klen)) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    file_put(sock_file);
    return 0;
}

int64_t sys_getpeername(uint64_t fd, uint64_t addr, uint64_t addrlen_ptr,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, FD_RIGHT_READ, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->getpeername) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }

    uint32_t ulen_raw = 0;
    if (copy_from_user(&ulen_raw, (const void *)addrlen_ptr,
                       sizeof(ulen_raw)) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    int ulen = (int32_t)ulen_raw;
    if (ulen < 0) {
        file_put(sock_file);
        return -EINVAL;
    }

    struct sockaddr_storage kaddr;
    int klen = (int)sizeof(kaddr);
    int ret = sock->ops->getpeername(sock, (struct sockaddr *)&kaddr, &klen);
    if (ret < 0) {
        file_put(sock_file);
        return (int64_t)ret;
    }

    int copylen = (klen < ulen) ? klen : ulen;
    if (copy_to_user((void *)addr, &kaddr, (size_t)copylen) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    if (copy_to_user((void *)addrlen_ptr, &klen, sizeof(klen)) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    file_put(sock_file);
    return 0;
}

int64_t sys_setsockopt(uint64_t fd, uint64_t level, uint64_t optname,
                       uint64_t optval, uint64_t optlen, uint64_t a5) {
    (void)a5;
    int klevel = syssock_abi_i32(level);
    int koptname = syssock_abi_i32(optname);
    int klen = syssock_abi_i32(optlen);
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, 0, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->setsockopt) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }

    if (klen < 0 || klen > 256) {
        file_put(sock_file);
        return -EINVAL;
    }
    char kval[256];
    if (klen > 0 && optval) {
        if (copy_from_user(kval, (const void *)optval, (size_t)klen) < 0) {
            file_put(sock_file);
            return -EFAULT;
        }
    }
    int64_t ret =
        (int64_t)sock->ops->setsockopt(sock, klevel, koptname, kval, klen);
    file_put(sock_file);
    return ret;
}

int64_t sys_getsockopt(uint64_t fd, uint64_t level, uint64_t optname,
                       uint64_t optval, uint64_t optlen_ptr, uint64_t a5) {
    (void)a5;
    int klevel = syssock_abi_i32(level);
    int koptname = syssock_abi_i32(optname);
    struct process *p = proc_current();
    struct file *sock_file = NULL;
    struct socket *sock = sock_from_fd(p, fd, 0, &sock_file);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->getsockopt) {
        file_put(sock_file);
        return -EOPNOTSUPP;
    }

    uint32_t klen_raw = 0;
    if (copy_from_user(&klen_raw, (const void *)optlen_ptr,
                       sizeof(klen_raw)) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    int klen = (int32_t)klen_raw;
    if (klen < 0 || klen > 256) {
        file_put(sock_file);
        return -EINVAL;
    }

    char kval[256];
    int ret = sock->ops->getsockopt(sock, klevel, koptname, kval, &klen);
    if (ret < 0) {
        file_put(sock_file);
        return (int64_t)ret;
    }
    if (klen > 0 && optval) {
        if (copy_to_user((void *)optval, kval, (size_t)klen) < 0) {
            file_put(sock_file);
            return -EFAULT;
        }
    }
    if (copy_to_user((void *)optlen_ptr, &klen, sizeof(klen)) < 0) {
        file_put(sock_file);
        return -EFAULT;
    }
    file_put(sock_file);
    return 0;
}

int64_t sys_socketpair(uint64_t domain, uint64_t type, uint64_t protocol,
                       uint64_t sv_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p) {
        return -EINVAL;
    }

    int sock_domain = syssock_abi_i32(domain);
    int sock_type = syssock_abi_i32(type);
    int sock_protocol = syssock_abi_i32(protocol);
    int extra_flags = sock_type & (SOCK_NONBLOCK | SOCK_CLOEXEC);

    struct socket *sock0 = NULL, *sock1 = NULL;
    int ret = sock_create(sock_domain, sock_type, sock_protocol, &sock0);
    if (ret < 0) {
        return (int64_t)ret;
    }
    ret = sock_create(sock_domain, sock_type, sock_protocol, &sock1);
    if (ret < 0) {
        sock_destroy(sock0);
        return (int64_t)ret;
    }

    /* Cross-connect the pair for AF_UNIX */
    if (sock_domain == AF_UNIX) {
        ret = unix_socketpair_connect(sock0, sock1);
        if (ret < 0) {
            sock_destroy(sock0);
            sock_destroy(sock1);
            return (int64_t)ret;
        }
    }

    struct file *f0 = vfs_file_alloc();
    struct file *f1 = vfs_file_alloc();
    if (!f0 || !f1) {
        if (f0) {
            vfs_file_free(f0);
        }
        if (f1) {
            vfs_file_free(f1);
        }
        sock_destroy(sock0);
        sock_destroy(sock1);
        return -ENOMEM;
    }

    uint32_t file_flags = O_RDWR;
    if (extra_flags & SOCK_NONBLOCK) {
        file_flags |= O_NONBLOCK;
    }
    f0->vnode = sock0->vnode;
    vnode_get(sock0->vnode);
    f0->flags = file_flags;
    f1->vnode = sock1->vnode;
    vnode_get(sock1->vnode);
    f1->flags = file_flags;

    uint32_t fd_flags = (extra_flags & SOCK_CLOEXEC) ? FD_CLOEXEC : 0;
    int fd0 = fd_alloc_flags(p, f0, fd_flags);
    int fd1 = fd_alloc_flags(p, f1, fd_flags);
    if (fd0 < 0 || fd1 < 0) {
        if (fd0 >= 0) {
            fd_close(p, fd0);
        } else {
            vfs_close(f0);
        }
        if (fd1 >= 0) {
            fd_close(p, fd1);
        } else {
            vfs_close(f1);
        }
        sock_destroy(sock0);
        sock_destroy(sock1);
        return -EMFILE;
    }

    int sv[2] = {fd0, fd1};
    if (copy_to_user((void *)sv_ptr, sv, sizeof(sv)) < 0) {
        fd_close(p, fd0);
        fd_close(p, fd1);
        return -EFAULT;
    }
    return 0;
}
