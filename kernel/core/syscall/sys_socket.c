/**
 * kernel/core/syscall/sys_socket.c - Socket syscall handlers
 */

#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/socket.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

static struct socket *sock_from_fd(struct process *p, int fd) {
    struct file *f = fd_get(p, fd);
    if (!f || !f->vnode) {
        return NULL;
    }
    return sock_from_vnode(f->vnode);
}

static int copy_sockaddr_from_user(struct sockaddr_storage *kaddr,
                                   uint64_t uaddr, uint64_t ulen) {
    if (!uaddr || !ulen) {
        return 0;
    }
    int len = (int)ulen;
    if (len < 0 || (size_t)len > sizeof(*kaddr)) {
        return -EINVAL;
    }
    memset(kaddr, 0, sizeof(*kaddr));
    if (copy_from_user(kaddr, (const void *)uaddr, (size_t)len) < 0) {
        return -EFAULT;
    }
    return len;
}

int64_t sys_socket(uint64_t domain, uint64_t type, uint64_t protocol,
                   uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p) {
        return -EINVAL;
    }

    int sock_type = (int)type;
    int extra_flags = sock_type & (SOCK_NONBLOCK | SOCK_CLOEXEC);

    struct socket *sock = NULL;
    int ret = sock_create((int)domain, sock_type, (int)protocol, &sock);
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
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->bind) {
        return -EOPNOTSUPP;
    }

    struct sockaddr_storage kaddr;
    int len = copy_sockaddr_from_user(&kaddr, addr, addrlen);
    if (len < 0) {
        return (int64_t)len;
    }
    return (int64_t)sock->ops->bind(sock, (struct sockaddr *)&kaddr, len);
}

int64_t sys_listen(uint64_t fd, uint64_t backlog, uint64_t a2,
                   uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->listen) {
        return -EOPNOTSUPP;
    }
    return (int64_t)sock->ops->listen(sock, (int)backlog);
}

int64_t sys_accept(uint64_t fd, uint64_t addr, uint64_t addrlen_ptr,
                   uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->accept) {
        return -EOPNOTSUPP;
    }

    struct socket *newsock = NULL;
    int ret = sock->ops->accept(sock, &newsock);
    if (ret < 0) {
        return (int64_t)ret;
    }

    /* Copy peer address to user if requested */
    if (addr && addrlen_ptr && newsock->ops && newsock->ops->getpeername) {
        int ulen = 0;
        if (copy_from_user(&ulen, (const void *)addrlen_ptr,
                           sizeof(ulen)) == 0) {
            struct sockaddr_storage kaddr;
            int klen = (int)sizeof(kaddr);
            if (newsock->ops->getpeername(newsock, (struct sockaddr *)&kaddr,
                                          &klen) == 0) {
                int copylen = (klen < ulen) ? klen : ulen;
                copy_to_user((void *)addr, &kaddr, (size_t)copylen);
                copy_to_user((void *)addrlen_ptr, &klen, sizeof(klen));
            }
        }
    }

    struct file *file = vfs_file_alloc();
    if (!file) {
        sock_destroy(newsock);
        return -ENOMEM;
    }
    file->vnode = newsock->vnode;
    vnode_get(newsock->vnode);
    file->flags = O_RDWR;

    int newfd = fd_alloc(p, file);
    if (newfd < 0) {
        vfs_close(file);
        sock_destroy(newsock);
        return -EMFILE;
    }
    return newfd;
}

int64_t sys_connect(uint64_t fd, uint64_t addr, uint64_t addrlen,
                    uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->connect) {
        return -EOPNOTSUPP;
    }

    struct sockaddr_storage kaddr;
    int len = copy_sockaddr_from_user(&kaddr, addr, addrlen);
    if (len < 0) {
        return (int64_t)len;
    }
    return (int64_t)sock->ops->connect(sock, (struct sockaddr *)&kaddr, len);
}

int64_t sys_sendto(uint64_t fd, uint64_t buf, uint64_t len,
                   uint64_t flags, uint64_t dest, uint64_t addrlen) {
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->sendto) {
        return -EOPNOTSUPP;
    }

    struct sockaddr_storage kaddr;
    struct sockaddr *destp = NULL;
    int dlen = 0;
    if (dest) {
        dlen = copy_sockaddr_from_user(&kaddr, dest, addrlen);
        if (dlen < 0) {
            return (int64_t)dlen;
        }
        destp = (struct sockaddr *)&kaddr;
    }

    /* Copy data from user */
    if (!len) {
        return (int64_t)sock->ops->sendto(sock, NULL, 0, (int)flags,
                                          destp, dlen);
    }
    size_t klen = (size_t)len;
    if (klen > 65536) {
        klen = 65536;
    }
    void *kbuf = kmalloc(klen);
    if (!kbuf) {
        return -ENOMEM;
    }
    if (copy_from_user(kbuf, (const void *)buf, klen) < 0) {
        kfree(kbuf);
        return -EFAULT;
    }
    ssize_t ret = sock->ops->sendto(sock, kbuf, klen, (int)flags,
                                    destp, dlen);
    kfree(kbuf);
    return (int64_t)ret;
}

int64_t sys_recvfrom(uint64_t fd, uint64_t buf, uint64_t len,
                     uint64_t flags, uint64_t src, uint64_t addrlen_ptr) {
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->recvfrom) {
        return -EOPNOTSUPP;
    }

    size_t klen = (size_t)len;
    if (klen > 65536) {
        klen = 65536;
    }
    void *kbuf = kmalloc(klen);
    if (!kbuf) {
        return -ENOMEM;
    }

    struct sockaddr_storage kaddr;
    int alen = (int)sizeof(kaddr);
    ssize_t ret = sock->ops->recvfrom(sock, kbuf, klen, (int)flags,
                                      src ? (struct sockaddr *)&kaddr : NULL,
                                      src ? &alen : NULL);
    if (ret > 0) {
        if (copy_to_user((void *)buf, kbuf, (size_t)ret) < 0) {
            kfree(kbuf);
            return -EFAULT;
        }
    }
    kfree(kbuf);

    /* Copy source address to user */
    if (ret >= 0 && src && addrlen_ptr) {
        int ulen = 0;
        if (copy_from_user(&ulen, (const void *)addrlen_ptr,
                           sizeof(ulen)) == 0) {
            int copylen = (alen < ulen) ? alen : ulen;
            copy_to_user((void *)src, &kaddr, (size_t)copylen);
            copy_to_user((void *)addrlen_ptr, &alen, sizeof(alen));
        }
    }
    return (int64_t)ret;
}

int64_t sys_shutdown(uint64_t fd, uint64_t how, uint64_t a2,
                     uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->shutdown) {
        return -EOPNOTSUPP;
    }
    return (int64_t)sock->ops->shutdown(sock, (int)how);
}

int64_t sys_getsockname(uint64_t fd, uint64_t addr, uint64_t addrlen_ptr,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->getsockname) {
        return -EOPNOTSUPP;
    }

    int ulen = 0;
    if (copy_from_user(&ulen, (const void *)addrlen_ptr, sizeof(ulen)) < 0) {
        return -EFAULT;
    }

    struct sockaddr_storage kaddr;
    int klen = (int)sizeof(kaddr);
    int ret = sock->ops->getsockname(sock, (struct sockaddr *)&kaddr, &klen);
    if (ret < 0) {
        return (int64_t)ret;
    }

    int copylen = (klen < ulen) ? klen : ulen;
    if (copy_to_user((void *)addr, &kaddr, (size_t)copylen) < 0) {
        return -EFAULT;
    }
    if (copy_to_user((void *)addrlen_ptr, &klen, sizeof(klen)) < 0) {
        return -EFAULT;
    }
    return 0;
}

int64_t sys_getpeername(uint64_t fd, uint64_t addr, uint64_t addrlen_ptr,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->getpeername) {
        return -EOPNOTSUPP;
    }

    int ulen = 0;
    if (copy_from_user(&ulen, (const void *)addrlen_ptr, sizeof(ulen)) < 0) {
        return -EFAULT;
    }

    struct sockaddr_storage kaddr;
    int klen = (int)sizeof(kaddr);
    int ret = sock->ops->getpeername(sock, (struct sockaddr *)&kaddr, &klen);
    if (ret < 0) {
        return (int64_t)ret;
    }

    int copylen = (klen < ulen) ? klen : ulen;
    if (copy_to_user((void *)addr, &kaddr, (size_t)copylen) < 0) {
        return -EFAULT;
    }
    if (copy_to_user((void *)addrlen_ptr, &klen, sizeof(klen)) < 0) {
        return -EFAULT;
    }
    return 0;
}

int64_t sys_setsockopt(uint64_t fd, uint64_t level, uint64_t optname,
                       uint64_t optval, uint64_t optlen, uint64_t a5) {
    (void)a5;
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->setsockopt) {
        /* Silently succeed for unsupported options */
        return 0;
    }

    int klen = (int)optlen;
    if (klen < 0 || klen > 256) {
        return -EINVAL;
    }
    char kval[256];
    if (klen > 0 && optval) {
        if (copy_from_user(kval, (const void *)optval, (size_t)klen) < 0) {
            return -EFAULT;
        }
    }
    return (int64_t)sock->ops->setsockopt(sock, (int)level, (int)optname,
                                          kval, klen);
}

int64_t sys_getsockopt(uint64_t fd, uint64_t level, uint64_t optname,
                       uint64_t optval, uint64_t optlen_ptr, uint64_t a5) {
    (void)a5;
    struct process *p = proc_current();
    struct socket *sock = sock_from_fd(p, (int)fd);
    if (!sock) {
        return -ENOTSOCK;
    }
    if (!sock->ops || !sock->ops->getsockopt) {
        return -EOPNOTSUPP;
    }

    int klen = 0;
    if (copy_from_user(&klen, (const void *)optlen_ptr, sizeof(klen)) < 0) {
        return -EFAULT;
    }
    if (klen < 0 || klen > 256) {
        return -EINVAL;
    }

    char kval[256];
    int ret = sock->ops->getsockopt(sock, (int)level, (int)optname,
                                    kval, &klen);
    if (ret < 0) {
        return (int64_t)ret;
    }
    if (klen > 0 && optval) {
        if (copy_to_user((void *)optval, kval, (size_t)klen) < 0) {
            return -EFAULT;
        }
    }
    if (copy_to_user((void *)optlen_ptr, &klen, sizeof(klen)) < 0) {
        return -EFAULT;
    }
    return 0;
}

int64_t sys_socketpair(uint64_t domain, uint64_t type, uint64_t protocol,
                       uint64_t sv_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p) {
        return -EINVAL;
    }

    int sock_type = (int)type;
    int extra_flags = sock_type & (SOCK_NONBLOCK | SOCK_CLOEXEC);

    struct socket *sock0 = NULL, *sock1 = NULL;
    int ret = sock_create((int)domain, sock_type, (int)protocol, &sock0);
    if (ret < 0) {
        return (int64_t)ret;
    }
    ret = sock_create((int)domain, sock_type, (int)protocol, &sock1);
    if (ret < 0) {
        sock_destroy(sock0);
        return (int64_t)ret;
    }

    /* Cross-connect the pair for AF_UNIX */
    if ((int)domain == AF_UNIX) {
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
        }
        if (fd1 >= 0) {
            fd_close(p, fd1);
        }
        vfs_close(f0);
        vfs_close(f1);
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
