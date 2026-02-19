/**
 * kernel/net/socket.c - Core socket abstraction layer
 */

#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/socket.h>
#include <kairos/string.h>
#include <kairos/vfs.h>

/* Protocol family table */
struct sock_family {
    const struct proto_ops *stream_ops;
    const struct proto_ops *dgram_ops;
};

#define MAX_AF 4
static struct sock_family families[MAX_AF];

int sock_register_family(int domain, const struct proto_ops *stream_ops,
                         const struct proto_ops *dgram_ops) {
    if (domain < 0 || domain >= MAX_AF) {
        return -EINVAL;
    }
    families[domain].stream_ops = stream_ops;
    families[domain].dgram_ops = dgram_ops;
    return 0;
}

/* Socket vnode file_ops */
static ssize_t socket_vnode_read(struct vnode *vn, void *buf, size_t len,
                                 off_t off, uint32_t flags) {
    (void)off;
    struct socket *sock = sock_from_vnode(vn);
    if (!sock || !sock->ops || !sock->ops->recvfrom) {
        return -EOPNOTSUPP;
    }
    int msg_flags = (flags & O_NONBLOCK) ? MSG_DONTWAIT : 0;
    return sock->ops->recvfrom(sock, buf, len, msg_flags, NULL, NULL);
}

static ssize_t socket_vnode_write(struct vnode *vn, const void *buf,
                                  size_t len, off_t off, uint32_t flags) {
    (void)off;
    struct socket *sock = sock_from_vnode(vn);
    if (!sock || !sock->ops || !sock->ops->sendto) {
        return -EOPNOTSUPP;
    }
    int msg_flags = (flags & O_NONBLOCK) ? MSG_DONTWAIT : 0;
    return sock->ops->sendto(sock, buf, len, msg_flags, NULL, 0);
}

static int socket_vnode_close(struct vnode *vn) {
    struct socket *sock = sock_from_vnode(vn);
    if (sock) {
        if (sock->ops && sock->ops->close) {
            sock->ops->close(sock);
        }
        kfree(sock);
        vn->fs_data = NULL;
    }
    return 0;
}

static int socket_vnode_poll(struct vnode *vn, uint32_t events) {
    struct socket *sock = sock_from_vnode(vn);
    if (!sock || !sock->ops || !sock->ops->poll) {
        return 0;
    }
    return sock->ops->poll(sock, events);
}

static struct file_ops socket_file_ops = {
    .read = socket_vnode_read,
    .write = socket_vnode_write,
    .close = socket_vnode_close,
    .poll = socket_vnode_poll,
};

struct socket *sock_from_vnode(struct vnode *vn) {
    if (!vn || vn->type != VNODE_SOCKET) {
        return NULL;
    }
    return (struct socket *)vn->fs_data;
}

int sock_create(int domain, int type, int protocol, struct socket **out) {
    if (!out) {
        return -EINVAL;
    }
    if (domain < 0 || domain >= MAX_AF) {
        return -EAFNOSUPPORT;
    }

    int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    const struct proto_ops *ops = NULL;
    if (base_type == SOCK_STREAM) {
        ops = families[domain].stream_ops;
    } else if (base_type == SOCK_DGRAM) {
        ops = families[domain].dgram_ops;
    }
    if (!ops) {
        return -EPROTONOSUPPORT;
    }

    struct socket *sock = kzalloc(sizeof(*sock));
    if (!sock) {
        return -ENOMEM;
    }

    struct vnode *vn = kzalloc(sizeof(*vn));
    if (!vn) {
        kfree(sock);
        return -ENOMEM;
    }

    sock->domain = domain;
    sock->type = base_type;
    sock->protocol = protocol;
    sock->state = SS_UNCONNECTED;
    sock->ops = ops;
    mutex_init(&sock->lock, "socket");
    poll_wait_head_init(&sock->pollers);

    vn->type = VNODE_SOCKET;
    vn->mode = S_IFSOCK | 0600;
    vn->nlink = 1;
    vn->ops = &socket_file_ops;
    vn->fs_data = sock;
    atomic_init(&vn->refcount, 1);
    vn->parent = NULL;
    vn->name[0] = '\0';
    rwlock_init(&vn->lock, "sock_vnode");
    poll_wait_head_init(&vn->pollers);

    sock->vnode = vn;
    *out = sock;
    return 0;
}

void sock_destroy(struct socket *sock) {
    if (!sock) {
        return;
    }
    if (sock->ops && sock->ops->close) {
        sock->ops->close(sock);
    }
    if (sock->vnode) {
        sock->vnode->fs_data = NULL;
        vnode_put(sock->vnode);
    }
    kfree(sock);
}
