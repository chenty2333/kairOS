/**
 * kernel/net/af_unix.c - AF_UNIX (Unix domain) socket implementation
 *
 * Supports SOCK_STREAM (connection-oriented) and SOCK_DGRAM (connectionless).
 * STREAM mode uses a per-direction ring buffer similar to pipe.c.
 * DGRAM mode uses a simple message queue.
 */

#include <kairos/atomic.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/socket.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/vfs.h>
#include <kairos/wait.h>

#define UNIX_BUF_SIZE 16384
#define UNIX_DGRAM_MAX 65536
#define UNIX_BACKLOG_MAX 128
#define UNIX_SHUT_RD_BIT (1u << 0)
#define UNIX_SHUT_WR_BIT (1u << 1)

struct unix_sock;

/* Per-direction stream buffer */
struct unix_buf {
    uint8_t *data;
    size_t head;
    size_t tail;
    size_t count;
    struct wait_queue rwait;
    struct wait_queue wwait;
};

/* Datagram message in receive queue */
struct unix_dgram_msg {
    struct list_head node;
    size_t len;
    struct sockaddr_un sender;
    bool has_creds;
    struct socket_ucred creds;
    size_t rights_count;
    struct file *rights[SOCKET_MAX_RIGHTS];
    uint8_t data[];
};

/* STREAM ancillary control payload */
struct unix_stream_ctrl {
    struct list_head node;
    uint64_t attach_off;
    bool has_creds;
    struct socket_ucred creds;
    size_t rights_count;
    struct file *rights[SOCKET_MAX_RIGHTS];
};

/* Pending connection for accept queue */
struct unix_pending {
    struct list_head node;
    struct unix_sock *client;
};

struct unix_sock {
    struct socket *sock;
    char path[UNIX_PATH_MAX];
    bool bound;
    struct unix_sock *peer;

    /* STREAM data buffer (recv side — data written by peer) */
    struct unix_buf buf;
    int shutdown_flags;

    /* STREAM listen state */
    struct list_head accept_queue;
    int backlog;
    int pending_count;
    struct wait_queue accept_wait;

    /* DGRAM receive queue */
    struct list_head dgram_queue;
    int dgram_count;
    struct wait_queue dgram_wait;
    struct list_head stream_ctrl_queue;
    int stream_ctrl_count;
    uint64_t stream_rx_write_off;
    uint64_t stream_rx_read_off;

    struct mutex lock;
    atomic_t refcount;
    bool closing;
    int connect_err;
};

/* Global bound socket registry (simple linear scan) */
#define UNIX_BIND_TABLE_SIZE 64
static struct {
    struct mutex lock;
    struct unix_sock *entries[UNIX_BIND_TABLE_SIZE];
    bool init;
} unix_bind_table;

static void unix_sock_get(struct unix_sock *us) {
    if (us)
        atomic_inc(&us->refcount);
}

static void unix_sock_put(struct unix_sock *us) {
    if (!us)
        return;
    uint32_t cur = atomic_read(&us->refcount);
    if (cur == 0)
        panic("af_unix: unix_sock refcount underflow");
    uint32_t old = atomic_fetch_sub(&us->refcount, 1);
    if (old == 1)
        kfree(us);
}

static uint32_t unix_shutdown_mask(int how) {
    switch (how) {
    case SHUT_RD:
        return UNIX_SHUT_RD_BIT;
    case SHUT_WR:
        return UNIX_SHUT_WR_BIT;
    case SHUT_RDWR:
        return UNIX_SHUT_RD_BIT | UNIX_SHUT_WR_BIT;
    default:
        return 0;
    }
}

static void unix_bind_table_init(void) {
    if (unix_bind_table.init) {
        return;
    }
    mutex_init(&unix_bind_table.lock, "unix_bind");
    memset(unix_bind_table.entries, 0, sizeof(unix_bind_table.entries));
    unix_bind_table.init = true;
}

static struct unix_sock *unix_find_bound_locked(const char *path) {
    for (int i = 0; i < UNIX_BIND_TABLE_SIZE; i++) {
        struct unix_sock *us = unix_bind_table.entries[i];
        if (us && strcmp(us->path, path) == 0) {
            return us;
        }
    }
    return NULL;
}

static struct unix_sock *unix_find_bound_get_locked(const char *path) {
    struct unix_sock *us = unix_find_bound_locked(path);
    if (us)
        unix_sock_get(us);
    return us;
}

static int unix_add_bound(struct unix_sock *us) {
    for (int i = 0; i < UNIX_BIND_TABLE_SIZE; i++) {
        if (!unix_bind_table.entries[i]) {
            unix_bind_table.entries[i] = us;
            unix_sock_get(us);
            return 0;
        }
    }
    return -ENOMEM;
}

static void unix_remove_bound(struct unix_sock *us) {
    for (int i = 0; i < UNIX_BIND_TABLE_SIZE; i++) {
        if (unix_bind_table.entries[i] == us) {
            unix_bind_table.entries[i] = NULL;
            unix_sock_put(us);
            return;
        }
    }
}

static int unix_buf_init(struct unix_buf *b) {
    b->data = kmalloc(UNIX_BUF_SIZE);
    if (!b->data) {
        return -ENOMEM;
    }
    b->head = 0;
    b->tail = 0;
    b->count = 0;
    wait_queue_init(&b->rwait);
    wait_queue_init(&b->wwait);
    return 0;
}

static void unix_buf_destroy(struct unix_buf *b) {
    if (b->data) {
        kfree(b->data);
        b->data = NULL;
    }
}

static struct unix_sock *unix_sock_alloc(struct socket *sock) {
    struct unix_sock *us = kzalloc(sizeof(*us));
    if (!us) {
        return NULL;
    }
    us->sock = sock;
    us->path[0] = '\0';
    us->bound = false;
    us->peer = NULL;
    us->buf.data = NULL;
    us->buf.head = 0;
    us->buf.tail = 0;
    us->buf.count = 0;
    wait_queue_init(&us->buf.rwait);
    wait_queue_init(&us->buf.wwait);
    us->shutdown_flags = 0;
    INIT_LIST_HEAD(&us->accept_queue);
    us->backlog = 0;
    us->pending_count = 0;
    wait_queue_init(&us->accept_wait);
    INIT_LIST_HEAD(&us->dgram_queue);
    us->dgram_count = 0;
    wait_queue_init(&us->dgram_wait);
    INIT_LIST_HEAD(&us->stream_ctrl_queue);
    us->stream_ctrl_count = 0;
    us->stream_rx_write_off = 0;
    us->stream_rx_read_off = 0;
    mutex_init(&us->lock, "unix_sock");
    atomic_init(&us->refcount, 1);
    us->closing = false;
    us->connect_err = 0;
    sock->proto_data = us;
    return us;
}

/* --- Ring buffer read/write (STREAM) --- */

static ssize_t unix_buf_read(struct unix_buf *b, struct mutex *lock,
                              void *buf, size_t len, int shutdown,
                              struct unix_sock *peer, bool nonblock) {
    size_t total = 0;

    mutex_lock(lock);
    while (total < len) {
        while (b->count == 0) {
            if ((shutdown & (int)UNIX_SHUT_RD_BIT) || !peer || peer->closing) {
                mutex_unlock(lock);
                return (ssize_t)total;
            }
            if (nonblock) {
                mutex_unlock(lock);
                return total ? (ssize_t)total : -EAGAIN;
            }
            int rc = proc_sleep_on_mutex(&b->rwait, &b->rwait,
                                         lock, true);
            if (rc == -EINTR) {
                mutex_unlock(lock);
                return total ? (ssize_t)total : -EINTR;
            }
        }

        size_t want = len - total;
        size_t can = (b->count < want) ? b->count : want;
        size_t tail_space = UNIX_BUF_SIZE - b->tail;
        size_t n1 = (can < tail_space) ? can : tail_space;
        memcpy((uint8_t *)buf + total, b->data + b->tail, n1);
        b->tail = (b->tail + n1) % UNIX_BUF_SIZE;
        b->count -= n1;
        total += n1;

        size_t n2 = can - n1;
        if (n2) {
            memcpy((uint8_t *)buf + total, b->data + b->tail, n2);
            b->tail = (b->tail + n2) % UNIX_BUF_SIZE;
            b->count -= n2;
            total += n2;
        }

        wait_queue_wakeup_one(&b->wwait);
        break; /* STREAM: return as soon as we have data */
    }
    mutex_unlock(lock);
    return (ssize_t)total;
}

static ssize_t unix_buf_write_locked(struct unix_buf *b, struct mutex *lock,
                                     const void *buf, size_t len,
                                     int *shutdown_flags, bool nonblock) {
    size_t total = 0;

    while (total < len) {
        if (*shutdown_flags & (int)UNIX_SHUT_RD_BIT) {
            struct process *curr = proc_current();
            if (curr) {
                signal_send(curr->pid, SIGPIPE);
            }
            return total ? (ssize_t)total : -EPIPE;
        }

        size_t space = UNIX_BUF_SIZE - b->count;
        if (space == 0) {
            if (nonblock) {
                return total ? (ssize_t)total : -EAGAIN;
            }
            int rc = proc_sleep_on_mutex(&b->wwait, &b->wwait,
                                         lock, true);
            if (rc == -EINTR) {
                return total ? (ssize_t)total : -EINTR;
            }
            continue;
        }

        size_t want = len - total;
        size_t can = (space < want) ? space : want;
        size_t head_space = UNIX_BUF_SIZE - b->head;
        size_t n1 = (can < head_space) ? can : head_space;
        memcpy(b->data + b->head, (const uint8_t *)buf + total, n1);
        b->head = (b->head + n1) % UNIX_BUF_SIZE;
        b->count += n1;
        total += n1;

        size_t n2 = can - n1;
        if (n2) {
            memcpy(b->data + b->head, (const uint8_t *)buf + total, n2);
            b->head = (b->head + n2) % UNIX_BUF_SIZE;
            b->count += n2;
            total += n2;
        }

        wait_queue_wakeup_one(&b->rwait);
    }
    return (ssize_t)total;
}

static void unix_stream_ctrl_release(struct unix_stream_ctrl *msg) {
    if (!msg)
        return;
    for (size_t i = 0; i < msg->rights_count && i < SOCKET_MAX_RIGHTS; i++) {
        if (msg->rights[i]) {
            file_put(msg->rights[i]);
            msg->rights[i] = NULL;
        }
    }
    msg->rights_count = 0;
    msg->has_creds = false;
}

static int unix_stream_ctrl_from_send(const struct socket_control *control,
                                      struct unix_stream_ctrl **out) {
    if (!out)
        return -EINVAL;
    *out = NULL;
    if (!control || (!control->has_creds && control->rights_count == 0))
        return 0;
    if (control->rights_count > SOCKET_MAX_RIGHTS)
        return -EINVAL;

    struct unix_stream_ctrl *msg = kzalloc(sizeof(*msg));
    if (!msg)
        return -ENOMEM;
    INIT_LIST_HEAD(&msg->node);
    msg->attach_off = 0;
    msg->has_creds = control->has_creds;
    msg->creds = control->creds;
    msg->rights_count = control->rights_count;
    for (size_t i = 0; i < msg->rights_count; i++) {
        if (!control->rights[i]) {
            unix_stream_ctrl_release(msg);
            kfree(msg);
            return -EINVAL;
        }
        file_get(control->rights[i]);
        msg->rights[i] = control->rights[i];
    }
    *out = msg;
    return 0;
}

static void unix_stream_ctrl_move_to_recv(struct socket_control *control,
                                          struct unix_stream_ctrl *msg) {
    if (!control || !msg)
        return;
    if (control->has_creds || control->rights_count > 0)
        return;

    control->has_creds = msg->has_creds;
    control->creds = msg->creds;
    control->rights_count = msg->rights_count;
    if (control->rights_count > SOCKET_MAX_RIGHTS)
        control->rights_count = SOCKET_MAX_RIGHTS;
    for (size_t i = 0; i < control->rights_count; i++) {
        control->rights[i] = msg->rights[i];
        msg->rights[i] = NULL;
    }
    msg->rights_count = 0;
    msg->has_creds = false;
}

static void unix_stream_ctrl_consume_locked(struct unix_sock *us,
                                            size_t consumed,
                                            struct socket_control *control) {
    if (!us || consumed == 0)
        return;

    uint64_t start = us->stream_rx_read_off;
    uint64_t end = start + (uint64_t)consumed;
    if (end < start)
        end = UINT64_MAX;
    us->stream_rx_read_off = end;

    while (!list_empty(&us->stream_ctrl_queue)) {
        struct unix_stream_ctrl *msg = list_first_entry(
            &us->stream_ctrl_queue, struct unix_stream_ctrl, node);
        if (msg->attach_off >= end)
            break;
        list_del(&msg->node);
        if (us->stream_ctrl_count > 0)
            us->stream_ctrl_count--;
        if (msg->attach_off >= start)
            unix_stream_ctrl_move_to_recv(control, msg);
        unix_stream_ctrl_release(msg);
        kfree(msg);
    }
}

static void unix_stream_post_recv(struct unix_sock *us, ssize_t ret,
                                  struct socket_control *control) {
    if (!us || ret <= 0)
        return;
    mutex_lock(&us->lock);
    unix_stream_ctrl_consume_locked(us, (size_t)ret, control);
    mutex_unlock(&us->lock);
}

/* --- Proto ops (STREAM) --- */

static int unix_bind(struct socket *sock, const struct sockaddr *addr,
                     int addrlen) {
    struct unix_sock *us = sock->proto_data;
    const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;

    if (!sun || addrlen < (int)sizeof(sun->sun_family) + 1) {
        return -EINVAL;
    }
    if (sun->sun_family != AF_UNIX) {
        return -EINVAL;
    }

    mutex_lock(&unix_bind_table.lock);
    if (us->bound) {
        mutex_unlock(&unix_bind_table.lock);
        return -EINVAL;
    }
    struct unix_sock *existing = unix_find_bound_get_locked(sun->sun_path);
    if (existing) {
        mutex_unlock(&unix_bind_table.lock);
        unix_sock_put(existing);
        return -EADDRINUSE;
    }

    size_t pathlen = (size_t)addrlen - offsetof(struct sockaddr_un, sun_path);
    if (pathlen >= UNIX_PATH_MAX) {
        pathlen = UNIX_PATH_MAX - 1;
    }
    memcpy(us->path, sun->sun_path, pathlen);
    us->path[pathlen] = '\0';
    us->bound = true;

    int ret = unix_add_bound(us);
    mutex_unlock(&unix_bind_table.lock);
    if (ret < 0) {
        us->bound = false;
        return ret;
    }

    sock->state = SS_BOUND;
    return 0;
}

static int unix_stream_listen(struct socket *sock, int backlog) {
    struct unix_sock *us = sock->proto_data;

    if (sock->type != SOCK_STREAM) {
        return -EOPNOTSUPP;
    }
    if (!us->bound) {
        return -EINVAL;
    }

    mutex_lock(&us->lock);
    if (backlog < 1) {
        backlog = 1;
    }
    if (backlog > UNIX_BACKLOG_MAX) {
        backlog = UNIX_BACKLOG_MAX;
    }
    us->backlog = backlog;
    sock->state = SS_LISTENING;
    mutex_unlock(&us->lock);
    return 0;
}

static int unix_stream_connect(struct socket *sock, const struct sockaddr *addr,
                               int addrlen, int flags) {
    struct unix_sock *us = sock->proto_data;
    const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;
    struct unix_sock *listener = NULL;
    struct unix_pending *pend = NULL;
    int ret = 0;
    bool nonblock = (flags & MSG_DONTWAIT) != 0;

    if (!sun || addrlen < (int)sizeof(sun->sun_family) + 1) {
        return -EINVAL;
    }
    if (sun->sun_family != AF_UNIX) {
        return -EINVAL;
    }
    if (sock->state == SS_CONNECTED) {
        return -EISCONN;
    }
    if (sock->state == SS_CONNECTING) {
        mutex_lock(&us->lock);
        if (us->peer) {
            sock->state = SS_CONNECTED;
            mutex_unlock(&us->lock);
            return -EISCONN;
        }
        if (us->connect_err != 0 || us->closing) {
            ret = us->connect_err ? us->connect_err : -ECONNABORTED;
            sock->state = SS_UNCONNECTED;
            mutex_unlock(&us->lock);
            return ret;
        }
        if (nonblock) {
            mutex_unlock(&us->lock);
            return -EALREADY;
        }
        while (!us->peer && us->connect_err == 0 && !us->closing) {
            int rc = proc_sleep_on_mutex(&us->buf.rwait, &us->buf.rwait,
                                         &us->lock, true);
            if (rc == -EINTR) {
                mutex_unlock(&us->lock);
                return -EINTR;
            }
        }
        if (!us->peer && us->connect_err == 0 && us->closing)
            ret = -ECONNABORTED;
        else
            ret = us->connect_err;
        if (!ret && us->peer)
            sock->state = SS_CONNECTED;
        else
            sock->state = SS_UNCONNECTED;
        mutex_unlock(&us->lock);
        return ret;
    }

    mutex_lock(&unix_bind_table.lock);
    listener = unix_find_bound_get_locked(sun->sun_path);
    mutex_unlock(&unix_bind_table.lock);
    if (!listener) {
        return -ECONNREFUSED;
    }

    mutex_lock(&listener->lock);
    bool listener_ok =
        !listener->closing && listener->sock &&
        listener->sock->state == SS_LISTENING &&
        listener->pending_count < listener->backlog;
    mutex_unlock(&listener->lock);
    if (!listener_ok) {
        unix_sock_put(listener);
        return -ECONNREFUSED;
    }

    if (!us->buf.data) {
        ret = unix_buf_init(&us->buf);
        if (ret < 0) {
            unix_sock_put(listener);
            return ret;
        }
    }

    pend = kzalloc(sizeof(*pend));
    if (!pend) {
        unix_sock_put(listener);
        return -ENOMEM;
    }
    pend->client = us;
    unix_sock_get(us);
    INIT_LIST_HEAD(&pend->node);

    mutex_lock(&listener->lock);
    if (listener->closing || !listener->sock ||
        listener->sock->state != SS_LISTENING ||
        listener->pending_count >= listener->backlog) {
        mutex_unlock(&listener->lock);
        unix_sock_put(us);
        kfree(pend);
        unix_sock_put(listener);
        return -ECONNREFUSED;
    }
    list_add_tail(&pend->node, &listener->accept_queue);
    listener->pending_count++;
    wait_queue_wakeup_one(&listener->accept_wait);
    if (listener->sock)
        poll_wait_wake(&listener->sock->pollers, POLLIN);
    mutex_unlock(&listener->lock);

    mutex_lock(&us->lock);
    us->connect_err = 0;
    sock->state = SS_CONNECTING;
    if (nonblock) {
        mutex_unlock(&us->lock);
        unix_sock_put(listener);
        return -EINPROGRESS;
    }
    while (!us->peer) {
        if (us->closing) {
            ret = -ECONNABORTED;
            break;
        }
        if (us->connect_err != 0) {
            ret = us->connect_err;
            break;
        }
        int rc = proc_sleep_on_mutex(&us->buf.rwait, &us->buf.rwait,
                                     &us->lock, true);
        if (rc == -EINTR) {
            mutex_unlock(&us->lock);
            unix_sock_put(listener);
            return -EINTR;
        }
    }
    if (!ret && us->peer)
        sock->state = SS_CONNECTED;
    else
        sock->state = SS_UNCONNECTED;
    mutex_unlock(&us->lock);
    unix_sock_put(listener);
    return ret;
}

static int unix_stream_accept(struct socket *sock, struct socket **newsock,
                              int flags) {
    struct unix_sock *us = sock->proto_data;
    bool nonblock = (flags & MSG_DONTWAIT) != 0;

    if (sock->type != SOCK_STREAM || sock->state != SS_LISTENING) {
        return -EINVAL;
    }

    while (1) {
        mutex_lock(&us->lock);
        while (list_empty(&us->accept_queue)) {
            if (nonblock) {
                mutex_unlock(&us->lock);
                return -EAGAIN;
            }
            int rc = proc_sleep_on_mutex(&us->accept_wait, &us->accept_wait,
                                         &us->lock, true);
            if (rc == -EINTR) {
                mutex_unlock(&us->lock);
                return -EINTR;
            }
        }

        struct unix_pending *pend = list_first_entry(&us->accept_queue,
                                                     struct unix_pending, node);
        list_del(&pend->node);
        us->pending_count--;
        mutex_unlock(&us->lock);

        struct unix_sock *client = pend->client;
        pend->client = NULL;
        kfree(pend);
        if (!client)
            continue;

        mutex_lock(&client->lock);
        bool client_closing = client->closing;
        mutex_unlock(&client->lock);
        if (client_closing) {
            unix_sock_put(client);
            continue;
        }

        struct socket *svr = NULL;
        int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &svr);
        if (ret < 0) {
            mutex_lock(&client->lock);
            if (!client->peer && client->connect_err == 0) {
                client->connect_err = -ECONNABORTED;
                if (client->sock)
                    client->sock->state = SS_UNCONNECTED;
            }
            wait_queue_wakeup_all(&client->buf.rwait);
            if (client->sock)
                poll_wait_wake(&client->sock->pollers, POLLOUT | POLLERR);
            mutex_unlock(&client->lock);
            unix_sock_put(client);
            return ret;
        }

        struct unix_sock *svr_us = svr->proto_data;
        if (!svr_us) {
            svr_us = unix_sock_alloc(svr);
            if (!svr_us) {
                sock_destroy(svr);
                mutex_lock(&client->lock);
                if (!client->peer && client->connect_err == 0) {
                    client->connect_err = -ECONNABORTED;
                    if (client->sock)
                        client->sock->state = SS_UNCONNECTED;
                }
                wait_queue_wakeup_all(&client->buf.rwait);
                if (client->sock)
                    poll_wait_wake(&client->sock->pollers, POLLOUT | POLLERR);
                mutex_unlock(&client->lock);
                unix_sock_put(client);
                return -ENOMEM;
            }
        }

        ret = unix_buf_init(&svr_us->buf);
        if (ret < 0) {
            sock_destroy(svr);
            mutex_lock(&client->lock);
            if (!client->peer && client->connect_err == 0) {
                client->connect_err = ret;
                if (client->sock)
                    client->sock->state = SS_UNCONNECTED;
            }
            wait_queue_wakeup_all(&client->buf.rwait);
            if (client->sock)
                poll_wait_wake(&client->sock->pollers, POLLOUT | POLLERR);
            mutex_unlock(&client->lock);
            unix_sock_put(client);
            return ret;
        }

        mutex_lock(&client->lock);
        if (client->closing) {
            mutex_unlock(&client->lock);
            sock_destroy(svr);
            unix_sock_put(client);
            continue;
        }
        unix_sock_get(svr_us);
        client->peer = svr_us;
        client->connect_err = 0;
        if (client->sock)
            client->sock->state = SS_CONNECTED;
        unix_sock_get(client);
        svr_us->peer = client;
        svr->state = SS_CONNECTED;
        wait_queue_wakeup_all(&client->buf.rwait);
        if (client->sock)
            poll_wait_wake(&client->sock->pollers, POLLOUT | POLLIN);
        mutex_unlock(&client->lock);

        unix_sock_put(client);
        *newsock = svr;
        return 0;
    }
}

static ssize_t unix_stream_sendto(struct socket *sock, const void *buf,
                                   size_t len, int flags,
                                   const struct sockaddr *dest, int addrlen) {
    (void)dest;
    (void)addrlen;
    struct unix_sock *us = sock->proto_data;
    struct unix_sock *peer = NULL;
    bool nonblock = (flags & MSG_DONTWAIT) != 0;

    mutex_lock(&us->lock);
    if (sock->state != SS_CONNECTED || us->closing || !us->peer) {
        mutex_unlock(&us->lock);
        return -ENOTCONN;
    }
    if (us->shutdown_flags & (int)UNIX_SHUT_WR_BIT) {
        mutex_unlock(&us->lock);
        if (!(flags & MSG_NOSIGNAL)) {
            struct process *curr = proc_current();
            if (curr)
                signal_send(curr->pid, SIGPIPE);
        }
        return -EPIPE;
    }
    peer = us->peer;
    unix_sock_get(peer);
    mutex_unlock(&us->lock);

    ssize_t ret = 0;
    mutex_lock(&peer->lock);
    if (peer->closing || !peer->buf.data) {
        ret = -ENOTCONN;
    } else {
        ret = unix_buf_write_locked(&peer->buf, &peer->lock, buf, len,
                                    &peer->shutdown_flags, nonblock);
        if (ret > 0)
            peer->stream_rx_write_off += (uint64_t)ret;
    }
    mutex_unlock(&peer->lock);

    unix_sock_put(peer);
    return ret;
}

static ssize_t unix_stream_recvfrom(struct socket *sock, void *buf,
                                     size_t len, int flags,
                                     struct sockaddr *src, int *addrlen) {
    (void)src;
    (void)addrlen;
    struct unix_sock *us = sock->proto_data;
    struct unix_sock *peer = NULL;
    int shutdown_flags = 0;
    bool nonblock = (flags & MSG_DONTWAIT) != 0;

    mutex_lock(&us->lock);
    if (sock->state != SS_CONNECTED || us->closing) {
        mutex_unlock(&us->lock);
        return -ENOTCONN;
    }
    shutdown_flags = us->shutdown_flags;
    peer = us->peer;
    if (peer)
        unix_sock_get(peer);
    mutex_unlock(&us->lock);

    ssize_t ret = unix_buf_read(&us->buf, &us->lock, buf, len,
                                shutdown_flags, peer, nonblock);
    if (peer)
        unix_sock_put(peer);
    return ret;
}

static int unix_stream_poll(struct socket *sock, uint32_t events) {
    struct unix_sock *us = sock->proto_data;
    struct unix_sock *peer = NULL;
    uint32_t revents = 0;

    mutex_lock(&us->lock);
    if (sock->state == SS_LISTENING) {
        if (!list_empty(&us->accept_queue)) {
            revents |= POLLIN;
        }
    } else if (sock->state == SS_CONNECTING) {
        if (us->peer) {
            revents |= POLLOUT;
        } else if (us->connect_err != 0 || us->closing) {
            revents |= POLLOUT | POLLERR;
        }
    } else if (sock->state == SS_UNCONNECTED) {
        if (us->connect_err != 0)
            revents |= POLLOUT | POLLERR;
    } else if (sock->state == SS_CONNECTED) {
        if (us->buf.count > 0 || !us->peer || us->closing)
            revents |= POLLIN;
        if (!us->peer || (us->shutdown_flags & (int)UNIX_SHUT_RD_BIT) ||
            us->closing) {
            revents |= POLLHUP;
        }
        peer = us->peer;
        if (peer)
            unix_sock_get(peer);
    }
    mutex_unlock(&us->lock);

    if (peer) {
        mutex_lock(&peer->lock);
        if (!peer->closing && peer->buf.count < UNIX_BUF_SIZE)
            revents |= POLLOUT;
        if (peer->closing)
            revents |= POLLHUP;
        mutex_unlock(&peer->lock);
        unix_sock_put(peer);
    }

    return (int)(revents & events);
}

/* --- Proto ops (DGRAM) --- */

static ssize_t unix_dgram_recvmsg(struct socket *sock, void *buf,
                                  size_t len, int flags,
                                  struct sockaddr *src, int *addrlen,
                                  struct socket_control *control);

static void unix_dgram_msg_release_control(struct unix_dgram_msg *msg) {
    if (!msg)
        return;
    for (size_t i = 0; i < msg->rights_count && i < SOCKET_MAX_RIGHTS; i++) {
        if (msg->rights[i]) {
            file_put(msg->rights[i]);
            msg->rights[i] = NULL;
        }
    }
    msg->rights_count = 0;
    msg->has_creds = false;
}

static ssize_t unix_dgram_sendmsg(struct socket *sock, const void *buf,
                                  size_t len, int flags,
                                  const struct sockaddr *dest, int addrlen,
                                  const struct socket_control *control) {
    (void)flags;
    struct unix_sock *us = sock->proto_data;
    const struct sockaddr_un *sun = (const struct sockaddr_un *)dest;
    struct unix_sock *target = NULL;
    char sender_path[UNIX_PATH_MAX];
    bool sender_bound = false;

    if (!dest) {
        mutex_lock(&us->lock);
        if (us->closing) {
            mutex_unlock(&us->lock);
            return -ENOTCONN;
        }
        target = us->peer;
        if (target)
            unix_sock_get(target);
        mutex_unlock(&us->lock);
    } else if (sun && addrlen >= (int)sizeof(sun->sun_family) + 1 &&
               sun->sun_family == AF_UNIX) {
        mutex_lock(&unix_bind_table.lock);
        target = unix_find_bound_get_locked(sun->sun_path);
        mutex_unlock(&unix_bind_table.lock);
    }

    if (!target) {
        return -ENOTCONN;
    }
    if (len > UNIX_DGRAM_MAX) {
        return -EMSGSIZE;
    }

    struct unix_dgram_msg *msg = kmalloc(sizeof(*msg) + len);
    if (!msg) {
        unix_sock_put(target);
        return -ENOMEM;
    }
    memset(msg, 0, sizeof(*msg));
    msg->len = len;
    memset(&msg->sender, 0, sizeof(msg->sender));
    msg->sender.sun_family = AF_UNIX;
    if (control) {
        msg->has_creds = control->has_creds;
        msg->creds = control->creds;
        msg->rights_count =
            (control->rights_count > SOCKET_MAX_RIGHTS)
                ? SOCKET_MAX_RIGHTS
                : control->rights_count;
        for (size_t i = 0; i < msg->rights_count; i++) {
            if (control->rights[i]) {
                file_get(control->rights[i]);
                msg->rights[i] = control->rights[i];
            }
        }
    }

    mutex_lock(&us->lock);
    sender_bound = us->bound;
    if (sender_bound) {
        strncpy(sender_path, us->path, sizeof(sender_path) - 1);
        sender_path[sizeof(sender_path) - 1] = '\0';
    }
    mutex_unlock(&us->lock);
    if (sender_bound) {
        size_t plen = strlen(sender_path);
        if (plen >= UNIX_PATH_MAX) {
            plen = UNIX_PATH_MAX - 1;
        }
        memcpy(msg->sender.sun_path, sender_path, plen);
        msg->sender.sun_path[plen] = '\0';
    }
    memcpy(msg->data, buf, len);

    mutex_lock(&target->lock);
    if (target->closing) {
        mutex_unlock(&target->lock);
        unix_dgram_msg_release_control(msg);
        kfree(msg);
        unix_sock_put(target);
        return -ECONNREFUSED;
    }
    list_add_tail(&msg->node, &target->dgram_queue);
    target->dgram_count++;
    wait_queue_wakeup_one(&target->dgram_wait);
    if (target->sock)
        poll_wait_wake(&target->sock->pollers, POLLIN);
    mutex_unlock(&target->lock);

    unix_sock_put(target);
    return (ssize_t)len;
}

static ssize_t unix_dgram_sendto(struct socket *sock, const void *buf,
                                 size_t len, int flags,
                                 const struct sockaddr *dest, int addrlen) {
    return unix_dgram_sendmsg(sock, buf, len, flags, dest, addrlen, NULL);
}

static ssize_t unix_dgram_recvmsg(struct socket *sock, void *buf,
                                  size_t len, int flags,
                                  struct sockaddr *src, int *addrlen,
                                  struct socket_control *control) {
    bool nonblock = (flags & MSG_DONTWAIT) != 0;
    struct unix_sock *us = sock->proto_data;

    if (control) {
        memset(control, 0, sizeof(*control));
    }

    mutex_lock(&us->lock);
    while (list_empty(&us->dgram_queue)) {
        if (us->closing) {
            mutex_unlock(&us->lock);
            return -ENOTCONN;
        }
        if (nonblock) {
            mutex_unlock(&us->lock);
            return -EAGAIN;
        }
        int rc = proc_sleep_on_mutex(&us->dgram_wait, &us->dgram_wait,
                                     &us->lock, true);
        if (rc == -EINTR) {
            mutex_unlock(&us->lock);
            return -EINTR;
        }
    }

    struct unix_dgram_msg *msg = list_first_entry(&us->dgram_queue,
                                                   struct unix_dgram_msg, node);
    list_del(&msg->node);
    us->dgram_count--;
    mutex_unlock(&us->lock);

    size_t copylen = (msg->len < len) ? msg->len : len;
    memcpy(buf, msg->data, copylen);

    if (src && addrlen) {
        int slen = (int)sizeof(struct sockaddr_un);
        if (*addrlen < slen) {
            slen = *addrlen;
        }
        memcpy(src, &msg->sender, (size_t)slen);
        *addrlen = (int)sizeof(struct sockaddr_un);
    }

    if (control) {
        control->has_creds = msg->has_creds;
        control->creds = msg->creds;
        control->rights_count = msg->rights_count;
        if (control->rights_count > SOCKET_MAX_RIGHTS)
            control->rights_count = SOCKET_MAX_RIGHTS;
        for (size_t i = 0; i < control->rights_count; i++) {
            control->rights[i] = msg->rights[i];
            msg->rights[i] = NULL;
        }
        msg->rights_count = 0;
        msg->has_creds = false;
    }

    ssize_t ret = (ssize_t)msg->len;
    unix_dgram_msg_release_control(msg);
    kfree(msg);
    return ret;
}

static ssize_t unix_dgram_recvfrom(struct socket *sock, void *buf,
                                   size_t len, int flags,
                                   struct sockaddr *src, int *addrlen) {
    return unix_dgram_recvmsg(sock, buf, len, flags, src, addrlen, NULL);
}

static int unix_dgram_connect(struct socket *sock, const struct sockaddr *addr,
                              int addrlen, int flags) {
    (void)flags;
    struct unix_sock *us = sock->proto_data;
    const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;

    if (!sun || addrlen < (int)sizeof(sun->sun_family) + 1 ||
        sun->sun_family != AF_UNIX) {
        return -EINVAL;
    }

    mutex_lock(&unix_bind_table.lock);
    struct unix_sock *target = unix_find_bound_get_locked(sun->sun_path);
    mutex_unlock(&unix_bind_table.lock);

    if (!target) {
        return -ECONNREFUSED;
    }
    mutex_lock(&target->lock);
    bool target_closing = target->closing;
    mutex_unlock(&target->lock);
    if (target_closing) {
        unix_sock_put(target);
        return -ECONNREFUSED;
    }

    struct unix_sock *old_peer = NULL;
    mutex_lock(&us->lock);
    if (us->closing) {
        mutex_unlock(&us->lock);
        unix_sock_put(target);
        return -ENOTCONN;
    }
    old_peer = us->peer;
    us->peer = target;
    sock->state = SS_CONNECTED;
    mutex_unlock(&us->lock);
    if (old_peer && old_peer != target)
        unix_sock_put(old_peer);
    if (old_peer == target)
        unix_sock_put(target);
    return 0;
}

static int unix_dgram_poll(struct socket *sock, uint32_t events) {
    struct unix_sock *us = sock->proto_data;
    uint32_t revents = 0;

    mutex_lock(&us->lock);
    if (!list_empty(&us->dgram_queue) || us->closing) {
        revents |= POLLIN;
    }
    if (!us->closing)
        revents |= POLLOUT;
    else
        revents |= POLLHUP;
    mutex_unlock(&us->lock);

    return (int)(revents & events);
}

/* --- Common ops --- */

static int unix_shutdown(struct socket *sock, int how) {
    struct unix_sock *us = sock->proto_data;
    struct unix_sock *peer = NULL;
    uint32_t mask = unix_shutdown_mask(how);
    if (mask == 0)
        return -EINVAL;

    mutex_lock(&us->lock);
    if (us->closing) {
        mutex_unlock(&us->lock);
        return -ENOTCONN;
    }
    us->shutdown_flags |= (int)mask;
    peer = us->peer;
    if (peer)
        unix_sock_get(peer);
    wait_queue_wakeup_all(&us->buf.rwait);
    wait_queue_wakeup_all(&us->buf.wwait);
    mutex_unlock(&us->lock);

    if (peer) {
        mutex_lock(&peer->lock);
        wait_queue_wakeup_all(&peer->buf.rwait);
        wait_queue_wakeup_all(&peer->buf.wwait);
        if (peer->sock)
            poll_wait_wake(&peer->sock->pollers, POLLHUP);
        mutex_unlock(&peer->lock);
        unix_sock_put(peer);
    }
    if (sock)
        poll_wait_wake(&sock->pollers, POLLHUP);
    return 0;
}

static int unix_close(struct socket *sock) {
    struct unix_sock *us = sock->proto_data;
    if (!us) {
        return 0;
    }

    struct unix_sock *peer = NULL;
    bool drop_peer_ref_on_us = false;
    mutex_lock(&us->lock);
    if (us->closing) {
        mutex_unlock(&us->lock);
        sock->proto_data = NULL;
        return 0;
    }
    us->closing = true;
    peer = us->peer;
    us->peer = NULL;
    wait_queue_wakeup_all(&us->buf.rwait);
    wait_queue_wakeup_all(&us->buf.wwait);
    wait_queue_wakeup_all(&us->dgram_wait);
    mutex_unlock(&us->lock);

    if (us->bound) {
        mutex_lock(&unix_bind_table.lock);
        if (us->bound) {
            us->bound = false;
            unix_remove_bound(us);
        }
        mutex_unlock(&unix_bind_table.lock);
    }

    if (peer) {
        mutex_lock(&peer->lock);
        if (peer->peer == us) {
            peer->peer = NULL;
            drop_peer_ref_on_us = true;
        }
        wait_queue_wakeup_all(&peer->buf.rwait);
        wait_queue_wakeup_all(&peer->buf.wwait);
        if (peer->sock)
            poll_wait_wake(&peer->sock->pollers, POLLHUP | POLLIN);
        mutex_unlock(&peer->lock);
        unix_sock_put(peer);
    }
    if (drop_peer_ref_on_us)
        unix_sock_put(us);

    struct list_head *pos, *tmp;
    mutex_lock(&us->lock);
    list_for_each_safe(pos, tmp, &us->accept_queue) {
        struct unix_pending *pend = list_entry(pos, struct unix_pending, node);
        list_del(&pend->node);
        if (us->pending_count > 0)
            us->pending_count--;
        if (pend->client) {
            mutex_lock(&pend->client->lock);
            if (!pend->client->peer && pend->client->connect_err == 0) {
                pend->client->connect_err = -ECONNREFUSED;
                if (pend->client->sock)
                    pend->client->sock->state = SS_UNCONNECTED;
            }
            wait_queue_wakeup_all(&pend->client->buf.rwait);
            if (pend->client->sock)
                poll_wait_wake(&pend->client->sock->pollers,
                               POLLOUT | POLLERR);
            mutex_unlock(&pend->client->lock);
            unix_sock_put(pend->client);
            pend->client = NULL;
        }
        kfree(pend);
    }

    list_for_each_safe(pos, tmp, &us->dgram_queue) {
        struct unix_dgram_msg *msg = list_entry(pos, struct unix_dgram_msg,
                                                 node);
        list_del(&msg->node);
        unix_dgram_msg_release_control(msg);
        kfree(msg);
    }
    list_for_each_safe(pos, tmp, &us->stream_ctrl_queue) {
        struct unix_stream_ctrl *msg =
            list_entry(pos, struct unix_stream_ctrl, node);
        list_del(&msg->node);
        if (us->stream_ctrl_count > 0)
            us->stream_ctrl_count--;
        unix_stream_ctrl_release(msg);
        kfree(msg);
    }
    unix_buf_destroy(&us->buf);
    mutex_unlock(&us->lock);

    if (sock)
        poll_wait_wake(&sock->pollers, POLLHUP | POLLIN);
    us->sock = NULL;
    sock->proto_data = NULL;
    unix_sock_put(us);
    return 0;
}

static int unix_getsockname(struct socket *sock, struct sockaddr *addr,
                             int *addrlen) {
    struct unix_sock *us = sock->proto_data;
    struct sockaddr_un *sun = (struct sockaddr_un *)addr;
    char path[UNIX_PATH_MAX];
    bool bound = false;

    mutex_lock(&us->lock);
    bound = us->bound;
    if (bound) {
        strncpy(path, us->path, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }
    mutex_unlock(&us->lock);

    memset(sun, 0, sizeof(*sun));
    sun->sun_family = AF_UNIX;
    if (bound) {
        size_t plen = strlen(path);
        if (plen >= UNIX_PATH_MAX) {
            plen = UNIX_PATH_MAX - 1;
        }
        memcpy(sun->sun_path, path, plen);
        sun->sun_path[plen] = '\0';
    }
    *addrlen = (int)sizeof(struct sockaddr_un);
    return 0;
}

static int unix_getpeername(struct socket *sock, struct sockaddr *addr,
                             int *addrlen) {
    struct unix_sock *us = sock->proto_data;
    struct unix_sock *peer = NULL;
    char path[UNIX_PATH_MAX];
    bool bound = false;

    mutex_lock(&us->lock);
    if (!us->peer || us->closing) {
        mutex_unlock(&us->lock);
        return -ENOTCONN;
    }
    peer = us->peer;
    unix_sock_get(peer);
    mutex_unlock(&us->lock);

    struct sockaddr_un *sun = (struct sockaddr_un *)addr;
    memset(sun, 0, sizeof(*sun));
    sun->sun_family = AF_UNIX;

    mutex_lock(&peer->lock);
    bound = peer->bound;
    if (bound) {
        strncpy(path, peer->path, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }
    mutex_unlock(&peer->lock);

    if (bound) {
        size_t plen = strlen(path);
        if (plen >= UNIX_PATH_MAX) {
            plen = UNIX_PATH_MAX - 1;
        }
        memcpy(sun->sun_path, path, plen);
        sun->sun_path[plen] = '\0';
    }
    *addrlen = (int)sizeof(struct sockaddr_un);
    unix_sock_put(peer);
    return 0;
}

static int unix_getsockopt(struct socket *sock, int level, int optname,
                            void *optval, int *optlen) {
    if (!optlen || !optval || *optlen < (int)sizeof(int))
        return -EINVAL;
    int value = 0;
    struct unix_sock *us = sock ? sock->proto_data : NULL;
    if (us && level == SOL_SOCKET && optname == SO_ERROR) {
        mutex_lock(&us->lock);
        value = (us->connect_err < 0) ? -us->connect_err : 0;
        us->connect_err = 0;
        mutex_unlock(&us->lock);
    }
    *(int *)optval = value;
    *optlen = sizeof(int);
    return 0;
}

/* --- Initialization --- */

/*
 * Called after sock_create to attach the AF_UNIX private state.
 * sock_create dispatches to our ops via the family table, so we hook
 * proto_data allocation here through a wrapper registered as a family
 * create callback — but since sock_create doesn't call a per-family
 * init, we do it lazily in each op.  We need to ensure proto_data is
 * set up before any op runs, so we use a helper.
 */
static struct unix_sock *unix_ensure_proto_data(struct socket *sock) {
    if (sock->proto_data) {
        return sock->proto_data;
    }
    return unix_sock_alloc(sock);
}

/* Wrapper ops that lazily allocate proto_data */
static int unix_stream_bind_wrap(struct socket *sock,
                                  const struct sockaddr *addr, int addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_bind(sock, addr, addrlen);
}

static int unix_stream_connect_wrap(struct socket *sock,
                                    const struct sockaddr *addr, int addrlen,
                                    int flags) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_stream_connect(sock, addr, addrlen, flags);
}

static int unix_stream_listen_wrap(struct socket *sock, int backlog) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_stream_listen(sock, backlog);
}

static int unix_stream_accept_wrap(struct socket *sock,
                                   struct socket **newsock, int flags) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_stream_accept(sock, newsock, flags);
}

static ssize_t unix_stream_sendto_wrap(struct socket *sock, const void *buf,
                                        size_t len, int flags,
                                        const struct sockaddr *dest,
                                        int addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_stream_sendto(sock, buf, len, flags, dest, addrlen);
}

static ssize_t unix_stream_recvfrom_wrap(struct socket *sock, void *buf,
                                          size_t len, int flags,
                                          struct sockaddr *src, int *addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    ssize_t ret = unix_stream_recvfrom(sock, buf, len, flags, src, addrlen);
    struct unix_sock *us = sock->proto_data;
    unix_stream_post_recv(us, ret, NULL);
    return ret;
}

static ssize_t unix_stream_sendmsg_wrap(struct socket *sock, const void *buf,
                                        size_t len, int flags,
                                        const struct sockaddr *dest,
                                        int addrlen,
                                        const struct socket_control *control) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    if (control && (control->has_creds || control->rights_count)) {
        struct unix_sock *us = sock->proto_data;
        struct unix_sock *peer = NULL;
        bool nonblock = (flags & MSG_DONTWAIT) != 0;
        struct unix_stream_ctrl *ctrl = NULL;
        int ctrl_ret = unix_stream_ctrl_from_send(control, &ctrl);
        if (ctrl_ret < 0)
            return ctrl_ret;
        if (!ctrl)
            return -EINVAL;
        if (len == 0) {
            unix_stream_ctrl_release(ctrl);
            kfree(ctrl);
            return -EINVAL;
        }

        mutex_lock(&us->lock);
        if (sock->state != SS_CONNECTED || us->closing || !us->peer) {
            mutex_unlock(&us->lock);
            unix_stream_ctrl_release(ctrl);
            kfree(ctrl);
            return -ENOTCONN;
        }
        if (us->shutdown_flags & (int)UNIX_SHUT_WR_BIT) {
            mutex_unlock(&us->lock);
            unix_stream_ctrl_release(ctrl);
            kfree(ctrl);
            if (!(flags & MSG_NOSIGNAL)) {
                struct process *curr = proc_current();
                if (curr)
                    signal_send(curr->pid, SIGPIPE);
            }
            return -EPIPE;
        }
        peer = us->peer;
        unix_sock_get(peer);
        mutex_unlock(&us->lock);

        ssize_t ret = 0;
        mutex_lock(&peer->lock);
        if (peer->closing || !peer->buf.data) {
            ret = -ENOTCONN;
        } else {
            uint64_t attach_off = peer->stream_rx_write_off;
            ret = unix_buf_write_locked(&peer->buf, &peer->lock, buf, len,
                                        &peer->shutdown_flags, nonblock);
            if (ret > 0) {
                peer->stream_rx_write_off += (uint64_t)ret;
                ctrl->attach_off = attach_off;
                list_add_tail(&ctrl->node, &peer->stream_ctrl_queue);
                peer->stream_ctrl_count++;
                ctrl = NULL;
                if (peer->sock)
                    poll_wait_wake(&peer->sock->pollers, POLLIN);
            }
        }
        mutex_unlock(&peer->lock);
        unix_sock_put(peer);

        if (ctrl) {
            unix_stream_ctrl_release(ctrl);
            kfree(ctrl);
        }
        return ret;
    }
    return unix_stream_sendto(sock, buf, len, flags, dest, addrlen);
}

static ssize_t unix_stream_recvmsg_wrap(struct socket *sock, void *buf,
                                        size_t len, int flags,
                                        struct sockaddr *src, int *addrlen,
                                        struct socket_control *control) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    ssize_t ret = unix_stream_recvfrom(sock, buf, len, flags, src, addrlen);
    if (control)
        memset(control, 0, sizeof(*control));
    struct unix_sock *us = sock->proto_data;
    unix_stream_post_recv(us, ret, control);
    return ret;
}

static int unix_stream_poll_wrap(struct socket *sock, uint32_t events) {
    if (!unix_ensure_proto_data(sock)) {
        return 0;
    }
    return unix_stream_poll(sock, events);
}

static int unix_shutdown_wrap(struct socket *sock, int how) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_shutdown(sock, how);
}

static int unix_close_wrap(struct socket *sock) {
    if (!sock->proto_data) {
        return 0;
    }
    return unix_close(sock);
}

static int unix_getsockname_wrap(struct socket *sock, struct sockaddr *addr,
                                  int *addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_getsockname(sock, addr, addrlen);
}

static int unix_getpeername_wrap(struct socket *sock, struct sockaddr *addr,
                                  int *addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_getpeername(sock, addr, addrlen);
}

static int unix_setsockopt_wrap(struct socket *sock, int level, int optname,
                                 const void *optval, int optlen) {
    (void)sock; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0;
}

static int unix_getsockopt_wrap(struct socket *sock, int level, int optname,
                                 void *optval, int *optlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_getsockopt(sock, level, optname, optval, optlen);
}

/* DGRAM wrappers */
static int unix_dgram_bind_wrap(struct socket *sock,
                                 const struct sockaddr *addr, int addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_bind(sock, addr, addrlen);
}

static int unix_dgram_connect_wrap(struct socket *sock,
                                   const struct sockaddr *addr, int addrlen,
                                   int flags) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_dgram_connect(sock, addr, addrlen, flags);
}

static ssize_t unix_dgram_sendto_wrap(struct socket *sock, const void *buf,
                                       size_t len, int flags,
                                       const struct sockaddr *dest,
                                       int addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_dgram_sendto(sock, buf, len, flags, dest, addrlen);
}

static ssize_t unix_dgram_recvfrom_wrap(struct socket *sock, void *buf,
                                         size_t len, int flags,
                                         struct sockaddr *src, int *addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_dgram_recvfrom(sock, buf, len, flags, src, addrlen);
}

static ssize_t unix_dgram_sendmsg_wrap(struct socket *sock, const void *buf,
                                       size_t len, int flags,
                                       const struct sockaddr *dest, int addrlen,
                                       const struct socket_control *control) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_dgram_sendmsg(sock, buf, len, flags, dest, addrlen, control);
}

static ssize_t unix_dgram_recvmsg_wrap(struct socket *sock, void *buf,
                                       size_t len, int flags,
                                       struct sockaddr *src, int *addrlen,
                                       struct socket_control *control) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_dgram_recvmsg(sock, buf, len, flags, src, addrlen, control);
}

static int unix_dgram_poll_wrap(struct socket *sock, uint32_t events) {
    if (!unix_ensure_proto_data(sock)) {
        return 0;
    }
    return unix_dgram_poll(sock, events);
}

static const struct proto_ops unix_stream_wrap_ops = {
    .bind       = unix_stream_bind_wrap,
    .connect    = unix_stream_connect_wrap,
    .listen     = unix_stream_listen_wrap,
    .accept     = unix_stream_accept_wrap,
    .sendto     = unix_stream_sendto_wrap,
    .recvfrom   = unix_stream_recvfrom_wrap,
    .sendmsg    = unix_stream_sendmsg_wrap,
    .recvmsg    = unix_stream_recvmsg_wrap,
    .shutdown   = unix_shutdown_wrap,
    .close      = unix_close_wrap,
    .poll       = unix_stream_poll_wrap,
    .getsockname = unix_getsockname_wrap,
    .getpeername = unix_getpeername_wrap,
    .setsockopt = unix_setsockopt_wrap,
    .getsockopt = unix_getsockopt_wrap,
};

static const struct proto_ops unix_dgram_wrap_ops = {
    .bind       = unix_dgram_bind_wrap,
    .connect    = unix_dgram_connect_wrap,
    .listen     = NULL,
    .accept     = NULL,
    .sendto     = unix_dgram_sendto_wrap,
    .recvfrom   = unix_dgram_recvfrom_wrap,
    .sendmsg    = unix_dgram_sendmsg_wrap,
    .recvmsg    = unix_dgram_recvmsg_wrap,
    .shutdown   = unix_shutdown_wrap,
    .close      = unix_close_wrap,
    .poll       = unix_dgram_poll_wrap,
    .getsockname = unix_getsockname_wrap,
    .getpeername = unix_getpeername_wrap,
    .setsockopt = unix_setsockopt_wrap,
    .getsockopt = unix_getsockopt_wrap,
};

int unix_socketpair_connect(struct socket *sock0, struct socket *sock1) {
    struct unix_sock *us0 = unix_ensure_proto_data(sock0);
    struct unix_sock *us1 = unix_ensure_proto_data(sock1);
    bool us0_buf_alloc = false;
    bool us1_buf_alloc = false;
    if (!us0 || !us1) {
        return -ENOMEM;
    }

    mutex_lock(&us0->lock);
    mutex_lock(&us1->lock);
    if (us0->closing || us1->closing || us0->peer || us1->peer) {
        mutex_unlock(&us1->lock);
        mutex_unlock(&us0->lock);
        return -EISCONN;
    }
    mutex_unlock(&us1->lock);
    mutex_unlock(&us0->lock);

    int ret = 0;
    if (!us0->buf.data) {
        ret = unix_buf_init(&us0->buf);
        if (ret < 0)
            return ret;
        us0_buf_alloc = true;
    }
    if (!us1->buf.data) {
        ret = unix_buf_init(&us1->buf);
        if (ret < 0) {
            if (us0_buf_alloc)
                unix_buf_destroy(&us0->buf);
            return ret;
        }
        us1_buf_alloc = true;
    }

    mutex_lock(&us0->lock);
    mutex_lock(&us1->lock);
    if (us0->closing || us1->closing || us0->peer || us1->peer) {
        mutex_unlock(&us1->lock);
        mutex_unlock(&us0->lock);
        if (us1_buf_alloc)
            unix_buf_destroy(&us1->buf);
        if (us0_buf_alloc)
            unix_buf_destroy(&us0->buf);
        return -EISCONN;
    }
    unix_sock_get(us1);
    us0->peer = us1;
    unix_sock_get(us0);
    us1->peer = us0;
    sock0->state = SS_CONNECTED;
    sock1->state = SS_CONNECTED;
    mutex_unlock(&us1->lock);
    mutex_unlock(&us0->lock);
    return 0;
}

void af_unix_init(void) {
    unix_bind_table_init();
    sock_register_family(AF_UNIX, &unix_stream_wrap_ops, &unix_dgram_wrap_ops);
    pr_info("af_unix: initialized\n");
}
