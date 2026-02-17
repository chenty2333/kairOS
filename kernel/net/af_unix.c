/**
 * kernel/net/af_unix.c - AF_UNIX (Unix domain) socket implementation
 *
 * Supports SOCK_STREAM (connection-oriented) and SOCK_DGRAM (connectionless).
 * STREAM mode uses a per-direction ring buffer similar to pipe.c.
 * DGRAM mode uses a simple message queue.
 */

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
    uint8_t data[];
};

/* Pending connection for accept queue */
struct unix_pending {
    struct list_head node;
    struct socket *sock;
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

    struct mutex lock;
};

/* Global bound socket registry (simple linear scan) */
#define UNIX_BIND_TABLE_SIZE 64
static struct {
    struct mutex lock;
    struct unix_sock *entries[UNIX_BIND_TABLE_SIZE];
    bool init;
} unix_bind_table;

static void unix_bind_table_init(void) {
    if (unix_bind_table.init) {
        return;
    }
    mutex_init(&unix_bind_table.lock, "unix_bind");
    memset(unix_bind_table.entries, 0, sizeof(unix_bind_table.entries));
    unix_bind_table.init = true;
}

static struct unix_sock *unix_find_bound(const char *path) {
    for (int i = 0; i < UNIX_BIND_TABLE_SIZE; i++) {
        struct unix_sock *us = unix_bind_table.entries[i];
        if (us && strcmp(us->path, path) == 0) {
            return us;
        }
    }
    return NULL;
}

static int unix_add_bound(struct unix_sock *us) {
    for (int i = 0; i < UNIX_BIND_TABLE_SIZE; i++) {
        if (!unix_bind_table.entries[i]) {
            unix_bind_table.entries[i] = us;
            return 0;
        }
    }
    return -ENOMEM;
}

static void unix_remove_bound(struct unix_sock *us) {
    for (int i = 0; i < UNIX_BIND_TABLE_SIZE; i++) {
        if (unix_bind_table.entries[i] == us) {
            unix_bind_table.entries[i] = NULL;
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
    us->shutdown_flags = 0;
    INIT_LIST_HEAD(&us->accept_queue);
    us->backlog = 0;
    us->pending_count = 0;
    wait_queue_init(&us->accept_wait);
    INIT_LIST_HEAD(&us->dgram_queue);
    us->dgram_count = 0;
    wait_queue_init(&us->dgram_wait);
    mutex_init(&us->lock, "unix_sock");
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
            if ((shutdown & SHUT_RD) || !peer) {
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

static ssize_t unix_buf_write(struct unix_buf *b, struct mutex *lock,
                               const void *buf, size_t len,
                               int *reader_alive, bool nonblock) {
    size_t total = 0;

    mutex_lock(lock);
    while (total < len) {
        if (!*reader_alive) {
            mutex_unlock(lock);
            struct process *curr = proc_current();
            if (curr) {
                signal_send(curr->pid, SIGPIPE);
            }
            return total ? (ssize_t)total : -EPIPE;
        }

        size_t space = UNIX_BUF_SIZE - b->count;
        if (space == 0) {
            if (nonblock) {
                mutex_unlock(lock);
                return total ? (ssize_t)total : -EAGAIN;
            }
            int rc = proc_sleep_on_mutex(&b->wwait, &b->wwait,
                                         lock, true);
            if (rc == -EINTR) {
                mutex_unlock(lock);
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
    mutex_unlock(lock);
    return (ssize_t)total;
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

    unix_bind_table_init();

    mutex_lock(&unix_bind_table.lock);
    if (us->bound) {
        mutex_unlock(&unix_bind_table.lock);
        return -EINVAL;
    }
    if (unix_find_bound(sun->sun_path)) {
        mutex_unlock(&unix_bind_table.lock);
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
                                int addrlen) {
    struct unix_sock *us = sock->proto_data;
    const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;

    if (!sun || addrlen < (int)sizeof(sun->sun_family) + 1) {
        return -EINVAL;
    }
    if (sun->sun_family != AF_UNIX) {
        return -EINVAL;
    }
    if (sock->state == SS_CONNECTED) {
        return -EISCONN;
    }

    unix_bind_table_init();

    mutex_lock(&unix_bind_table.lock);
    struct unix_sock *listener = unix_find_bound(sun->sun_path);
    if (!listener || listener->sock->state != SS_LISTENING) {
        mutex_unlock(&unix_bind_table.lock);
        return -ECONNREFUSED;
    }
    mutex_unlock(&unix_bind_table.lock);

    /* Allocate recv buffer for this socket */
    int ret = unix_buf_init(&us->buf);
    if (ret < 0) {
        return ret;
    }

    /* Enqueue ourselves on the listener's accept queue */
    struct unix_pending *pend = kzalloc(sizeof(*pend));
    if (!pend) {
        unix_buf_destroy(&us->buf);
        return -ENOMEM;
    }
    pend->sock = sock;

    mutex_lock(&listener->lock);
    if (listener->pending_count >= listener->backlog) {
        mutex_unlock(&listener->lock);
        kfree(pend);
        unix_buf_destroy(&us->buf);
        return -ECONNREFUSED;
    }
    list_add_tail(&pend->node, &listener->accept_queue);
    listener->pending_count++;
    wait_queue_wakeup_one(&listener->accept_wait);
    poll_wait_wake(&listener->sock->pollers, POLLIN);
    mutex_unlock(&listener->lock);

    /* Wait for the listener to accept us (peer will be set) */
    mutex_lock(&us->lock);
    while (!us->peer) {
        int rc = proc_sleep_on_mutex(&us->buf.rwait, &us->buf.rwait,
                                     &us->lock, true);
        if (rc == -EINTR) {
            mutex_unlock(&us->lock);
            return -EINTR;
        }
    }
    sock->state = SS_CONNECTED;
    mutex_unlock(&us->lock);
    return 0;
}

static int unix_stream_accept(struct socket *sock, struct socket **newsock) {
    struct unix_sock *us = sock->proto_data;

    if (sock->type != SOCK_STREAM || sock->state != SS_LISTENING) {
        return -EINVAL;
    }

    /* Wait for a pending connection */
    mutex_lock(&us->lock);
    while (list_empty(&us->accept_queue)) {
        int rc = proc_sleep_on_mutex(&us->accept_wait, &us->accept_wait,
                                     &us->lock, true);
        if (rc == -EINTR) {
            mutex_unlock(&us->lock);
            return -EINTR;
        }
    }

    /* Dequeue */
    struct unix_pending *pend = list_first_entry(&us->accept_queue,
                                                  struct unix_pending, node);
    list_del(&pend->node);
    us->pending_count--;
    struct socket *client_sock = pend->sock;
    kfree(pend);
    mutex_unlock(&us->lock);

    struct unix_sock *client = client_sock->proto_data;

    /* Create the server-side socket */
    struct socket *svr = NULL;
    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &svr);
    if (ret < 0) {
        return ret;
    }

    struct unix_sock *svr_us = svr->proto_data;
    if (!svr_us) {
        svr_us = unix_sock_alloc(svr);
        if (!svr_us) {
            sock_destroy(svr);
            return -ENOMEM;
        }
    }

    /* Allocate recv buffer for the server side */
    ret = unix_buf_init(&svr_us->buf);
    if (ret < 0) {
        sock_destroy(svr);
        return ret;
    }

    /* Cross-connect peers */
    mutex_lock(&client->lock);
    client->peer = svr_us;
    svr_us->peer = client;
    svr->state = SS_CONNECTED;
    /* Wake the connecting client */
    wait_queue_wakeup_one(&client->buf.rwait);
    mutex_unlock(&client->lock);

    *newsock = svr;
    return 0;
}

static ssize_t unix_stream_sendto(struct socket *sock, const void *buf,
                                   size_t len, int flags,
                                   const struct sockaddr *dest, int addrlen) {
    (void)flags; (void)dest; (void)addrlen;
    struct unix_sock *us = sock->proto_data;

    if (sock->state != SS_CONNECTED || !us->peer) {
        return -ENOTCONN;
    }
    if (us->shutdown_flags & SHUT_WR) {
        struct process *curr = proc_current();
        if (curr) {
            signal_send(curr->pid, SIGPIPE);
        }
        return -EPIPE;
    }

    /* Write into peer's recv buffer */
    struct unix_sock *peer = us->peer;
    int reader_alive = (peer->shutdown_flags & SHUT_RD) ? 0 : 1;
    return unix_buf_write(&peer->buf, &peer->lock, buf, len,
                          &reader_alive, false);
}

static ssize_t unix_stream_recvfrom(struct socket *sock, void *buf,
                                     size_t len, int flags,
                                     struct sockaddr *src, int *addrlen) {
    (void)flags; (void)src; (void)addrlen;
    struct unix_sock *us = sock->proto_data;

    if (sock->state != SS_CONNECTED) {
        return -ENOTCONN;
    }

    return unix_buf_read(&us->buf, &us->lock, buf, len,
                         us->shutdown_flags, us->peer, false);
}

static int unix_stream_poll(struct socket *sock, uint32_t events) {
    struct unix_sock *us = sock->proto_data;
    uint32_t revents = 0;

    mutex_lock(&us->lock);
    if (sock->state == SS_LISTENING) {
        if (!list_empty(&us->accept_queue)) {
            revents |= POLLIN;
        }
    } else if (sock->state == SS_CONNECTED) {
        /* Readable: data in our recv buffer, or peer gone */
        if (us->buf.count > 0 || !us->peer) {
            revents |= POLLIN;
        }
        /* Writable: space in peer's recv buffer */
        if (us->peer && us->peer->buf.count < UNIX_BUF_SIZE) {
            revents |= POLLOUT;
        }
        if (!us->peer || (us->shutdown_flags & SHUT_RD)) {
            revents |= POLLHUP;
        }
    }
    mutex_unlock(&us->lock);

    return (int)(revents & events);
}

/* --- Proto ops (DGRAM) --- */

static ssize_t unix_dgram_sendto(struct socket *sock, const void *buf,
                                  size_t len, int flags,
                                  const struct sockaddr *dest, int addrlen) {
    (void)flags;
    struct unix_sock *us = sock->proto_data;
    const struct sockaddr_un *sun = (const struct sockaddr_un *)dest;
    struct unix_sock *target = NULL;

    /* Connected DGRAM: use peer */
    if (!dest && us->peer) {
        target = us->peer;
    } else if (sun && addrlen >= (int)sizeof(sun->sun_family) + 1) {
        unix_bind_table_init();
        mutex_lock(&unix_bind_table.lock);
        target = unix_find_bound(sun->sun_path);
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
        return -ENOMEM;
    }
    msg->len = len;
    memset(&msg->sender, 0, sizeof(msg->sender));
    msg->sender.sun_family = AF_UNIX;
    if (us->bound) {
        size_t plen = strlen(us->path);
        if (plen >= UNIX_PATH_MAX) {
            plen = UNIX_PATH_MAX - 1;
        }
        memcpy(msg->sender.sun_path, us->path, plen);
        msg->sender.sun_path[plen] = '\0';
    }
    memcpy(msg->data, buf, len);

    mutex_lock(&target->lock);
    list_add_tail(&msg->node, &target->dgram_queue);
    target->dgram_count++;
    wait_queue_wakeup_one(&target->dgram_wait);
    poll_wait_wake(&target->sock->pollers, POLLIN);
    mutex_unlock(&target->lock);

    return (ssize_t)len;
}

static ssize_t unix_dgram_recvfrom(struct socket *sock, void *buf,
                                    size_t len, int flags,
                                    struct sockaddr *src, int *addrlen) {
    (void)flags;
    struct unix_sock *us = sock->proto_data;

    mutex_lock(&us->lock);
    while (list_empty(&us->dgram_queue)) {
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

    ssize_t ret = (ssize_t)msg->len;
    kfree(msg);
    return ret;
}

static int unix_dgram_connect(struct socket *sock, const struct sockaddr *addr,
                               int addrlen) {
    struct unix_sock *us = sock->proto_data;
    const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;

    if (!sun || addrlen < (int)sizeof(sun->sun_family) + 1) {
        return -EINVAL;
    }

    unix_bind_table_init();

    mutex_lock(&unix_bind_table.lock);
    struct unix_sock *target = unix_find_bound(sun->sun_path);
    mutex_unlock(&unix_bind_table.lock);

    if (!target) {
        return -ECONNREFUSED;
    }

    mutex_lock(&us->lock);
    us->peer = target;
    sock->state = SS_CONNECTED;
    mutex_unlock(&us->lock);
    return 0;
}

static int unix_dgram_poll(struct socket *sock, uint32_t events) {
    struct unix_sock *us = sock->proto_data;
    uint32_t revents = 0;

    mutex_lock(&us->lock);
    if (!list_empty(&us->dgram_queue)) {
        revents |= POLLIN;
    }
    revents |= POLLOUT; /* DGRAM send is always "ready" */
    mutex_unlock(&us->lock);

    return (int)(revents & events);
}

/* --- Common ops --- */

static int unix_shutdown(struct socket *sock, int how) {
    struct unix_sock *us = sock->proto_data;

    mutex_lock(&us->lock);
    us->shutdown_flags |= how;
    /* Wake blocked readers/writers */
    wait_queue_wakeup_all(&us->buf.rwait);
    wait_queue_wakeup_all(&us->buf.wwait);
    if (us->peer) {
        wait_queue_wakeup_all(&us->peer->buf.rwait);
        wait_queue_wakeup_all(&us->peer->buf.wwait);
        poll_wait_wake(&us->peer->sock->pollers, POLLHUP);
    }
    poll_wait_wake(&sock->pollers, POLLHUP);
    mutex_unlock(&us->lock);
    return 0;
}

static int unix_close(struct socket *sock) {
    struct unix_sock *us = sock->proto_data;
    if (!us) {
        return 0;
    }

    /* Disconnect peer */
    mutex_lock(&us->lock);
    if (us->peer) {
        struct unix_sock *peer = us->peer;
        mutex_lock(&peer->lock);
        peer->peer = NULL;
        wait_queue_wakeup_all(&peer->buf.rwait);
        wait_queue_wakeup_all(&peer->buf.wwait);
        poll_wait_wake(&peer->sock->pollers, POLLHUP | POLLIN);
        mutex_unlock(&peer->lock);
        us->peer = NULL;
    }
    mutex_unlock(&us->lock);

    /* Remove from bind table */
    if (us->bound) {
        unix_bind_table_init();
        mutex_lock(&unix_bind_table.lock);
        unix_remove_bound(us);
        mutex_unlock(&unix_bind_table.lock);
    }

    /* Drain pending accept queue */
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &us->accept_queue) {
        struct unix_pending *pend = list_entry(pos, struct unix_pending, node);
        list_del(&pend->node);
        kfree(pend);
    }

    /* Drain DGRAM queue */
    list_for_each_safe(pos, tmp, &us->dgram_queue) {
        struct unix_dgram_msg *msg = list_entry(pos, struct unix_dgram_msg,
                                                 node);
        list_del(&msg->node);
        kfree(msg);
    }

    unix_buf_destroy(&us->buf);
    sock->proto_data = NULL;
    kfree(us);
    return 0;
}

static int unix_getsockname(struct socket *sock, struct sockaddr *addr,
                             int *addrlen) {
    struct unix_sock *us = sock->proto_data;
    struct sockaddr_un *sun = (struct sockaddr_un *)addr;

    memset(sun, 0, sizeof(*sun));
    sun->sun_family = AF_UNIX;
    if (us->bound) {
        size_t plen = strlen(us->path);
        if (plen >= UNIX_PATH_MAX) {
            plen = UNIX_PATH_MAX - 1;
        }
        memcpy(sun->sun_path, us->path, plen);
        sun->sun_path[plen] = '\0';
    }
    *addrlen = (int)sizeof(struct sockaddr_un);
    return 0;
}

static int unix_getpeername(struct socket *sock, struct sockaddr *addr,
                             int *addrlen) {
    struct unix_sock *us = sock->proto_data;

    if (!us->peer) {
        return -ENOTCONN;
    }

    struct sockaddr_un *sun = (struct sockaddr_un *)addr;
    memset(sun, 0, sizeof(*sun));
    sun->sun_family = AF_UNIX;

    struct unix_sock *peer = us->peer;
    if (peer->bound) {
        size_t plen = strlen(peer->path);
        if (plen >= UNIX_PATH_MAX) {
            plen = UNIX_PATH_MAX - 1;
        }
        memcpy(sun->sun_path, peer->path, plen);
        sun->sun_path[plen] = '\0';
    }
    *addrlen = (int)sizeof(struct sockaddr_un);
    return 0;
}

static int unix_getsockopt(struct socket *sock, int level, int optname,
                            void *optval, int *optlen) {
    (void)sock; (void)level; (void)optname;
    if (optlen && *optlen >= (int)sizeof(int)) {
        *(int *)optval = 0;
        *optlen = sizeof(int);
    }
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
                                     const struct sockaddr *addr, int addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_stream_connect(sock, addr, addrlen);
}

static int unix_stream_listen_wrap(struct socket *sock, int backlog) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_stream_listen(sock, backlog);
}

static int unix_stream_accept_wrap(struct socket *sock,
                                    struct socket **newsock) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_stream_accept(sock, newsock);
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
    return unix_stream_recvfrom(sock, buf, len, flags, src, addrlen);
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
                                    const struct sockaddr *addr, int addrlen) {
    if (!unix_ensure_proto_data(sock)) {
        return -ENOMEM;
    }
    return unix_dgram_connect(sock, addr, addrlen);
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
    if (!us0 || !us1) {
        return -ENOMEM;
    }

    int ret = unix_buf_init(&us0->buf);
    if (ret < 0) {
        return ret;
    }
    ret = unix_buf_init(&us1->buf);
    if (ret < 0) {
        unix_buf_destroy(&us0->buf);
        return ret;
    }

    us0->peer = us1;
    us1->peer = us0;
    sock0->state = SS_CONNECTED;
    sock1->state = SS_CONNECTED;
    return 0;
}

void af_unix_init(void) {
    unix_bind_table_init();
    sock_register_family(AF_UNIX, &unix_stream_wrap_ops, &unix_dgram_wrap_ops);
    pr_info("af_unix: initialized\n");
}
