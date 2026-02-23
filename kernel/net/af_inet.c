/**
 * kernel/net/af_inet.c - AF_INET socket implementation using lwIP
 *
 * Uses lwIP raw/callback API for TCP and UDP.
 * Each socket maps to a tcp_pcb or udp_pcb.
 */

#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/socket.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/vfs.h>
#include <kairos/wait.h>

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"

#define INET_RECV_BUF_SIZE  65536
#define INET_ACCEPT_BACKLOG 16

/* Per-socket private data for AF_INET */
struct inet_sock {
    struct socket *sock;
    int proto; /* IPPROTO_TCP or IPPROTO_UDP */

    union {
        struct tcp_pcb *tcp;
        struct udp_pcb *udp;
    } pcb;

    /* Receive buffer (ring buffer for TCP, pbuf queue for UDP) */
    uint8_t *recv_buf;
    size_t recv_head;
    size_t recv_tail;
    size_t recv_count;
    struct wait_queue recv_wait;

    /* TCP connect completion */
    int connect_err;
    bool connect_done;
    struct wait_queue connect_wait;

    /* TCP accept queue */
    struct list_head accept_queue;
    int accept_count;
    struct wait_queue accept_wait;

    /* Send wait (TCP flow control) */
    struct wait_queue send_wait;
    bool send_ready;

    /* UDP: per-message source address tracking */
    struct sockaddr_in last_src;
    bool has_last_src;

    int shutdown_flags;
    bool peer_closed;
    struct mutex lock;
};

/* Pending accepted TCP connection */
struct inet_pending {
    struct list_head node;
    struct tcp_pcb *pcb;
    struct sockaddr_in addr;
};

static struct inet_sock *inet_sock_alloc(struct socket *sock, int proto) {
    struct inet_sock *is = kzalloc(sizeof(*is));
    if (!is) {
        return NULL;
    }
    is->sock = sock;
    is->proto = proto;
    is->recv_buf = NULL;
    is->recv_head = 0;
    is->recv_tail = 0;
    is->recv_count = 0;
    wait_queue_init(&is->recv_wait);
    is->connect_err = 0;
    is->connect_done = false;
    wait_queue_init(&is->connect_wait);
    INIT_LIST_HEAD(&is->accept_queue);
    is->accept_count = 0;
    wait_queue_init(&is->accept_wait);
    wait_queue_init(&is->send_wait);
    is->send_ready = true;
    is->has_last_src = false;
    is->shutdown_flags = 0;
    is->peer_closed = false;
    mutex_init(&is->lock, "inet_sock");
    sock->proto_data = is;
    return is;
}

static struct inet_sock *inet_ensure(struct socket *sock) {
    if (sock->proto_data) {
        return sock->proto_data;
    }
    int proto = (sock->type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
    return inet_sock_alloc(sock, proto);
}

static int inet_recv_buf_init(struct inet_sock *is) {
    if (is->recv_buf) {
        return 0;
    }
    is->recv_buf = kmalloc(INET_RECV_BUF_SIZE);
    if (!is->recv_buf) {
        return -ENOMEM;
    }
    is->recv_head = 0;
    is->recv_tail = 0;
    is->recv_count = 0;
    return 0;
}

static void inet_recv_buf_push(struct inet_sock *is, const void *data,
                                size_t len) {
    while (len > 0 && is->recv_count < INET_RECV_BUF_SIZE) {
        size_t space = INET_RECV_BUF_SIZE - is->recv_head;
        size_t can = len;
        if (can > space) {
            can = space;
        }
        if (can > INET_RECV_BUF_SIZE - is->recv_count) {
            can = INET_RECV_BUF_SIZE - is->recv_count;
        }
        memcpy(is->recv_buf + is->recv_head, data, can);
        is->recv_head = (is->recv_head + can) % INET_RECV_BUF_SIZE;
        is->recv_count += can;
        data = (const uint8_t *)data + can;
        len -= can;
    }
}

static size_t inet_recv_buf_pop(struct inet_sock *is, void *buf, size_t len) {
    size_t total = 0;
    while (total < len && is->recv_count > 0) {
        size_t avail = INET_RECV_BUF_SIZE - is->recv_tail;
        size_t can = len - total;
        if (can > avail) {
            can = avail;
        }
        if (can > is->recv_count) {
            can = is->recv_count;
        }
        memcpy((uint8_t *)buf + total, is->recv_buf + is->recv_tail, can);
        is->recv_tail = (is->recv_tail + can) % INET_RECV_BUF_SIZE;
        is->recv_count -= can;
        total += can;
    }
    return total;
}

/* --- lwIP TCP callbacks --- */

static err_t inet_tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                               err_t err) {
    struct inet_sock *is = arg;
    (void)pcb;
    (void)err;

    mutex_lock(&is->lock);
    if (!p) {
        /* Peer closed the connection */
        is->peer_closed = true;
        mutex_unlock(&is->lock);
        wait_queue_wakeup_all(&is->recv_wait);
        poll_wait_wake(&is->sock->pollers, POLLIN | POLLHUP);
        return ERR_OK;
    }

    /* Copy pbuf data into receive buffer */
    for (struct pbuf *q = p; q != NULL; q = q->next) {
        inet_recv_buf_push(is, q->payload, q->len);
    }
    tcp_recved(pcb, p->tot_len);
    mutex_unlock(&is->lock);
    pbuf_free(p);

    wait_queue_wakeup_all(&is->recv_wait);
    poll_wait_wake(&is->sock->pollers, POLLIN);
    return ERR_OK;
}

static err_t inet_tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len) {
    struct inet_sock *is = arg;
    (void)pcb; (void)len;

    is->send_ready = true;
    wait_queue_wakeup_all(&is->send_wait);
    poll_wait_wake(&is->sock->pollers, POLLOUT);
    return ERR_OK;
}

static err_t inet_tcp_connected_cb(void *arg, struct tcp_pcb *pcb,
                                    err_t err) {
    struct inet_sock *is = arg;
    (void)pcb;

    mutex_lock(&is->lock);
    is->connect_err = (err == ERR_OK) ? 0 : -ECONNREFUSED;
    is->connect_done = true;
    mutex_unlock(&is->lock);
    wait_queue_wakeup_all(&is->connect_wait);
    return ERR_OK;
}

static void inet_tcp_err_cb(void *arg, err_t err) {
    struct inet_sock *is = arg;
    (void)err;

    mutex_lock(&is->lock);
    is->peer_closed = true;
    /* PCB is already freed by lwIP when this callback fires */
    is->pcb.tcp = NULL;
    is->connect_err = -ECONNRESET;
    is->connect_done = true;
    mutex_unlock(&is->lock);

    wait_queue_wakeup_all(&is->recv_wait);
    wait_queue_wakeup_all(&is->send_wait);
    wait_queue_wakeup_all(&is->connect_wait);
    poll_wait_wake(&is->sock->pollers, POLLERR | POLLHUP);
}

static err_t inet_tcp_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
    struct inet_sock *is = arg;
    if (err != ERR_OK || !newpcb) {
        return ERR_VAL;
    }

    struct inet_pending *pend = kzalloc(sizeof(*pend));
    if (!pend) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }
    pend->pcb = newpcb;
    pend->addr.sin_family = AF_INET;
    pend->addr.sin_port = newpcb->remote_port;
    pend->addr.sin_addr = newpcb->remote_ip.addr;

    mutex_lock(&is->lock);
    list_add_tail(&pend->node, &is->accept_queue);
    is->accept_count++;
    mutex_unlock(&is->lock);

    wait_queue_wakeup_one(&is->accept_wait);
    poll_wait_wake(&is->sock->pollers, POLLIN);
    return ERR_OK;
}

/* --- lwIP UDP callback --- */

static void inet_udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                              const ip_addr_t *addr, u16_t port) {
    struct inet_sock *is = arg;
    (void)pcb;

    if (!p) {
        return;
    }

    mutex_lock(&is->lock);
    /* Store source address */
    is->last_src.sin_family = AF_INET;
    is->last_src.sin_port = port;
    is->last_src.sin_addr = addr->addr;
    is->has_last_src = true;

    /* Copy payload into recv buffer */
    for (struct pbuf *q = p; q != NULL; q = q->next) {
        inet_recv_buf_push(is, q->payload, q->len);
    }
    mutex_unlock(&is->lock);
    pbuf_free(p);

    wait_queue_wakeup_all(&is->recv_wait);
    poll_wait_wake(&is->sock->pollers, POLLIN);
}

/* --- Helpers to convert between Kairos sockaddr and lwIP ip_addr --- */

static void sockaddr_to_lwip(const struct sockaddr *addr, ip_addr_t *ip,
                              u16_t *port) {
    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    ip->addr = sin->sin_addr;
    /* sin_port is in network byte order, lwIP expects host byte order */
    *port = __builtin_bswap16(sin->sin_port);
}

static void lwip_to_sockaddr(struct sockaddr_in *sin, const ip_addr_t *ip,
                              u16_t port) {
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = __builtin_bswap16(port);
    sin->sin_addr = ip->addr;
}

/* --- Proto ops (TCP / STREAM) --- */

static int inet_tcp_bind(struct socket *sock, const struct sockaddr *addr,
                          int addrlen) {
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }

    if (addrlen < (int)sizeof(struct sockaddr_in)) {
        return -EINVAL;
    }

    if (!is->pcb.tcp) {
        is->pcb.tcp = tcp_new();
        if (!is->pcb.tcp) {
            return -ENOMEM;
        }
    }

    ip_addr_t ip;
    u16_t port;
    sockaddr_to_lwip(addr, &ip, &port);

    err_t err = tcp_bind(is->pcb.tcp, &ip, port);
    if (err != ERR_OK) {
        return -EADDRINUSE;
    }
    sock->state = SS_BOUND;
    return 0;
}

static int inet_tcp_listen(struct socket *sock, int backlog) {
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }
    if (!is->pcb.tcp) {
        return -EINVAL;
    }

    (void)backlog;
    struct tcp_pcb *lpcb = tcp_listen(is->pcb.tcp);
    if (!lpcb) {
        return -ENOMEM;
    }
    is->pcb.tcp = lpcb;
    tcp_arg(lpcb, is);
    tcp_accept(lpcb, inet_tcp_accept_cb);
    sock->state = SS_LISTENING;

    int ret = inet_recv_buf_init(is);
    if (ret < 0) {
        return ret;
    }
    return 0;
}

static int inet_tcp_connect(struct socket *sock, const struct sockaddr *addr,
                             int addrlen) {
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }

    if (addrlen < (int)sizeof(struct sockaddr_in)) {
        return -EINVAL;
    }
    if (sock->state == SS_CONNECTED) {
        return -EISCONN;
    }

    if (!is->pcb.tcp) {
        is->pcb.tcp = tcp_new();
        if (!is->pcb.tcp) {
            return -ENOMEM;
        }
    }

    int ret = inet_recv_buf_init(is);
    if (ret < 0) {
        return ret;
    }

    tcp_arg(is->pcb.tcp, is);
    tcp_recv(is->pcb.tcp, inet_tcp_recv_cb);
    tcp_sent(is->pcb.tcp, inet_tcp_sent_cb);
    tcp_err(is->pcb.tcp, inet_tcp_err_cb);

    ip_addr_t ip;
    u16_t port;
    sockaddr_to_lwip(addr, &ip, &port);

    is->connect_done = false;
    err_t err = tcp_connect(is->pcb.tcp, &ip, port, inet_tcp_connected_cb);
    if (err != ERR_OK) {
        return -ECONNREFUSED;
    }

    /* Wait for connection completion */
    mutex_lock(&is->lock);
    while (!is->connect_done) {
        int rc = proc_sleep_on_mutex(&is->connect_wait, &is->connect_wait,
                                     &is->lock, true);
        if (rc == -EINTR) {
            mutex_unlock(&is->lock);
            return -EINTR;
        }
    }
    ret = is->connect_err;
    mutex_unlock(&is->lock);

    if (ret == 0) {
        sock->state = SS_CONNECTED;
    }
    return ret;
}

static int inet_tcp_accept(struct socket *sock, struct socket **newsock) {
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }
    if (sock->state != SS_LISTENING) {
        return -EINVAL;
    }

    /* Wait for a pending connection */
    mutex_lock(&is->lock);
    while (list_empty(&is->accept_queue)) {
        int rc = proc_sleep_on_mutex(&is->accept_wait, &is->accept_wait,
                                     &is->lock, true);
        if (rc == -EINTR) {
            mutex_unlock(&is->lock);
            return -EINTR;
        }
    }

    struct inet_pending *pend = list_first_entry(&is->accept_queue,
                                                  struct inet_pending, node);
    list_del(&pend->node);
    is->accept_count--;
    mutex_unlock(&is->lock);

    /* Create a new socket for the accepted connection */
    struct socket *nsock = NULL;
    int ret = sock_create(AF_INET, SOCK_STREAM, 0, &nsock);
    if (ret < 0) {
        tcp_abort(pend->pcb);
        kfree(pend);
        return ret;
    }

    struct inet_sock *nis = inet_ensure(nsock);
    if (!nis) {
        tcp_abort(pend->pcb);
        kfree(pend);
        sock_destroy(nsock);
        return -ENOMEM;
    }

    ret = inet_recv_buf_init(nis);
    if (ret < 0) {
        tcp_abort(pend->pcb);
        kfree(pend);
        sock_destroy(nsock);
        return ret;
    }

    nis->pcb.tcp = pend->pcb;
    tcp_arg(pend->pcb, nis);
    tcp_recv(pend->pcb, inet_tcp_recv_cb);
    tcp_sent(pend->pcb, inet_tcp_sent_cb);
    tcp_err(pend->pcb, inet_tcp_err_cb);
    nsock->state = SS_CONNECTED;

    kfree(pend);
    *newsock = nsock;
    return 0;
}

static ssize_t inet_tcp_sendto(struct socket *sock, const void *buf,
                                size_t len, int flags,
                                const struct sockaddr *dest, int addrlen) {
    (void)flags; (void)dest; (void)addrlen;
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }
    if (sock->state != SS_CONNECTED || !is->pcb.tcp) {
        return -ENOTCONN;
    }

    mutex_lock(&is->lock);
    bool peer_closed = is->peer_closed;
    mutex_unlock(&is->lock);
    if (peer_closed)
        return -EPIPE;

    size_t total = 0;
    while (total < len) {
        u16_t sndbuf = tcp_sndbuf(is->pcb.tcp);
        if (sndbuf == 0) {
            /* Wait for send space */
            is->send_ready = false;
            mutex_lock(&is->lock);
            while (!is->send_ready && !is->peer_closed) {
                int rc = proc_sleep_on_mutex(&is->send_wait, &is->send_wait,
                                             &is->lock, true);
                if (rc == -EINTR) {
                    mutex_unlock(&is->lock);
                    return total ? (ssize_t)total : -EINTR;
                }
            }
            mutex_unlock(&is->lock);
            if (is->peer_closed) {
                return total ? (ssize_t)total : -EPIPE;
            }
            continue;
        }

        size_t chunk = len - total;
        if (chunk > sndbuf) {
            chunk = sndbuf;
        }
        if (chunk > 0xFFFF) {
            chunk = 0xFFFF;
        }

        err_t err = tcp_write(is->pcb.tcp, (const uint8_t *)buf + total,
                               (u16_t)chunk, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK) {
            return total ? (ssize_t)total : -EIO;
        }
        tcp_output(is->pcb.tcp);
        total += chunk;
    }

    return (ssize_t)total;
}

static ssize_t inet_tcp_recvfrom(struct socket *sock, void *buf, size_t len,
                                  int flags, struct sockaddr *src,
                                  int *addrlen) {
    (void)flags; (void)src; (void)addrlen;
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }
    if (sock->state != SS_CONNECTED) {
        return -ENOTCONN;
    }

    mutex_lock(&is->lock);
    while (is->recv_count == 0) {
        if (is->peer_closed) {
            mutex_unlock(&is->lock);
            return 0; /* EOF */
        }
        int rc = proc_sleep_on_mutex(&is->recv_wait, &is->recv_wait,
                                     &is->lock, true);
        if (rc == -EINTR) {
            mutex_unlock(&is->lock);
            return -EINTR;
        }
    }

    size_t n = inet_recv_buf_pop(is, buf, len);
    mutex_unlock(&is->lock);
    return (ssize_t)n;
}

static int inet_tcp_poll(struct socket *sock, uint32_t events) {
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return 0;
    }
    uint32_t revents = 0;

    mutex_lock(&is->lock);
    if (sock->state == SS_LISTENING) {
        if (!list_empty(&is->accept_queue)) {
            revents |= POLLIN;
        }
    } else if (sock->state == SS_CONNECTED) {
        if (is->recv_count > 0 || is->peer_closed) {
            revents |= POLLIN;
        }
        if (is->pcb.tcp && tcp_sndbuf(is->pcb.tcp) > 0) {
            revents |= POLLOUT;
        }
        if (is->peer_closed) {
            revents |= POLLHUP;
        }
    }
    mutex_unlock(&is->lock);

    return (int)(revents & events);
}

/* --- Proto ops (UDP / DGRAM) --- */

static int inet_udp_bind(struct socket *sock, const struct sockaddr *addr,
                          int addrlen) {
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }
    if (addrlen < (int)sizeof(struct sockaddr_in)) {
        return -EINVAL;
    }
    if (!is->pcb.udp) {
        is->pcb.udp = udp_new();
        if (!is->pcb.udp) {
            return -ENOMEM;
        }
        udp_recv(is->pcb.udp, inet_udp_recv_cb, is);
    }

    int ret = inet_recv_buf_init(is);
    if (ret < 0) {
        return ret;
    }

    ip_addr_t ip;
    u16_t port;
    sockaddr_to_lwip(addr, &ip, &port);

    err_t err = udp_bind(is->pcb.udp, &ip, port);
    if (err != ERR_OK) {
        return -EADDRINUSE;
    }
    sock->state = SS_BOUND;
    return 0;
}

static int inet_udp_connect(struct socket *sock, const struct sockaddr *addr,
                             int addrlen) {
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }
    if (addrlen < (int)sizeof(struct sockaddr_in)) {
        return -EINVAL;
    }
    if (!is->pcb.udp) {
        is->pcb.udp = udp_new();
        if (!is->pcb.udp) {
            return -ENOMEM;
        }
        udp_recv(is->pcb.udp, inet_udp_recv_cb, is);
        inet_recv_buf_init(is);
    }

    ip_addr_t ip;
    u16_t port;
    sockaddr_to_lwip(addr, &ip, &port);

    err_t err = udp_connect(is->pcb.udp, &ip, port);
    if (err != ERR_OK) {
        return -EINVAL;
    }
    sock->state = SS_CONNECTED;
    return 0;
}

static ssize_t inet_udp_sendto(struct socket *sock, const void *buf,
                                size_t len, int flags,
                                const struct sockaddr *dest, int addrlen) {
    (void)flags;
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }
    if (!is->pcb.udp) {
        is->pcb.udp = udp_new();
        if (!is->pcb.udp) {
            return -ENOMEM;
        }
        udp_recv(is->pcb.udp, inet_udp_recv_cb, is);
        inet_recv_buf_init(is);
    }

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
    if (!p) {
        return -ENOMEM;
    }
    memcpy(p->payload, buf, len);

    err_t err;
    if (dest && addrlen >= (int)sizeof(struct sockaddr_in)) {
        ip_addr_t ip;
        u16_t port;
        sockaddr_to_lwip(dest, &ip, &port);
        err = udp_sendto(is->pcb.udp, p, &ip, port);
    } else {
        err = udp_send(is->pcb.udp, p);
    }
    pbuf_free(p);

    return (err == ERR_OK) ? (ssize_t)len : -EIO;
}

static ssize_t inet_udp_recvfrom(struct socket *sock, void *buf, size_t len,
                                  int flags, struct sockaddr *src,
                                  int *addrlen) {
    (void)flags;
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return -ENOMEM;
    }

    mutex_lock(&is->lock);
    while (is->recv_count == 0) {
        int rc = proc_sleep_on_mutex(&is->recv_wait, &is->recv_wait,
                                     &is->lock, true);
        if (rc == -EINTR) {
            mutex_unlock(&is->lock);
            return -EINTR;
        }
    }

    size_t n = inet_recv_buf_pop(is, buf, len);

    if (src && addrlen && is->has_last_src) {
        int slen = (int)sizeof(struct sockaddr_in);
        if (*addrlen < slen) {
            slen = *addrlen;
        }
        memcpy(src, &is->last_src, (size_t)slen);
        *addrlen = (int)sizeof(struct sockaddr_in);
    }
    mutex_unlock(&is->lock);

    return (ssize_t)n;
}

static int inet_udp_poll(struct socket *sock, uint32_t events) {
    struct inet_sock *is = inet_ensure(sock);
    if (!is) {
        return 0;
    }
    uint32_t revents = 0;

    mutex_lock(&is->lock);
    if (is->recv_count > 0) {
        revents |= POLLIN;
    }
    revents |= POLLOUT; /* UDP send is always ready */
    mutex_unlock(&is->lock);

    return (int)(revents & events);
}

/* --- Common ops --- */

static int inet_shutdown(struct socket *sock, int how) {
    struct inet_sock *is = sock->proto_data;
    if (!is) {
        return -EINVAL;
    }

    is->shutdown_flags |= how;
    if (is->proto == IPPROTO_TCP && is->pcb.tcp) {
        int shut_rx = (how == SHUT_RD || how == SHUT_RDWR) ? 1 : 0;
        int shut_tx = (how == SHUT_WR || how == SHUT_RDWR) ? 1 : 0;
        tcp_shutdown(is->pcb.tcp, shut_rx, shut_tx);
    }
    wait_queue_wakeup_all(&is->recv_wait);
    wait_queue_wakeup_all(&is->send_wait);
    poll_wait_wake(&sock->pollers, POLLHUP);
    return 0;
}

static int inet_close(struct socket *sock) {
    struct inet_sock *is = sock->proto_data;
    if (!is) {
        return 0;
    }

    if (is->proto == IPPROTO_TCP && is->pcb.tcp) {
        struct tcp_pcb *pcb = is->pcb.tcp;
        bool listening = (pcb->state == LISTEN);
        tcp_arg(pcb, NULL);
        if (listening) {
            tcp_accept(pcb, NULL);
            tcp_close(pcb);
        } else {
            tcp_recv(pcb, NULL);
            tcp_sent(pcb, NULL);
            tcp_err(pcb, NULL);

            for (int i = 0; i < 2000; i++) {
                if (!pcb->unsent && !pcb->unacked)
                    break;
                tcp_output(pcb);
                proc_yield();
            }

            if (pcb->unsent || pcb->unacked) {
                tcp_abort(pcb);
            } else {
                tcp_close(pcb);
            }
        }
        is->pcb.tcp = NULL;
    } else if (is->proto == IPPROTO_UDP && is->pcb.udp) {
        udp_remove(is->pcb.udp);
        is->pcb.udp = NULL;
    }

    /* Drain accept queue */
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &is->accept_queue) {
        struct inet_pending *pend = list_entry(pos, struct inet_pending, node);
        list_del(&pend->node);
        tcp_abort(pend->pcb);
        kfree(pend);
    }

    if (is->recv_buf) {
        kfree(is->recv_buf);
    }
    sock->proto_data = NULL;
    kfree(is);
    return 0;
}

static int inet_getsockname(struct socket *sock, struct sockaddr *addr,
                             int *addrlen) {
    struct inet_sock *is = sock->proto_data;
    if (!is) {
        return -EINVAL;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;

    if (is->proto == IPPROTO_TCP && is->pcb.tcp) {
        lwip_to_sockaddr(sin, &is->pcb.tcp->local_ip,
                         is->pcb.tcp->local_port);
    } else if (is->proto == IPPROTO_UDP && is->pcb.udp) {
        lwip_to_sockaddr(sin, &is->pcb.udp->local_ip,
                         is->pcb.udp->local_port);
    }
    *addrlen = sizeof(struct sockaddr_in);
    return 0;
}

static int inet_getpeername(struct socket *sock, struct sockaddr *addr,
                             int *addrlen) {
    struct inet_sock *is = sock->proto_data;
    if (!is || sock->state != SS_CONNECTED) {
        return -ENOTCONN;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;

    if (is->proto == IPPROTO_TCP && is->pcb.tcp) {
        lwip_to_sockaddr(sin, &is->pcb.tcp->remote_ip,
                         is->pcb.tcp->remote_port);
    } else if (is->proto == IPPROTO_UDP && is->pcb.udp) {
        lwip_to_sockaddr(sin, &is->pcb.udp->remote_ip,
                         is->pcb.udp->remote_port);
    }
    *addrlen = sizeof(struct sockaddr_in);
    return 0;
}

static int inet_setsockopt(struct socket *sock, int level, int optname,
                            const void *optval, int optlen) {
    (void)sock; (void)level; (void)optname; (void)optval; (void)optlen;
    /* Silently accept common options */
    return 0;
}

static int inet_getsockopt(struct socket *sock, int level, int optname,
                            void *optval, int *optlen) {
    (void)sock; (void)level; (void)optname;
    if (optlen && *optlen >= (int)sizeof(int)) {
        *(int *)optval = 0;
        *optlen = sizeof(int);
    }
    return 0;
}

/* --- Proto ops tables --- */

static const struct proto_ops inet_stream_ops = {
    .bind       = inet_tcp_bind,
    .connect    = inet_tcp_connect,
    .listen     = inet_tcp_listen,
    .accept     = inet_tcp_accept,
    .sendto     = inet_tcp_sendto,
    .recvfrom   = inet_tcp_recvfrom,
    .shutdown   = inet_shutdown,
    .close      = inet_close,
    .poll       = inet_tcp_poll,
    .getsockname = inet_getsockname,
    .getpeername = inet_getpeername,
    .setsockopt = inet_setsockopt,
    .getsockopt = inet_getsockopt,
};

static const struct proto_ops inet_dgram_ops = {
    .bind       = inet_udp_bind,
    .connect    = inet_udp_connect,
    .listen     = NULL,
    .accept     = NULL,
    .sendto     = inet_udp_sendto,
    .recvfrom   = inet_udp_recvfrom,
    .shutdown   = inet_shutdown,
    .close      = inet_close,
    .poll       = inet_udp_poll,
    .getsockname = inet_getsockname,
    .getpeername = inet_getpeername,
    .setsockopt = inet_setsockopt,
    .getsockopt = inet_getsockopt,
};

void af_inet_init(void) {
    sock_register_family(AF_INET, &inet_stream_ops, &inet_dgram_ops);
    pr_info("af_inet: registered (lwIP backend)\n");
}
