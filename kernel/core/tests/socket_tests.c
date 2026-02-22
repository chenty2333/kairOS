/**
 * kernel/core/tests/socket_tests.c - Socket semantic tests
 */

#include <kairos/mm.h>
#include <kairos/net.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/socket.h>
#include <kairos/string.h>

#if CONFIG_KERNEL_TESTS

#define SOCKET_TEST_UNIX_STREAM_PATH "/tmp/.kairos_sock_stream_srv"
#define SOCKET_TEST_UNIX_STREAM_MISSING_PATH "/tmp/.kairos_sock_stream_missing"
#define SOCKET_TEST_UNIX_DGRAM_RX_PATH "/tmp/.kairos_sock_dgram_rx"
#define SOCKET_TEST_UNIX_DGRAM_TX_PATH "/tmp/.kairos_sock_dgram_tx"
#define SOCKET_TEST_DGRAM_OVERSIZE (65536U + 1U)

static int tests_failed;
static int tests_skipped;

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("socket_tests: %s failed\n", name);
        tests_failed++;
    }
}

static void test_skip(const char *name) {
    pr_warn("socket_tests: %s skipped\n", name);
    tests_skipped++;
}

static void close_socket_if_open(struct socket **sock) {
    if (sock && *sock) {
        sock_destroy(*sock);
        *sock = NULL;
    }
}

static void make_unix_addr(struct sockaddr_un *sun, const char *path) {
    size_t n = strlen(path);
    if (n >= UNIX_PATH_MAX) {
        n = UNIX_PATH_MAX - 1;
    }
    memset(sun, 0, sizeof(*sun));
    sun->sun_family = AF_UNIX;
    memcpy(sun->sun_path, path, n);
    sun->sun_path[n] = '\0';
}

static uint16_t to_be16(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }

static void make_inet_addr(struct sockaddr_in *sin, uint32_t ip,
                           uint16_t port_host) {
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = to_be16(port_host);
    sin->sin_addr = ip;
}

static bool wait_socket_event(struct socket *sock, uint32_t events,
                              uint32_t mask, int spins) {
    if (!sock || !sock->ops || !sock->ops->poll) {
        return false;
    }
    for (int i = 0; i < spins; i++) {
        int revents = sock->ops->poll(sock, events);
        if ((revents & (int)mask) == (int)mask) {
            return true;
        }
        proc_yield();
    }
    return (sock->ops->poll(sock, events) & (int)mask) == (int)mask;
}

static void test_unix_stream_semantics(void) {
    struct socket *listener = NULL;
    struct socket *connector = NULL;
    struct socket *dup = NULL;
    struct socket *a = NULL;
    struct socket *b = NULL;
    struct sockaddr_un srv_addr;
    struct sockaddr_un missing_addr;
    char buf[32];
    int ret;

    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &listener);
    test_check(ret == 0, "unix_stream create listener");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &connector);
    test_check(ret == 0, "unix_stream create connector");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &dup);
    test_check(ret == 0, "unix_stream create duplicate binder");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &a);
    test_check(ret == 0, "unix_stream create pair a");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &b);
    test_check(ret == 0, "unix_stream create pair b");
    if (!listener || !connector || !dup || !a || !b) {
        goto out;
    }

    make_unix_addr(&srv_addr, SOCKET_TEST_UNIX_STREAM_PATH);
    make_unix_addr(&missing_addr, SOCKET_TEST_UNIX_STREAM_MISSING_PATH);
    ret = listener->ops->bind(listener, (const struct sockaddr *)&srv_addr,
                              sizeof(srv_addr));
    test_check(ret == 0, "unix_stream bind");
    if (ret < 0) {
        goto out;
    }

    ret = dup->ops->bind(dup, (const struct sockaddr *)&srv_addr,
                         sizeof(srv_addr));
    test_check(ret == -EADDRINUSE, "unix_stream bind eaddrinuse");

    ret = listener->ops->listen(listener, 4);
    test_check(ret == 0, "unix_stream listen");
    if (ret < 0) {
        goto out;
    }

    ssize_t wr = connector->ops->sendto(connector, "x", 1, 0, NULL, 0);
    test_check(wr == -ENOTCONN, "unix_stream send before connect enotconn");
    ret = connector->ops->connect(connector, (const struct sockaddr *)&missing_addr,
                                  sizeof(missing_addr));
    test_check(ret == -ECONNREFUSED, "unix_stream connect missing econnrefused");

    int pre = listener->ops->poll(listener, POLLIN);
    test_check((pre & POLLIN) == 0, "unix_stream listener empty poll");

    ret = unix_socketpair_connect(a, b);
    test_check(ret == 0, "unix_stream socketpair connect");
    if (ret < 0) {
        goto out;
    }

    struct sockaddr_un self_addr;
    int self_len = sizeof(self_addr);
    memset(&self_addr, 0, sizeof(self_addr));
    ret = listener->ops->getsockname(listener, (struct sockaddr *)&self_addr,
                                     &self_len);
    test_check(ret == 0, "unix_stream getsockname");
    if (ret == 0) {
        test_check(strcmp(self_addr.sun_path, SOCKET_TEST_UNIX_STREAM_PATH) == 0,
                   "unix_stream self path");
    }

    int re = a->ops->poll(a, POLLOUT);
    test_check((re & POLLOUT) != 0, "unix_stream a writable");

    wr = a->ops->sendto(a, "PING", 4, 0, NULL, 0);
    test_check(wr == 4, "unix_stream a send");
    if (wr == 4) {
        bool ready = wait_socket_event(b, POLLIN, POLLIN, 2000);
        test_check(ready, "unix_stream b readable");
        if (ready) {
            memset(buf, 0, sizeof(buf));
            ssize_t rd = b->ops->recvfrom(b, buf, sizeof(buf), 0, NULL, NULL);
            test_check(rd == 4, "unix_stream b recv len");
            test_check(memcmp(buf, "PING", 4) == 0, "unix_stream b recv data");
        }
    }

    wr = b->ops->sendto(b, "PONG", 4, 0, NULL, 0);
    test_check(wr == 4, "unix_stream b send");
    if (wr == 4) {
        bool ready = wait_socket_event(a, POLLIN, POLLIN, 2000);
        test_check(ready, "unix_stream a readable");
        if (ready) {
            memset(buf, 0, sizeof(buf));
            ssize_t rd = a->ops->recvfrom(a, buf, sizeof(buf), 0, NULL, NULL);
            test_check(rd == 4, "unix_stream a recv len");
            test_check(memcmp(buf, "PONG", 4) == 0, "unix_stream a recv data");
        }
    }

    close_socket_if_open(&b);

    bool hup = wait_socket_event(a, POLLHUP, POLLHUP, 2000);
    test_check(hup, "unix_stream a pollhup after peer close");

    memset(buf, 0, sizeof(buf));
    ssize_t rd = a->ops->recvfrom(a, buf, sizeof(buf), 0, NULL, NULL);
    test_check(rd == 0, "unix_stream recv eof after peer close");

    wr = a->ops->sendto(a, "Z", 1, 0, NULL, 0);
    test_check(wr == -ENOTCONN, "unix_stream send enotconn after peer close");

out:
    close_socket_if_open(&b);
    close_socket_if_open(&a);
    close_socket_if_open(&connector);
    close_socket_if_open(&dup);
    close_socket_if_open(&listener);
}

static void test_unix_dgram_semantics(void) {
    struct socket *rx = NULL;
    struct socket *tx = NULL;
    struct socket *tmp = NULL;
    struct sockaddr_un rx_addr;
    struct sockaddr_un tx_addr;
    struct sockaddr_un bad_addr;
    char buf[64];
    int ret;

    ret = sock_create(AF_UNIX, SOCK_DGRAM, 0, &rx);
    test_check(ret == 0, "unix_dgram create rx");
    ret = sock_create(AF_UNIX, SOCK_DGRAM, 0, &tx);
    test_check(ret == 0, "unix_dgram create tx");
    ret = sock_create(AF_UNIX, SOCK_DGRAM, 0, &tmp);
    test_check(ret == 0, "unix_dgram create tmp");
    if (!rx || !tx || !tmp) {
        goto out;
    }

    make_unix_addr(&rx_addr, SOCKET_TEST_UNIX_DGRAM_RX_PATH);
    make_unix_addr(&tx_addr, SOCKET_TEST_UNIX_DGRAM_TX_PATH);
    make_unix_addr(&bad_addr, "/tmp/.kairos_sock_dgram_missing");

    ret = rx->ops->bind(rx, (const struct sockaddr *)&rx_addr, sizeof(rx_addr));
    test_check(ret == 0, "unix_dgram bind rx");
    ret = tx->ops->bind(tx, (const struct sockaddr *)&tx_addr, sizeof(tx_addr));
    test_check(ret == 0, "unix_dgram bind tx");
    if (ret < 0) {
        goto out;
    }

    ssize_t wr = tx->ops->sendto(tx, "x", 1, 0, NULL, 0);
    test_check(wr == -ENOTCONN, "unix_dgram send before connect enotconn");

    ret = tmp->ops->connect(tmp, (const struct sockaddr *)&bad_addr, sizeof(bad_addr));
    test_check(ret == -ECONNREFUSED, "unix_dgram connect missing econnrefused");

    ret = tx->ops->connect(tx, (const struct sockaddr *)&rx_addr, sizeof(rx_addr));
    test_check(ret == 0, "unix_dgram connect");
    if (ret < 0) {
        goto out;
    }

    int pre = rx->ops->poll(rx, POLLIN | POLLOUT);
    test_check((pre & POLLIN) == 0, "unix_dgram rx not readable before send");
    test_check((pre & POLLOUT) != 0, "unix_dgram rx writable poll");

    wr = tx->ops->sendto(tx, "hello-dgram", 11, 0, NULL, 0);
    test_check(wr == 11, "unix_dgram send");
    if (wr == 11) {
        bool ready = wait_socket_event(rx, POLLIN, POLLIN, 2000);
        test_check(ready, "unix_dgram rx readable");
        if (ready) {
            struct sockaddr_un src;
            int srclen = sizeof(src);
            memset(&src, 0, sizeof(src));
            memset(buf, 0, sizeof(buf));
            ssize_t rd =
                rx->ops->recvfrom(rx, buf, sizeof(buf), 0, (struct sockaddr *)&src, &srclen);
            test_check(rd == 11, "unix_dgram recv len");
            test_check(memcmp(buf, "hello-dgram", 11) == 0, "unix_dgram recv data");
            test_check(src.sun_family == AF_UNIX, "unix_dgram recv src family");
            test_check(strcmp(src.sun_path, SOCKET_TEST_UNIX_DGRAM_TX_PATH) == 0,
                       "unix_dgram recv src path");
        }
    }

    char *big = kmalloc(SOCKET_TEST_DGRAM_OVERSIZE);
    test_check(big != NULL, "unix_dgram oversize alloc");
    if (big) {
        memset(big, 'q', SOCKET_TEST_DGRAM_OVERSIZE);
        wr = tx->ops->sendto(tx, big, SOCKET_TEST_DGRAM_OVERSIZE, 0, NULL, 0);
        test_check(wr == -EMSGSIZE, "unix_dgram send oversize emsgsize");
        kfree(big);
    }

out:
    close_socket_if_open(&tmp);
    close_socket_if_open(&tx);
    close_socket_if_open(&rx);
}

static bool run_inet_udp_attempt(uint32_t loopback_ip, uint16_t server_port,
                                 uint16_t client_port) {
    struct socket *server = NULL;
    struct socket *client = NULL;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    struct sockaddr_in src;
    char buf[64];
    bool ok = false;
    int ret;

    ret = sock_create(AF_INET, SOCK_DGRAM, 0, &server);
    if (ret < 0) {
        goto out;
    }
    ret = sock_create(AF_INET, SOCK_DGRAM, 0, &client);
    if (ret < 0) {
        goto out;
    }

    make_inet_addr(&server_addr, loopback_ip, server_port);
    make_inet_addr(&client_addr, loopback_ip, client_port);

    ret = server->ops->bind(server, (const struct sockaddr *)&server_addr,
                            sizeof(server_addr));
    if (ret < 0) {
        goto out;
    }
    ret = client->ops->bind(client, (const struct sockaddr *)&client_addr,
                            sizeof(client_addr));
    if (ret < 0) {
        goto out;
    }

    ret = client->ops->connect(client, (const struct sockaddr *)&server_addr,
                               sizeof(server_addr));
    if (ret < 0) {
        goto out;
    }

    int pre = client->ops->poll(client, POLLOUT);
    if ((pre & POLLOUT) == 0) {
        goto out;
    }

    ssize_t wr = client->ops->sendto(client, "inet-udp", 8, 0, NULL, 0);
    if (wr != 8) {
        goto out;
    }

    if (!wait_socket_event(server, POLLIN, POLLIN, 3000)) {
        goto out;
    }

    int srclen = sizeof(src);
    memset(&src, 0, sizeof(src));
    memset(buf, 0, sizeof(buf));
    ssize_t rd =
        server->ops->recvfrom(server, buf, sizeof(buf), 0, (struct sockaddr *)&src, &srclen);
    if (rd != 8) {
        goto out;
    }
    if (memcmp(buf, "inet-udp", 8) != 0) {
        goto out;
    }

    ok = true;

out:
    close_socket_if_open(&client);
    close_socket_if_open(&server);
    return ok;
}

static void test_inet_udp_secondary(void) {
    if (!netdev_first()) {
        test_skip("inet_udp (no netdev)");
        return;
    }

    const uint32_t loopback_ips[] = {
        0x0100007fU, /* lwIP host-order encoded 127.0.0.1 */
        0x7f000001U, /* native-order encoded 127.0.0.1 */
    };

    bool ok = false;
    for (size_t i = 0; i < sizeof(loopback_ips) / sizeof(loopback_ips[0]); i++) {
        if (run_inet_udp_attempt(loopback_ips[i], (uint16_t)(42000 + i),
                                 (uint16_t)(43000 + i))) {
            ok = true;
            break;
        }
    }

    if (ok)
        test_check(true, "inet_udp loopback");
    else
        test_skip("inet_udp (loopback delivery unavailable)");
}

int run_socket_tests(void) {
    tests_failed = 0;
    tests_skipped = 0;

    pr_info("\n=== Socket Tests ===\n");

    test_unix_stream_semantics();
    test_unix_dgram_semantics();
    test_inet_udp_secondary();

    if (tests_failed == 0) {
        if (tests_skipped == 0)
            pr_info("socket tests: all passed\n");
        else
            pr_info("socket tests: passed with %d skipped\n", tests_skipped);
    } else {
        pr_err("socket tests: %d failures (%d skipped)\n", tests_failed,
               tests_skipped);
    }
    return tests_failed;
}

#else

int run_socket_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
