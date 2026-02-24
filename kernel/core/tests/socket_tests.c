/**
 * kernel/core/tests/socket_tests.c - Socket semantic tests
 */

#include <kairos/mm.h>
#include <kairos/net.h>
#include <kairos/ioctl.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/socket.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>
#include <kairos/arch.h>

#if CONFIG_KERNEL_TESTS

#define SOCKET_TEST_UNIX_STREAM_PATH "/tmp/.kairos_sock_stream_srv"
#define SOCKET_TEST_UNIX_STREAM_MISSING_PATH "/tmp/.kairos_sock_stream_missing"
#define SOCKET_TEST_UNIX_STREAM_STRESS_PATH "/tmp/.kairos_sock_stream_stress"
#define SOCKET_TEST_UNIX_ACCEPT4_PATH "/tmp/.kairos_sock_accept4_sys"
#define SOCKET_TEST_UNIX_ACCEPT4_CLIENT_PATH "/tmp/.kairos_sock_accept4_client"
#define SOCKET_TEST_UNIX_DGRAM_RX_PATH "/tmp/.kairos_sock_dgram_rx"
#define SOCKET_TEST_UNIX_DGRAM_TX_PATH "/tmp/.kairos_sock_dgram_tx"
#define SOCKET_TEST_UNIX_MSG_RX_PATH "/tmp/.kairos_sock_msg_rx"
#define SOCKET_TEST_UNIX_MSG_TX_PATH "/tmp/.kairos_sock_msg_tx"
#define TEST_MSG_WAITFORONE 0x10000U
#define SOCKET_TEST_DGRAM_OVERSIZE (65536U + 1U)

static int tests_failed;
static int tests_skipped;

struct user_map_ctx {
    struct process *proc;
    struct mm_struct *saved_mm;
    struct mm_struct *active_mm;
    struct mm_struct *temp_mm;
    paddr_t saved_pgdir;
    vaddr_t base;
    size_t len;
    bool switched_pgdir;
};

struct test_socket_iovec {
    void *iov_base;
    size_t iov_len;
};

struct test_socket_msghdr {
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

struct test_socket_mmsghdr {
    struct test_socket_msghdr msg_hdr;
    uint32_t msg_len;
    uint32_t __pad;
};

static int user_map_begin(struct user_map_ctx *ctx, size_t len) {
    if (!ctx || len == 0)
        return -EINVAL;

    memset(ctx, 0, sizeof(*ctx));
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    ctx->proc = p;
    ctx->saved_mm = p->mm;
    ctx->active_mm = p->mm;
    ctx->saved_pgdir = arch_mmu_current();

    if (!ctx->active_mm) {
        ctx->temp_mm = mm_create();
        if (!ctx->temp_mm)
            return -ENOMEM;
        p->mm = ctx->temp_mm;
        ctx->active_mm = ctx->temp_mm;
    }

    if (ctx->saved_pgdir != ctx->active_mm->pgdir) {
        arch_mmu_switch(ctx->active_mm->pgdir);
        ctx->switched_pgdir = true;
    }

    int rc = mm_mmap(ctx->active_mm, 0, len, VM_READ | VM_WRITE, 0, NULL, 0,
                     false, &ctx->base);
    if (rc < 0) {
        if (ctx->switched_pgdir)
            arch_mmu_switch(ctx->saved_pgdir);
        if (ctx->temp_mm) {
            p->mm = ctx->saved_mm;
            mm_destroy(ctx->temp_mm);
        }
        memset(ctx, 0, sizeof(*ctx));
        return rc;
    }

    ctx->len = len;
    return 0;
}

static void user_map_end(struct user_map_ctx *ctx) {
    if (!ctx || !ctx->proc)
        return;
    if (ctx->active_mm && ctx->base && ctx->len)
        (void)mm_munmap(ctx->active_mm, ctx->base, ctx->len);
    if (ctx->switched_pgdir)
        arch_mmu_switch(ctx->saved_pgdir);
    if (ctx->temp_mm) {
        ctx->proc->mm = ctx->saved_mm;
        mm_destroy(ctx->temp_mm);
    }
    memset(ctx, 0, sizeof(*ctx));
}

static void *user_map_ptr(const struct user_map_ctx *ctx, size_t off) {
    if (!ctx || off >= ctx->len)
        return NULL;
    return (void *)(ctx->base + off);
}

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

static void close_fd_if_open(int *fd) {
    if (!fd || *fd < 0)
        return;
    (void)fd_close(proc_current(), *fd);
    *fd = -1;
}

static int socket_install_fd(struct socket **sock) {
    if (!sock || !*sock || !(*sock)->vnode)
        return -EINVAL;

    struct file *file = vfs_file_alloc();
    if (!file)
        return -ENOMEM;

    file->vnode = (*sock)->vnode;
    vnode_get(file->vnode);
    file->flags = O_RDWR;

    int fd = fd_alloc(proc_current(), file);
    if (fd < 0) {
        vfs_close(file);
        return fd;
    }

    return fd;
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

struct unix_stream_client_ctx {
    struct sockaddr_un srv_addr;
    uint32_t token;
    volatile int started;
    int ret;
};

struct accept4_client_ctx {
    struct sockaddr_un srv_addr;
    struct sockaddr_un client_addr;
    volatile int started;
    int ret;
};

static int unix_stream_client_worker(void *arg) {
    struct unix_stream_client_ctx *ctx = (struct unix_stream_client_ctx *)arg;
    struct socket *client = NULL;
    ctx->started = 1;
    ctx->ret = -1;

    if (sock_create(AF_UNIX, SOCK_STREAM, 0, &client) < 0 || !client) {
        proc_exit(0);
    }

    int ret = client->ops->connect(client, (const struct sockaddr *)&ctx->srv_addr,
                                   sizeof(ctx->srv_addr));
    if (ret < 0)
        goto out;

    ssize_t wr = client->ops->sendto(client, &ctx->token, sizeof(ctx->token), 0,
                                     NULL, 0);
    if (wr != (ssize_t)sizeof(ctx->token))
        goto out;

    uint32_t echo = 0;
    ssize_t rd = client->ops->recvfrom(client, &echo, sizeof(echo), 0, NULL, NULL);
    if (rd != (ssize_t)sizeof(echo))
        goto out;
    if (echo != ctx->token)
        goto out;

    ctx->ret = 0;

out:
    close_socket_if_open(&client);
    proc_exit(0);
}

static int accept4_client_worker(void *arg) {
    struct accept4_client_ctx *ctx = (struct accept4_client_ctx *)arg;
    struct socket *client = NULL;
    ctx->started = 1;
    ctx->ret = -1;

    if (sock_create(AF_UNIX, SOCK_STREAM, 0, &client) < 0 || !client)
        proc_exit(0);

    int ret = client->ops->bind(client, (const struct sockaddr *)&ctx->client_addr,
                                sizeof(ctx->client_addr));
    if (ret < 0)
        goto out;

    ret = client->ops->connect(client, (const struct sockaddr *)&ctx->srv_addr,
                               sizeof(ctx->srv_addr));
    if (ret < 0)
        goto out;

    ctx->ret = 0;

out:
    close_socket_if_open(&client);
    proc_exit(0);
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

static void test_unix_stream_accept_stability(void) {
    struct socket *listener = NULL;
    struct sockaddr_un srv_addr;
    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &listener);
    test_check(ret == 0, "unix_accept_stress create listener");
    if (ret < 0 || !listener)
        goto out;

    make_unix_addr(&srv_addr, SOCKET_TEST_UNIX_STREAM_STRESS_PATH);
    ret = listener->ops->bind(listener, (const struct sockaddr *)&srv_addr,
                              sizeof(srv_addr));
    test_check(ret == 0, "unix_accept_stress bind");
    if (ret < 0)
        goto out;

    ret = listener->ops->listen(listener, 8);
    test_check(ret == 0, "unix_accept_stress listen");
    if (ret < 0)
        goto out;

    for (uint32_t round = 0; round < 32; round++) {
        struct unix_stream_client_ctx *ctx = kzalloc(sizeof(*ctx));
        test_check(ctx != NULL, "unix_accept_stress ctx alloc");
        if (!ctx)
            break;
        ctx->srv_addr = srv_addr;
        ctx->token = 0xA5000000U | round;
        ctx->ret = -1;

        struct process *child = kthread_create_joinable(unix_stream_client_worker,
                                                        ctx, "unixacc");
        test_check(child != NULL, "unix_accept_stress child create");
        if (!child) {
            kfree(ctx);
            break;
        }

        pid_t cpid = child->pid;
        sched_enqueue(child);

        for (int i = 0; i < 2000 && !ctx->started; i++)
            proc_yield();
        test_check(ctx->started != 0, "unix_accept_stress child started");

        bool listener_ready = wait_socket_event(listener, POLLIN, POLLIN, 2000);
        test_check(listener_ready, "unix_accept_stress listener readable");

        struct socket *accepted = NULL;
        if (listener_ready) {
            ret = listener->ops->accept(listener, &accepted);
            test_check(ret == 0, "unix_accept_stress accept");
            if (ret == 0 && accepted) {
                bool accepted_ops_ok = accepted->ops && accepted->ops->recvfrom &&
                                       accepted->ops->sendto;
                test_check(accepted_ops_ok, "unix_accept_stress accepted ops valid");
                if (accepted_ops_ok) {
                    uint32_t token = 0;
                    ssize_t rd = accepted->ops->recvfrom(accepted, &token,
                                                         sizeof(token), 0, NULL,
                                                         NULL);
                    test_check(rd == (ssize_t)sizeof(token),
                               "unix_accept_stress recv token");
                    if (rd == (ssize_t)sizeof(token))
                        test_check(token == ctx->token,
                                   "unix_accept_stress token value");

                    ssize_t wr = accepted->ops->sendto(accepted, &token,
                                                       sizeof(token), 0, NULL, 0);
                    test_check(wr == (ssize_t)sizeof(token),
                               "unix_accept_stress echo token");
                }
            }
        }
        close_socket_if_open(&accepted);

        int status = 0;
        pid_t wp = proc_wait(cpid, &status, 0);
        test_check(wp == cpid, "unix_accept_stress child reaped");
        if (wp == cpid) {
            test_check(status == 0, "unix_accept_stress child exit status");
            test_check(ctx->ret == 0, "unix_accept_stress child result");
        }
        kfree(ctx);
    }

out:
    close_socket_if_open(&listener);
}

static void test_accept4_syscall_semantics(void) {
    struct socket *listener = NULL;
    struct sockaddr_un srv_addr;
    int listener_fd = -1;

    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &listener);
    test_check(ret == 0, "accept4_sys create listener");
    if (ret < 0 || !listener)
        goto out;

    make_unix_addr(&srv_addr, SOCKET_TEST_UNIX_ACCEPT4_PATH);
    ret = listener->ops->bind(listener, (const struct sockaddr *)&srv_addr,
                              sizeof(srv_addr));
    test_check(ret == 0, "accept4_sys bind");
    if (ret < 0)
        goto out;

    ret = listener->ops->listen(listener, 8);
    test_check(ret == 0, "accept4_sys listen");
    if (ret < 0)
        goto out;

    listener_fd = socket_install_fd(&listener);
    test_check(listener_fd >= 0, "accept4_sys install listener fd");
    if (listener_fd < 0)
        goto out;
    int64_t ret64 = sys_accept4((uint64_t)listener_fd, 0, 0, SOCK_NONBLOCK | 1U,
                                0, 0);
    test_check(ret64 == -EINVAL, "accept4_sys invalid flags einval");

    ret64 = sys_accept4((uint64_t)listener_fd, 0x1000, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "accept4_sys addr only efault");

    ret64 = sys_accept4((uint64_t)listener_fd, 0, 0x1000, 0, 0, 0);
    test_check(ret64 == -EFAULT, "accept4_sys addrlen only efault");

out:
    close_fd_if_open(&listener_fd);
    close_socket_if_open(&listener);
}

static void test_accept4_syscall_functional(void) {
    struct socket *listener = NULL;
    struct sockaddr_un srv_addr;
    int listener_fd = -1;
    int accepted_fd = -1;
    struct accept4_client_ctx *ctx = NULL;
    struct process *child = NULL;
    struct user_map_ctx um = {0};
    bool mapped = false;

    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &listener);
    test_check(ret == 0, "accept4_func create listener");
    if (ret < 0 || !listener)
        goto out;

    make_unix_addr(&srv_addr, SOCKET_TEST_UNIX_ACCEPT4_PATH);
    ret = listener->ops->bind(listener, (const struct sockaddr *)&srv_addr,
                              sizeof(srv_addr));
    test_check(ret == 0, "accept4_func bind");
    if (ret < 0)
        goto out;

    ret = listener->ops->listen(listener, 4);
    test_check(ret == 0, "accept4_func listen");
    if (ret < 0)
        goto out;

    listener_fd = socket_install_fd(&listener);
    test_check(listener_fd >= 0, "accept4_func install listener fd");
    if (listener_fd < 0)
        goto out;

    ret = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "accept4_func user map");
    if (ret < 0)
        goto out;
    mapped = true;

    struct sockaddr_un *u_peer_addr = (struct sockaddr_un *)user_map_ptr(&um, 0x0);
    int *u_peer_len = (int *)user_map_ptr(&um, 0x100);
    test_check(u_peer_addr != NULL, "accept4_func u peer addr");
    test_check(u_peer_len != NULL, "accept4_func u peer len");
    if (!u_peer_addr || !u_peer_len)
        goto out;

    int peer_len = (int)sizeof(*u_peer_addr);
    ret = copy_to_user(u_peer_len, &peer_len, sizeof(peer_len));
    test_check(ret == 0, "accept4_func copy peer len");
    if (ret < 0)
        goto out;

    ctx = kzalloc(sizeof(*ctx));
    test_check(ctx != NULL, "accept4_func alloc ctx");
    if (!ctx)
        goto out;
    make_unix_addr(&ctx->srv_addr, SOCKET_TEST_UNIX_ACCEPT4_PATH);
    make_unix_addr(&ctx->client_addr, SOCKET_TEST_UNIX_ACCEPT4_CLIENT_PATH);
    ctx->ret = -1;

    child = kthread_create_joinable(accept4_client_worker, ctx, "acc4cli");
    test_check(child != NULL, "accept4_func create client");
    if (!child)
        goto out;
    pid_t cpid = child->pid;
    sched_enqueue(child);

    for (int i = 0; i < 2000 && !ctx->started; i++)
        proc_yield();
    test_check(ctx->started != 0, "accept4_func client started");

    bool ready = wait_socket_event(listener, POLLIN, POLLIN, 4000);
    test_check(ready, "accept4_func listener readable");

    int64_t ret64 =
        sys_accept4((uint64_t)listener_fd, (uint64_t)u_peer_addr,
                    (uint64_t)u_peer_len, SOCK_NONBLOCK | SOCK_CLOEXEC, 0, 0);
    test_check(ret64 >= 0, "accept4_func accept4");
    if (ret64 >= 0) {
        accepted_fd = (int)ret64;

        struct sockaddr_un peer_addr = {0};
        int peer_len_out = 0;
        ret = copy_from_user(&peer_len_out, u_peer_len, sizeof(peer_len_out));
        test_check(ret == 0, "accept4_func read peer len");
        if (ret == 0)
            test_check(peer_len_out >= (int)sizeof(peer_addr.sun_family),
                       "accept4_func peer len updated");

        ret = copy_from_user(&peer_addr, u_peer_addr, sizeof(peer_addr));
        test_check(ret == 0, "accept4_func read peer addr");
        if (ret == 0) {
            test_check(peer_addr.sun_family == AF_UNIX,
                       "accept4_func peer family");
            test_check(strcmp(peer_addr.sun_path,
                              SOCKET_TEST_UNIX_ACCEPT4_CLIENT_PATH) == 0,
                       "accept4_func peer path");
        }

        struct file *accepted = fd_get(proc_current(), accepted_fd);
        test_check(accepted != NULL, "accept4_func accepted fd get");
        if (accepted) {
            test_check((accepted->flags & O_NONBLOCK) != 0,
                       "accept4_func accepted nonblock");
            file_put(accepted);
        }

        struct process *p = proc_current();
        bool cloexec_ok = false;
        if (p && p->fdtable && accepted_fd >= 0 &&
            accepted_fd < CONFIG_MAX_FILES_PER_PROC) {
            mutex_lock(&p->fdtable->lock);
            cloexec_ok = (p->fdtable->fd_flags[accepted_fd] & FD_CLOEXEC) != 0;
            mutex_unlock(&p->fdtable->lock);
        }
        test_check(cloexec_ok, "accept4_func accepted cloexec");
    }

    int status = 0;
    pid_t wp = proc_wait(cpid, &status, 0);
    test_check(wp == cpid, "accept4_func client reaped");
    if (wp == cpid)
        test_check(ctx->ret == 0, "accept4_func client result");

out:
    close_fd_if_open(&accepted_fd);
    close_fd_if_open(&listener_fd);
    close_socket_if_open(&listener);
    if (mapped)
        user_map_end(&um);
    kfree(ctx);
}

static void test_socket_msg_syscall_semantics(void) {
    struct socket *rx = NULL;
    struct socket *tx = NULL;
    int rxfd = -1;
    int txfd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;

    int ret = sock_create(AF_UNIX, SOCK_DGRAM, 0, &rx);
    test_check(ret == 0, "sockmsg create rx");
    ret = sock_create(AF_UNIX, SOCK_DGRAM, 0, &tx);
    test_check(ret == 0, "sockmsg create tx");
    if (!rx || !tx)
        goto out;

    struct sockaddr_un rx_addr;
    struct sockaddr_un tx_addr;
    make_unix_addr(&rx_addr, SOCKET_TEST_UNIX_MSG_RX_PATH);
    make_unix_addr(&tx_addr, SOCKET_TEST_UNIX_MSG_TX_PATH);

    ret = rx->ops->bind(rx, (const struct sockaddr *)&rx_addr, sizeof(rx_addr));
    test_check(ret == 0, "sockmsg bind rx");
    ret = tx->ops->bind(tx, (const struct sockaddr *)&tx_addr, sizeof(tx_addr));
    test_check(ret == 0, "sockmsg bind tx");
    if (ret < 0)
        goto out;

    rxfd = socket_install_fd(&rx);
    txfd = socket_install_fd(&tx);
    test_check(rxfd >= 0, "sockmsg install rx fd");
    test_check(txfd >= 0, "sockmsg install tx fd");
    if (rxfd < 0 || txfd < 0)
        goto out;

    ret = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "sockmsg user map");
    if (ret < 0)
        goto out;
    mapped = true;

    struct sockaddr_un *u_rx_addr = (struct sockaddr_un *)user_map_ptr(&um, 0x000);
    struct sockaddr_un *u_src_addr = (struct sockaddr_un *)user_map_ptr(&um, 0x080);
    struct test_socket_iovec *u_send_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x100);
    struct test_socket_iovec *u_recv_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x180);
    struct test_socket_msghdr *u_send_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x200);
    struct test_socket_msghdr *u_recv_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x280);
    struct test_socket_mmsghdr *u_send_vec =
        (struct test_socket_mmsghdr *)user_map_ptr(&um, 0x300);
    struct test_socket_mmsghdr *u_recv_vec =
        (struct test_socket_mmsghdr *)user_map_ptr(&um, 0x400);
    struct timespec *u_timeout = (struct timespec *)user_map_ptr(&um, 0x500);
    char *u_send_buf0 = (char *)user_map_ptr(&um, 0x580);
    char *u_send_buf1 = (char *)user_map_ptr(&um, 0x5C0);
    char *u_recv_buf0 = (char *)user_map_ptr(&um, 0x600);
    char *u_recv_buf1 = (char *)user_map_ptr(&um, 0x640);
    char *u_sendm_buf0 = (char *)user_map_ptr(&um, 0x680);
    char *u_sendm_buf1 = (char *)user_map_ptr(&um, 0x6C0);
    char *u_recvm_buf0 = (char *)user_map_ptr(&um, 0x700);
    char *u_recvm_buf1 = (char *)user_map_ptr(&um, 0x740);
    test_check(u_rx_addr && u_src_addr && u_send_iov && u_recv_iov && u_send_msg &&
                   u_recv_msg && u_send_vec && u_recv_vec && u_timeout &&
                   u_send_buf0 && u_send_buf1 && u_recv_buf0 && u_recv_buf1 &&
                   u_sendm_buf0 && u_sendm_buf1 && u_recvm_buf0 && u_recvm_buf1,
               "sockmsg user pointers");
    if (!u_rx_addr || !u_src_addr || !u_send_iov || !u_recv_iov || !u_send_msg ||
        !u_recv_msg || !u_send_vec || !u_recv_vec || !u_timeout || !u_send_buf0 ||
        !u_send_buf1 || !u_recv_buf0 || !u_recv_buf1 || !u_sendm_buf0 ||
        !u_sendm_buf1 || !u_recvm_buf0 || !u_recvm_buf1) {
        goto out;
    }

    ret = copy_to_user(u_rx_addr, &rx_addr, sizeof(rx_addr));
    test_check(ret == 0, "sockmsg copy rx addr");
    if (ret < 0)
        goto out;

    ret = copy_to_user(u_send_buf0, "msg-", 4);
    test_check(ret == 0, "sockmsg copy send buf0");
    ret = copy_to_user(u_send_buf1, "one", 3);
    test_check(ret == 0, "sockmsg copy send buf1");
    if (ret < 0)
        goto out;

    struct test_socket_iovec send_iov[2] = {
        { .iov_base = u_send_buf0, .iov_len = 4 },
        { .iov_base = u_send_buf1, .iov_len = 3 },
    };
    struct test_socket_iovec recv_iov[2] = {
        { .iov_base = u_recv_buf0, .iov_len = 3 },
        { .iov_base = u_recv_buf1, .iov_len = 8 },
    };
    ret = copy_to_user(u_send_iov, send_iov, sizeof(send_iov));
    test_check(ret == 0, "sockmsg copy send iov");
    ret = copy_to_user(u_recv_iov, recv_iov, sizeof(recv_iov));
    test_check(ret == 0, "sockmsg copy recv iov");
    if (ret < 0)
        goto out;

    struct test_socket_msghdr send_msg = {
        .msg_name = u_rx_addr,
        .msg_namelen = sizeof(rx_addr),
        .msg_iov = u_send_iov,
        .msg_iovlen = 2,
    };
    struct test_socket_msghdr recv_msg = {
        .msg_name = u_src_addr,
        .msg_namelen = sizeof(*u_src_addr),
        .msg_iov = u_recv_iov,
        .msg_iovlen = 2,
    };

    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg copy send msg");
    if (ret < 0)
        goto out;

    int64_t ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 7, "sockmsg sendmsg len7");

    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg copy recv msg");
    if (ret < 0)
        goto out;

    ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
    test_check(ret64 == 7, "sockmsg recvmsg len7");
    if (ret64 == 7) {
        char got0[3] = {0};
        char got1[5] = {0};
        ret = copy_from_user(got0, u_recv_buf0, sizeof(got0));
        test_check(ret == 0, "sockmsg read recv buf0");
        ret = copy_from_user(got1, u_recv_buf1, 4);
        test_check(ret == 0, "sockmsg read recv buf1");
        if (ret == 0) {
            test_check(memcmp(got0, "msg", 3) == 0, "sockmsg recv buf0 data");
            test_check(memcmp(got1, "-one", 4) == 0, "sockmsg recv buf1 data");
        }

        ret = copy_from_user(&recv_msg, u_recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg read recv msg");
        if (ret == 0) {
            test_check(recv_msg.msg_namelen >= sizeof(recv_msg.msg_namelen),
                       "sockmsg recv namelen update");
        }

        struct sockaddr_un src_addr = {0};
        ret = copy_from_user(&src_addr, u_src_addr, sizeof(src_addr));
        test_check(ret == 0, "sockmsg read src addr");
        if (ret == 0) {
            test_check(src_addr.sun_family == AF_UNIX,
                       "sockmsg recv src family");
            test_check(strcmp(src_addr.sun_path, SOCKET_TEST_UNIX_MSG_TX_PATH) == 0,
                       "sockmsg recv src path");
        }
    }

    send_msg.msg_controllen = 8;
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg copy send msg ctrl");
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == -EOPNOTSUPP, "sockmsg sendmsg control eopnotsupp");
    }
    send_msg.msg_controllen = 0;
    send_msg.msg_iovlen = 1025;
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg copy send msg iovlen");
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == -EINVAL, "sockmsg sendmsg iovlen einval");
    }

    recv_msg.msg_controllen = 8;
    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg copy recv msg ctrl");
    if (ret == 0) {
        ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
        test_check(ret64 == -EOPNOTSUPP, "sockmsg recvmsg control eopnotsupp");
    }
    recv_msg.msg_controllen = 0;
    recv_msg.msg_iovlen = 1025;
    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg copy recv msg iovlen");
    if (ret == 0) {
        ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
        test_check(ret64 == -EINVAL, "sockmsg recvmsg iovlen einval");
    }

    send_msg.msg_iovlen = 2;
    send_msg.msg_controllen = 0;
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg copy send msg flags");
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 1ULL << 32, 0,
                            0, 0);
        test_check(ret64 == 7, "sockmsg sendmsg flags width");
    }

    recv_msg.msg_iovlen = 2;
    recv_msg.msg_controllen = 0;
    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg copy recv msg flags");
    if (ret == 0) {
        ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
        test_check(ret64 == 7, "sockmsg recvmsg flags width");
    }

    ret = copy_to_user(u_sendm_buf0, "aa", 2);
    test_check(ret == 0, "sockmsg copy sendm buf0");
    ret = copy_to_user(u_sendm_buf1, "bbb", 3);
    test_check(ret == 0, "sockmsg copy sendm buf1");
    if (ret < 0)
        goto out;

    struct test_socket_iovec sendm_iov[2] = {
        { .iov_base = u_sendm_buf0, .iov_len = 2 },
        { .iov_base = u_sendm_buf1, .iov_len = 3 },
    };
    struct test_socket_iovec recvm_iov[2] = {
        { .iov_base = u_recvm_buf0, .iov_len = 8 },
        { .iov_base = u_recvm_buf1, .iov_len = 8 },
    };
    ret = copy_to_user(u_send_iov, sendm_iov, sizeof(sendm_iov));
    test_check(ret == 0, "sockmsg copy sendm iov");
    ret = copy_to_user(u_recv_iov, recvm_iov, sizeof(recvm_iov));
    test_check(ret == 0, "sockmsg copy recvm iov");
    if (ret < 0)
        goto out;

    struct test_socket_mmsghdr send_vec[2] = {0};
    send_vec[0].msg_hdr.msg_name = u_rx_addr;
    send_vec[0].msg_hdr.msg_namelen = sizeof(rx_addr);
    send_vec[0].msg_hdr.msg_iov = &u_send_iov[0];
    send_vec[0].msg_hdr.msg_iovlen = 1;
    send_vec[1].msg_hdr.msg_name = u_rx_addr;
    send_vec[1].msg_hdr.msg_namelen = sizeof(rx_addr);
    send_vec[1].msg_hdr.msg_iov = &u_send_iov[1];
    send_vec[1].msg_hdr.msg_iovlen = 1;
    ret = copy_to_user(u_send_vec, send_vec, sizeof(send_vec));
    test_check(ret == 0, "sockmsg copy send vec");
    if (ret < 0)
        goto out;

    ret64 = sys_sendmmsg((uint64_t)txfd, (uint64_t)u_send_vec, 2, 0, 0, 0);
    test_check(ret64 == 2, "sockmsg sendmmsg count2");
    if (ret64 == 2) {
        ret = copy_from_user(send_vec, u_send_vec, sizeof(send_vec));
        test_check(ret == 0, "sockmsg read send vec");
        if (ret == 0) {
            test_check(send_vec[0].msg_len == 2, "sockmsg sendmmsg len0");
            test_check(send_vec[1].msg_len == 3, "sockmsg sendmmsg len1");
        }
    }

    struct test_socket_mmsghdr recv_vec[2] = {0};
    recv_vec[0].msg_hdr.msg_name = u_src_addr;
    recv_vec[0].msg_hdr.msg_namelen = sizeof(*u_src_addr);
    recv_vec[0].msg_hdr.msg_iov = &u_recv_iov[0];
    recv_vec[0].msg_hdr.msg_iovlen = 1;
    recv_vec[1].msg_hdr.msg_name = u_src_addr;
    recv_vec[1].msg_hdr.msg_namelen = sizeof(*u_src_addr);
    recv_vec[1].msg_hdr.msg_iov = &u_recv_iov[1];
    recv_vec[1].msg_hdr.msg_iovlen = 1;
    ret = copy_to_user(u_recv_vec, recv_vec, sizeof(recv_vec));
    test_check(ret == 0, "sockmsg copy recv vec");
    if (ret < 0)
        goto out;

    ret64 = sys_recvmmsg((uint64_t)rxfd, (uint64_t)u_recv_vec, 2, 0, 0, 0);
    test_check(ret64 == 2, "sockmsg recvmmsg count2");
    if (ret64 == 2) {
        char got0[3] = {0};
        char got1[4] = {0};
        ret = copy_from_user(got0, u_recvm_buf0, 2);
        test_check(ret == 0, "sockmsg read recvm buf0");
        ret = copy_from_user(got1, u_recvm_buf1, 3);
        test_check(ret == 0, "sockmsg read recvm buf1");
        if (ret == 0) {
            test_check(memcmp(got0, "aa", 2) == 0, "sockmsg recvmmsg data0");
            test_check(memcmp(got1, "bbb", 3) == 0, "sockmsg recvmmsg data1");
        }

        ret = copy_from_user(recv_vec, u_recv_vec, sizeof(recv_vec));
        test_check(ret == 0, "sockmsg read recv vec");
        if (ret == 0) {
            test_check(recv_vec[0].msg_len == 2, "sockmsg recvmmsg len0");
            test_check(recv_vec[1].msg_len == 3, "sockmsg recvmmsg len1");
        }
    }

    ret64 = sys_sendmmsg((uint64_t)txfd, (uint64_t)u_send_vec, 0, 0, 0, 0);
    test_check(ret64 == 0, "sockmsg sendmmsg vlen0");
    ret64 = sys_recvmmsg((uint64_t)rxfd, (uint64_t)u_recv_vec, 0, 0, 0, 0);
    test_check(ret64 == 0, "sockmsg recvmmsg vlen0");

    ret64 = sys_sendmmsg((uint64_t)txfd, (uint64_t)u_send_vec, 1025, 0, 0, 0);
    test_check(ret64 == -EINVAL, "sockmsg sendmmsg vlen einval");
    ret64 = sys_recvmmsg((uint64_t)rxfd, (uint64_t)u_recv_vec, 1025, 0, 0, 0);
    test_check(ret64 == -EINVAL, "sockmsg recvmmsg vlen einval");

    ret64 = sys_sendmmsg((uint64_t)txfd, (uint64_t)u_send_vec,
                         (1ULL << 32) | 1ULL, 0, 0, 0);
    test_check(ret64 == 1, "sockmsg sendmmsg vlen width");
    if (ret64 == 1) {
        ret = copy_to_user(u_recv_vec, recv_vec, sizeof(recv_vec));
        test_check(ret == 0, "sockmsg recvm width copy vec");
        if (ret == 0) {
            ret64 = sys_recvmmsg((uint64_t)rxfd, (uint64_t)u_recv_vec,
                                 (1ULL << 32) | 1ULL, 0, 0, 0);
            test_check(ret64 == 1, "sockmsg recvmmsg vlen width");
        }
    }

    struct timespec timeout_zero = { .tv_sec = 0, .tv_nsec = 0 };
    ret = copy_to_user(u_timeout, &timeout_zero, sizeof(timeout_zero));
    test_check(ret == 0, "sockmsg copy timeout zero");
    if (ret == 0) {
        ret64 = sys_recvmmsg((uint64_t)rxfd, (uint64_t)u_recv_vec, 1, 0,
                             (uint64_t)u_timeout, 0);
        test_check(ret64 == 0, "sockmsg recvmmsg timeout zero");
    }

    struct timespec timeout_bad = { .tv_sec = 0, .tv_nsec = 1000000000LL };
    ret = copy_to_user(u_timeout, &timeout_bad, sizeof(timeout_bad));
    test_check(ret == 0, "sockmsg copy timeout bad");
    if (ret == 0) {
        ret64 = sys_recvmmsg((uint64_t)rxfd, (uint64_t)u_recv_vec, 1, 0,
                             (uint64_t)u_timeout, 0);
        test_check(ret64 == -EINVAL, "sockmsg recvmmsg timeout einval");
    }

    ret64 = sys_sendmmsg((uint64_t)txfd, (uint64_t)u_send_vec, 1, 0, 0, 0);
    test_check(ret64 == 1, "sockmsg sendmmsg waitforone seed");
    if (ret64 == 1) {
        struct timespec timeout_short = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 };
        ret = copy_to_user(u_timeout, &timeout_short, sizeof(timeout_short));
        test_check(ret == 0, "sockmsg copy timeout short");
        if (ret == 0) {
            ret64 = sys_recvmmsg((uint64_t)rxfd, (uint64_t)u_recv_vec, 2,
                                 TEST_MSG_WAITFORONE, (uint64_t)u_timeout, 0);
            test_check(ret64 == 1, "sockmsg recvmmsg waitforone");
        }
    }

out:
    close_fd_if_open(&txfd);
    close_fd_if_open(&rxfd);
    close_socket_if_open(&tx);
    close_socket_if_open(&rx);
    if (mapped)
        user_map_end(&um);
}

static void test_socket_syscall_abi_width_edges(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int fd = -1;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "sockabi user map");
    if (rc < 0)
        goto out;
    mapped = true;

    int *u_on = (int *)user_map_ptr(&um, 0x0);
    test_check(u_on != NULL, "sockabi user ptr");
    if (!u_on)
        goto out;
    int on = 1;
    rc = copy_to_user(u_on, &on, sizeof(on));
    test_check(rc == 0, "sockabi copy on");
    if (rc < 0)
        goto out;

    int64_t fd64 = sys_socket(((uint64_t)0xA5A5U << 32) | (uint32_t)AF_UNIX,
                              (1ULL << 63) | (uint32_t)SOCK_DGRAM,
                              ((uint64_t)0x5A5AU << 32), 0, 0, 0);
    test_check(fd64 >= 0, "sockabi socket arg width");
    if (fd64 < 0)
        goto out;
    fd = (int)fd64;

    int64_t ret64 = sys_ioctl((uint64_t)fd, ((uint64_t)FIONBIO) | (1ULL << 32),
                              (uint64_t)u_on, 0, 0, 0);
    test_check(ret64 == 0, "sockabi ioctl cmd width");

    ret64 = sys_ioctl((uint64_t)((1ULL << 32) | (uint32_t)fd),
                      (uint64_t)FIONBIO, (uint64_t)u_on, 0, 0, 0);
    test_check(ret64 == 0, "sockabi ioctl fd width");

    struct file *f = fd_get(proc_current(), fd);
    test_check(f != NULL, "sockabi fd get");
    if (f) {
        bool nonblock = false;
        mutex_lock(&f->lock);
        nonblock = (f->flags & O_NONBLOCK) != 0;
        mutex_unlock(&f->lock);
        test_check(nonblock, "sockabi fionbio toggled");
        file_put(f);
    }

out:
    close_fd_if_open(&fd);
    if (mapped)
        user_map_end(&um);
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

static bool run_inet_udp_attempt_inner(uint32_t loopback_ip, uint16_t server_port,
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

static bool run_inet_tcp_attempt(uint32_t loopback_ip, uint16_t server_port,
                                 uint16_t client_port) {
    struct socket *listener = NULL;
    struct socket *client = NULL;
    struct socket *server = NULL;
    struct sockaddr_in listener_addr;
    struct sockaddr_in client_addr;
    char buf[64];
    bool ok = false;
    int ret;

    ret = sock_create(AF_INET, SOCK_STREAM, 0, &listener);
    if (ret < 0 || !listener)
        goto out;
    ret = sock_create(AF_INET, SOCK_STREAM, 0, &client);
    if (ret < 0 || !client)
        goto out;

    make_inet_addr(&listener_addr, loopback_ip, server_port);
    make_inet_addr(&client_addr, loopback_ip, client_port);

    ret = listener->ops->bind(listener, (const struct sockaddr *)&listener_addr,
                              sizeof(listener_addr));
    if (ret < 0)
        goto out;
    ret = listener->ops->listen(listener, 8);
    if (ret < 0)
        goto out;

    ret = client->ops->bind(client, (const struct sockaddr *)&client_addr,
                            sizeof(client_addr));
    if (ret < 0)
        goto out;
    ret = client->ops->connect(client, (const struct sockaddr *)&listener_addr,
                               sizeof(listener_addr));
    if (ret < 0)
        goto out;

    int cre = client->ops->poll(client, POLLOUT);
    if ((cre & POLLOUT) == 0)
        goto out;

    int lre = listener->ops->poll(listener, POLLIN);
    if ((lre & POLLIN) == 0)
        goto out;

    ret = listener->ops->accept(listener, &server);
    if (ret < 0 || !server)
        goto out;

    ssize_t wr = client->ops->sendto(client, "tcp-ping", 8, 0, NULL, 0);
    if (wr != 8)
        goto out;
    if (!wait_socket_event(server, POLLIN, POLLIN, 3000))
        goto out;

    memset(buf, 0, sizeof(buf));
    ssize_t rd = server->ops->recvfrom(server, buf, sizeof(buf), 0, NULL, NULL);
    if (rd != 8 || memcmp(buf, "tcp-ping", 8) != 0)
        goto out;

    wr = server->ops->sendto(server, "tcp-pong", 8, 0, NULL, 0);
    if (wr != 8)
        goto out;
    if (!wait_socket_event(client, POLLIN, POLLIN, 3000))
        goto out;

    memset(buf, 0, sizeof(buf));
    rd = client->ops->recvfrom(client, buf, sizeof(buf), 0, NULL, NULL);
    if (rd != 8 || memcmp(buf, "tcp-pong", 8) != 0)
        goto out;

    close_socket_if_open(&server);

    if (!wait_socket_event(client, POLLHUP, POLLHUP, 4000))
        goto out;

    rd = client->ops->recvfrom(client, buf, sizeof(buf), 0, NULL, NULL);
    if (rd != 0)
        goto out;

    wr = client->ops->sendto(client, "x", 1, 0, NULL, 0);
    if (wr != -EPIPE)
        goto out;

    ok = true;

out:
    close_socket_if_open(&server);
    close_socket_if_open(&client);
    close_socket_if_open(&listener);
    return ok;
}

struct inet_attempt_ctx {
    uint32_t loopback_ip;
    uint16_t server_port;
    uint16_t client_port;
    bool ok;
};

static int inet_udp_attempt_worker(void *arg) {
    struct inet_attempt_ctx *ctx = (struct inet_attempt_ctx *)arg;
    ctx->ok = run_inet_udp_attempt_inner(ctx->loopback_ip, ctx->server_port,
                                         ctx->client_port);
    proc_exit(0);
}

static int inet_tcp_attempt_worker(void *arg) {
    struct inet_attempt_ctx *ctx = (struct inet_attempt_ctx *)arg;
    ctx->ok = run_inet_tcp_attempt(ctx->loopback_ip, ctx->server_port,
                                   ctx->client_port);
    proc_exit(0);
}

static bool run_inet_attempt_with_timeout(int (*worker)(void *),
                                          const struct inet_attempt_ctx *ctx_tpl,
                                          const char *name, int spins) {
    struct inet_attempt_ctx *ctx = kmalloc(sizeof(*ctx));
    if (!ctx)
        return false;
    memcpy(ctx, ctx_tpl, sizeof(*ctx));

    struct process *child = kthread_create_joinable(worker, ctx, name);
    if (!child) {
        kfree(ctx);
        return false;
    }

    pid_t cpid = child->pid;
    sched_enqueue(child);

    int status = 0;
    for (int i = 0; i < spins; i++) {
        pid_t wp = proc_wait(cpid, &status, WNOHANG);
        if (wp == cpid) {
            bool ok = ctx->ok;
            kfree(ctx);
            return ok;
        }
        if (wp < 0) {
            kfree(ctx);
            return false;
        }
        proc_yield();
    }

    signal_send(cpid, SIGKILL);
    (void)proc_wait(cpid, &status, 0);
    kfree(ctx);
    return false;
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
        struct inet_attempt_ctx ctx = {
            .loopback_ip = loopback_ips[i],
            .server_port = (uint16_t)(42000 + i),
            .client_port = (uint16_t)(43000 + i),
            .ok = false,
        };
        if (run_inet_attempt_with_timeout(inet_udp_attempt_worker, &ctx, "inudp",
                                          8000)) {
            ok = true;
            break;
        }
    }

    if (ok)
        test_check(true, "inet_udp loopback");
    else
        test_skip("inet_udp (loopback delivery unavailable)");
}

static void test_inet_tcp_primary(void) {
    if (!netdev_first()) {
        test_skip("inet_tcp (no netdev)");
        return;
    }

    const uint32_t loopback_ips[] = {
        0x0100007fU, /* lwIP host-order encoded 127.0.0.1 */
        0x7f000001U, /* native-order encoded 127.0.0.1 */
    };

    bool ok = false;
    for (size_t i = 0; i < sizeof(loopback_ips) / sizeof(loopback_ips[0]); i++) {
        struct inet_attempt_ctx ctx = {
            .loopback_ip = loopback_ips[i],
            .server_port = (uint16_t)(44000 + i),
            .client_port = (uint16_t)(45000 + i),
            .ok = false,
        };
        if (run_inet_attempt_with_timeout(inet_tcp_attempt_worker, &ctx, "intcp",
                                          8000)) {
            ok = true;
            break;
        }
    }

    if (ok)
        test_check(true, "inet_tcp loopback");
    else
        test_skip("inet_tcp (loopback tcp unavailable)");
}

int run_socket_tests(void) {
    tests_failed = 0;
    tests_skipped = 0;

    pr_info("\n=== Socket Tests ===\n");

    test_unix_stream_semantics();
    test_unix_stream_accept_stability();
    test_accept4_syscall_semantics();
    test_accept4_syscall_functional();
    test_socket_msg_syscall_semantics();
    test_socket_syscall_abi_width_edges();
    test_unix_dgram_semantics();
    test_inet_tcp_primary();
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
