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
#define SOCKET_TEST_UNIX_NB_SRV_PATH "/tmp/.kairos_sock_nb_srv"
#define SOCKET_TEST_UNIX_NB_DGRAM_PATH "/tmp/.kairos_sock_nb_dgram"
#define SOCKET_TEST_UNIX_SOCKOPT_PATH "/tmp/.kairos_sock_sockopt_srv"
#define TEST_MSG_WAITFORONE 0x10000U
#define TEST_MSG_CMSG_CLOEXEC 0x40000000U
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

struct test_socket_cmsghdr {
    size_t cmsg_len;
    int32_t cmsg_level;
    int32_t cmsg_type;
};

#define TEST_SCM_RIGHTS 1
#define TEST_SCM_CREDENTIALS 2

struct test_socket_ucred {
    int32_t pid;
    uint32_t uid;
    uint32_t gid;
};

static size_t test_socket_cmsg_align(size_t len) {
    const size_t align = sizeof(size_t) - 1;
    return (len + align) & ~align;
}

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

static bool wait_inet_connect_so_error(struct socket *sock, int *so_error,
                                       int spins) {
    if (!sock || !sock->ops || !sock->ops->getsockopt || !so_error)
        return false;
    bool ready = false;
    for (int i = 0; i < spins; i++) {
        int revents = sock->ops->poll(sock, POLLOUT | POLLERR | POLLHUP);
        if (revents & (POLLOUT | POLLERR | POLLHUP)) {
            ready = true;
            break;
        }
        proc_yield();
    }
    if (!ready) {
        int revents = sock->ops->poll(sock, POLLOUT | POLLERR | POLLHUP);
        ready = (revents & (POLLOUT | POLLERR | POLLHUP)) != 0;
    }
    if (!ready)
        return false;
    int len = sizeof(*so_error);
    int rc = sock->ops->getsockopt(sock, SOL_SOCKET, SO_ERROR, so_error, &len);
    return rc == 0 && len == (int)sizeof(*so_error);
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
                                   sizeof(ctx->srv_addr), 0);
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
                               sizeof(ctx->srv_addr), 0);
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
                                  sizeof(missing_addr), 0);
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
            ret = listener->ops->accept(listener, &accepted, 0);
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
    struct test_socket_cmsghdr *u_ctrl =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x7C0);
    int32_t *u_rights = (int32_t *)user_map_ptr(&um, 0x7D0);
    struct test_socket_ucred *u_cred =
        (struct test_socket_ucred *)user_map_ptr(&um, 0x7D0);
    test_check(u_rx_addr && u_src_addr && u_send_iov && u_recv_iov && u_send_msg &&
                   u_recv_msg && u_send_vec && u_recv_vec && u_timeout &&
                   u_send_buf0 && u_send_buf1 && u_recv_buf0 && u_recv_buf1 &&
                   u_sendm_buf0 && u_sendm_buf1 && u_recvm_buf0 && u_recvm_buf1 &&
                   u_ctrl && u_rights && u_cred,
               "sockmsg user pointers");
    if (!u_rx_addr || !u_src_addr || !u_send_iov || !u_recv_iov || !u_send_msg ||
        !u_recv_msg || !u_send_vec || !u_recv_vec || !u_timeout || !u_send_buf0 ||
        !u_send_buf1 || !u_recv_buf0 || !u_recv_buf1 || !u_sendm_buf0 ||
        !u_sendm_buf1 || !u_recvm_buf0 || !u_recvm_buf1 || !u_ctrl || !u_rights ||
        !u_cred) {
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

    send_msg.msg_control = NULL;
    send_msg.msg_controllen = 8;
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg copy send msg ctrl");
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == -EFAULT, "sockmsg sendmsg control null efault");
    }

    struct test_socket_cmsghdr ctrl = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr) + sizeof(int32_t),
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = TEST_SCM_RIGHTS,
    };
    ret = copy_to_user(u_ctrl, &ctrl, sizeof(ctrl));
    test_check(ret == 0, "sockmsg copy control hdr");
    if (ret == 0) {
        int32_t rights_fd = txfd;
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl), &rights_fd,
                           sizeof(rights_fd));
        test_check(ret == 0, "sockmsg copy control rights");
    }
    if (ret == 0) {
        send_msg.msg_control = u_ctrl;
        send_msg.msg_controllen = test_socket_cmsg_align(ctrl.cmsg_len);
        ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
        test_check(ret == 0, "sockmsg copy send msg ctrl rights");
    }
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == 7, "sockmsg sendmsg control rights");
    }
    if (ret64 == 7) {
        recv_msg.msg_iovlen = 2;
        recv_msg.msg_control = NULL;
        recv_msg.msg_controllen = 0;
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg copy recv msg ctrl drain");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
            test_check(ret64 == 7, "sockmsg recvmsg control drain");
        }
    }
    send_msg.msg_control = NULL;
    send_msg.msg_controllen = 0;
    send_msg.msg_iovlen = 1025;
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg copy send msg iovlen");
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == -EINVAL, "sockmsg sendmsg iovlen einval");
    }

    recv_msg.msg_control = NULL;
    recv_msg.msg_controllen = 8;
    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg copy recv msg ctrl");
    if (ret == 0) {
        ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
        test_check(ret64 == -EFAULT, "sockmsg recvmsg control null efault");
    }

    send_msg.msg_iovlen = 2;
    send_msg.msg_control = u_ctrl;
    send_msg.msg_controllen = test_socket_cmsg_align(ctrl.cmsg_len);
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg copy send msg ctrl prep");
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == 7, "sockmsg sendmsg ctrl prep");
    }
    recv_msg.msg_control = u_ctrl;
    recv_msg.msg_controllen = sizeof(struct test_socket_cmsghdr);
    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg copy recv msg ctrl buf");
    ret64 = -1;
    if (ret == 0) {
        ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
        test_check(ret64 == 7, "sockmsg recvmsg control trunc");
    }
    if (ret64 == 7) {
        ret = copy_from_user(&recv_msg, u_recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg read recv msg ctrl");
        if (ret == 0) {
            test_check(recv_msg.msg_controllen == 0,
                       "sockmsg recvmsg control cleared");
            test_check((recv_msg.msg_flags & MSG_CTRUNC) != 0,
                       "sockmsg recvmsg control ctrunc");
        }
    }

    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg copy send msg ctrl full");
    ret64 = -1;
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == 7, "sockmsg sendmsg ctrl full");
    }
    if (ret64 == 7) {
        recv_msg.msg_control = u_ctrl;
        recv_msg.msg_controllen = test_socket_cmsg_align(ctrl.cmsg_len);
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg copy recv msg ctrl full");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
            test_check(ret64 == 7, "sockmsg recvmsg control rights");
        }
        if (ret64 == 7) {
            struct test_socket_cmsghdr got_ctrl;
            int32_t got_fd = -1;
            ret = copy_from_user(&recv_msg, u_recv_msg, sizeof(recv_msg));
            test_check(ret == 0, "sockmsg read recv msg ctrl full");
            ret = copy_from_user(&got_ctrl, u_ctrl, sizeof(got_ctrl));
            test_check(ret == 0, "sockmsg read recv ctrl hdr");
            ret = copy_from_user(&got_fd, u_rights, sizeof(got_fd));
            test_check(ret == 0, "sockmsg read recv ctrl fd");
            if (ret == 0) {
                test_check(got_ctrl.cmsg_level == SOL_SOCKET,
                           "sockmsg recv ctrl level");
                test_check(got_ctrl.cmsg_type == TEST_SCM_RIGHTS,
                           "sockmsg recv ctrl type");
                test_check(got_fd >= 0, "sockmsg recv ctrl fd valid");
            }
            if (got_fd >= 0) {
                struct file *tf = fd_get(proc_current(), txfd);
                struct file *rf = fd_get(proc_current(), got_fd);
                test_check(tf != NULL, "sockmsg recv ctrl tx fd get");
                test_check(rf != NULL, "sockmsg recv ctrl fd get");
                if (tf && rf)
                    test_check(tf == rf, "sockmsg recv ctrl fd shared file");
                if (tf)
                    file_put(tf);
                if (rf)
                    file_put(rf);
                (void)fd_close(proc_current(), got_fd);
            }
        }
    }

    ret = copy_to_user(u_ctrl, &ctrl, sizeof(ctrl));
    test_check(ret == 0, "sockmsg copy control hdr cloexec");
    if (ret == 0) {
        int32_t rights_fd = txfd;
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl), &rights_fd,
                           sizeof(rights_fd));
        test_check(ret == 0, "sockmsg copy control rights cloexec");
    }
    ret64 = -1;
    if (ret == 0) {
        ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
        test_check(ret == 0, "sockmsg copy send msg ctrl cloexec");
    }
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == 7, "sockmsg sendmsg ctrl cloexec");
    }
    if (ret64 == 7) {
        recv_msg.msg_control = u_ctrl;
        recv_msg.msg_controllen = test_socket_cmsg_align(ctrl.cmsg_len);
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg copy recv msg ctrl cloexec");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg,
                                TEST_MSG_CMSG_CLOEXEC, 0, 0, 0);
            test_check(ret64 == 7, "sockmsg recvmsg control cloexec");
        }
        if (ret64 == 7) {
            int32_t got_fd = -1;
            ret = copy_from_user(&got_fd, u_rights, sizeof(got_fd));
            test_check(ret == 0, "sockmsg read recv ctrl fd cloexec");
            if (ret == 0)
                test_check(got_fd >= 0, "sockmsg recv ctrl cloexec fd valid");
            if (got_fd >= 0) {
                struct process *p = proc_current();
                bool cloexec_ok = false;
                if (p && p->fdtable && got_fd < CONFIG_MAX_FILES_PER_PROC) {
                    mutex_lock(&p->fdtable->lock);
                    cloexec_ok = (p->fdtable->fd_flags[got_fd] & FD_CLOEXEC) != 0;
                    mutex_unlock(&p->fdtable->lock);
                }
                test_check(cloexec_ok, "sockmsg recv ctrl fd cloexec");
                (void)fd_close(proc_current(), got_fd);
            }
        }
    }

    struct test_socket_cmsghdr ctrl_cred = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr) +
                    sizeof(struct test_socket_ucred),
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = TEST_SCM_CREDENTIALS,
    };
    struct test_socket_ucred cred = {0};
    ret = copy_to_user(u_ctrl, &ctrl_cred, sizeof(ctrl_cred));
    test_check(ret == 0, "sockmsg copy control cred hdr");
    if (ret == 0) {
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_cred), &cred,
                           sizeof(cred));
        test_check(ret == 0, "sockmsg copy control cred payload");
    }
    if (ret == 0) {
        send_msg.msg_control = u_ctrl;
        send_msg.msg_controllen = test_socket_cmsg_align(ctrl_cred.cmsg_len);
        ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
        test_check(ret == 0, "sockmsg copy send msg cred");
    }
    ret64 = -1;
    if (ret == 0) {
        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == 7, "sockmsg sendmsg control creds");
    }
    if (ret64 == 7) {
        recv_msg.msg_control = u_ctrl;
        recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_cred.cmsg_len);
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg copy recv msg cred");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
            test_check(ret64 == 7, "sockmsg recvmsg control creds");
        }
        if (ret64 == 7) {
            struct test_socket_cmsghdr got_ctrl;
            struct test_socket_ucred got_cred = {0};
            ret = copy_from_user(&got_ctrl, u_ctrl, sizeof(got_ctrl));
            test_check(ret == 0, "sockmsg read recv cred hdr");
            ret = copy_from_user(&got_cred, u_cred, sizeof(got_cred));
            test_check(ret == 0, "sockmsg read recv cred payload");
            if (ret == 0) {
                test_check(got_ctrl.cmsg_level == SOL_SOCKET,
                           "sockmsg recv cred level");
                test_check(got_ctrl.cmsg_type == TEST_SCM_CREDENTIALS,
                           "sockmsg recv cred type");
                test_check(got_cred.pid == proc_current()->pid,
                           "sockmsg recv cred pid");
                test_check(got_cred.uid == proc_current()->uid,
                           "sockmsg recv cred uid");
                test_check(got_cred.gid == proc_current()->gid,
                           "sockmsg recv cred gid");
            }
        }
    }

    recv_msg.msg_controllen = 0;
    recv_msg.msg_control = NULL;
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

enum sockmsg_stream_phase {
    SOCKMSG_STREAM_PHASE_BASIC = 1u << 0,
    SOCKMSG_STREAM_PHASE_PEEK_MERGE = 1u << 1,
    SOCKMSG_STREAM_PHASE_BOUNDARY_DROP = 1u << 2,
};

static void test_unix_stream_msg_control_semantics_phase(uint32_t phases) {
    struct socket *tx = NULL;
    struct socket *rx = NULL;
    int txfd = -1;
    int rxfd = -1;
    int rights_src_fd = -1;
    int rights_nodup_fd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;

    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &tx);
    test_check(ret == 0, "sockmsg_stream create tx");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &rx);
    test_check(ret == 0, "sockmsg_stream create rx");
    if (!tx || !rx)
        goto out;

    ret = unix_socketpair_connect(tx, rx);
    test_check(ret == 0, "sockmsg_stream socketpair connect");
    if (ret < 0)
        goto out;

    txfd = socket_install_fd(&tx);
    rxfd = socket_install_fd(&rx);
    test_check(txfd >= 0, "sockmsg_stream install tx fd");
    test_check(rxfd >= 0, "sockmsg_stream install rx fd");
    if (txfd < 0 || rxfd < 0)
        goto out;

    ret = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "sockmsg_stream user map");
    if (ret < 0)
        goto out;
    mapped = true;

    struct test_socket_iovec *u_send_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x000);
    struct test_socket_iovec *u_recv_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x020);
    struct test_socket_msghdr *u_send_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x040);
    struct test_socket_msghdr *u_recv_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x080);
    char *u_send_buf = (char *)user_map_ptr(&um, 0x0C0);
    char *u_recv_buf = (char *)user_map_ptr(&um, 0x100);
    struct test_socket_cmsghdr *u_ctrl =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x140);
    int32_t *u_rights = (int32_t *)user_map_ptr(&um, 0x150);
    struct test_socket_ucred *u_cred =
        (struct test_socket_ucred *)user_map_ptr(&um, 0x150);
    test_check(u_send_iov && u_recv_iov && u_send_msg && u_recv_msg &&
                   u_send_buf && u_recv_buf && u_ctrl && u_rights && u_cred,
               "sockmsg_stream user pointers");
    if (!u_send_iov || !u_recv_iov || !u_send_msg || !u_recv_msg ||
        !u_send_buf || !u_recv_buf || !u_ctrl || !u_rights || !u_cred) {
        goto out;
    }

    struct test_socket_iovec send_iov = {
        .iov_base = u_send_buf,
        .iov_len = 4,
    };
    struct test_socket_iovec recv_iov = {
        .iov_base = u_recv_buf,
        .iov_len = 8,
    };
    ret = copy_to_user(u_send_iov, &send_iov, sizeof(send_iov));
    test_check(ret == 0, "sockmsg_stream copy send iov");
    ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
    test_check(ret == 0, "sockmsg_stream copy recv iov");
    if (ret < 0)
        goto out;

    struct test_socket_msghdr send_msg = {
        .msg_iov = u_send_iov,
        .msg_iovlen = 1,
    };
    struct test_socket_msghdr recv_msg = {
        .msg_iov = u_recv_iov,
        .msg_iovlen = 1,
    };

    uint32_t rights_mask = FD_RIGHT_READ | FD_RIGHT_DUP;
    rights_src_fd = fd_dup(proc_current(), txfd);
    test_check(rights_src_fd >= 0, "sockmsg_stream dup rights source");
    if (rights_src_fd < 0)
        goto out;
    ret = fd_limit_rights(proc_current(), rights_src_fd, rights_mask, NULL);
    test_check(ret == 0, "sockmsg_stream limit rights source");
    if (ret < 0)
        goto out;

    struct test_socket_cmsghdr ctrl_rights = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr) + sizeof(int32_t),
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = TEST_SCM_RIGHTS,
    };
    int32_t rights_fd = rights_src_fd;
    struct test_socket_cmsghdr ctrl_cred = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr) +
                    sizeof(struct test_socket_ucred),
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = TEST_SCM_CREDENTIALS,
    };
    struct test_socket_ucred cred = {0};
    if (phases & SOCKMSG_STREAM_PHASE_BASIC) {
        rights_nodup_fd = fd_dup(proc_current(), txfd);
        test_check(rights_nodup_fd >= 0, "sockmsg_stream dup no-dup source");
        if (rights_nodup_fd >= 0) {
            ret = fd_limit_rights(proc_current(), rights_nodup_fd, FD_RIGHT_READ, NULL);
            test_check(ret == 0, "sockmsg_stream limit no-dup source");
            if (ret == 0) {
                int32_t denied_fd = rights_nodup_fd;
                ret = copy_to_user(u_ctrl, &ctrl_rights, sizeof(ctrl_rights));
                test_check(ret == 0, "sockmsg_stream copy denied rights hdr");
                if (ret == 0)
                    ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_rights),
                                       &denied_fd, sizeof(denied_fd));
                test_check(ret == 0, "sockmsg_stream copy denied rights payload");
                if (ret == 0) {
                    ret = copy_to_user(u_send_buf, "SDNY", 4);
                    test_check(ret == 0, "sockmsg_stream copy denied send buf");
                }
                if (ret == 0) {
                    send_msg.msg_control = u_ctrl;
                    send_msg.msg_controllen =
                        test_socket_cmsg_align(ctrl_rights.cmsg_len);
                    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
                    test_check(ret == 0, "sockmsg_stream copy denied send msg");
                }
                if (ret == 0) {
                    int64_t denied_ret =
                        sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
                    test_check(denied_ret == -EBADF,
                               "sockmsg_stream sendmsg rights requires dup");
                }
            }
        }

        ret = copy_to_user(u_ctrl, &ctrl_rights, sizeof(ctrl_rights));
        test_check(ret == 0, "sockmsg_stream copy rights hdr");
        if (ret == 0) {
            ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_rights), &rights_fd,
                               sizeof(rights_fd));
            test_check(ret == 0, "sockmsg_stream copy rights payload");
        }
        if (ret < 0)
            goto out;

        ret = copy_to_user(u_send_buf, "SFD0", 4);
        test_check(ret == 0, "sockmsg_stream copy rights send buf");
        if (ret < 0)
            goto out;

        send_msg.msg_control = u_ctrl;
        send_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
        ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
        test_check(ret == 0, "sockmsg_stream copy rights send msg");
        if (ret < 0)
            goto out;

        int64_t ret64 =
            sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == 4, "sockmsg_stream sendmsg rights");

        if (ret64 == 4) {
            recv_msg.msg_control = u_ctrl;
            recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
            ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
            test_check(ret == 0, "sockmsg_stream copy rights recv msg");
            if (ret == 0) {
                ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0,
                                    0);
                test_check(ret64 == 4, "sockmsg_stream recvmsg rights");
            }
        }
        if (ret64 == 4) {
            char got[4] = {0};
            struct test_socket_cmsghdr got_ctrl = {0};
            int32_t got_fd = -1;
            ret = copy_from_user(got, u_recv_buf, sizeof(got));
            test_check(ret == 0, "sockmsg_stream read rights recv buf");
            ret = copy_from_user(&got_ctrl, u_ctrl, sizeof(got_ctrl));
            test_check(ret == 0, "sockmsg_stream read rights recv hdr");
            ret = copy_from_user(&got_fd, u_rights, sizeof(got_fd));
            test_check(ret == 0, "sockmsg_stream read rights recv fd");
            if (ret == 0) {
                test_check(memcmp(got, "SFD0", 4) == 0,
                           "sockmsg_stream rights data");
                test_check(got_ctrl.cmsg_type == TEST_SCM_RIGHTS,
                           "sockmsg_stream rights type");
                test_check(got_fd >= 0, "sockmsg_stream rights fd valid");
            }
            if (got_fd >= 0) {
                struct file *srcf = fd_get(proc_current(), txfd);
                struct file *gotf = fd_get(proc_current(), got_fd);
                test_check(srcf != NULL, "sockmsg_stream rights src fd get");
                test_check(gotf != NULL, "sockmsg_stream rights got fd get");
                if (srcf && gotf)
                    test_check(srcf == gotf, "sockmsg_stream rights same file");
                if (srcf)
                    file_put(srcf);
                if (gotf)
                    file_put(gotf);
                uint32_t src_rights = 0;
                uint32_t got_rights = 0;
                int rc0 = fd_get_rights(proc_current(), rights_src_fd, &src_rights);
                int rc1 = fd_get_rights(proc_current(), got_fd, &got_rights);
                test_check(rc0 == 0 && rc1 == 0,
                           "sockmsg_stream rights read rights mask");
                if (rc0 == 0 && rc1 == 0) {
                    test_check(src_rights == rights_mask,
                               "sockmsg_stream rights src mask limited");
                    test_check(got_rights == src_rights,
                               "sockmsg_stream rights mask preserved");
                }
                (void)fd_close(proc_current(), got_fd);
            }
        }

        ret = copy_to_user(u_ctrl, &ctrl_cred, sizeof(ctrl_cred));
        test_check(ret == 0, "sockmsg_stream copy cred hdr");
        if (ret == 0) {
            ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_cred), &cred,
                               sizeof(cred));
            test_check(ret == 0, "sockmsg_stream copy cred payload");
        }
        if (ret < 0)
            goto out;

        ret = copy_to_user(u_send_buf, "SCRD", 4);
        test_check(ret == 0, "sockmsg_stream copy cred send buf");
        if (ret < 0)
            goto out;

        send_msg.msg_control = u_ctrl;
        send_msg.msg_controllen = test_socket_cmsg_align(ctrl_cred.cmsg_len);
        ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
        test_check(ret == 0, "sockmsg_stream copy cred send msg");
        if (ret < 0)
            goto out;

        ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
        test_check(ret64 == 4, "sockmsg_stream sendmsg creds");

        if (ret64 == 4) {
            recv_msg.msg_control = u_ctrl;
            recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_cred.cmsg_len);
            ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
            test_check(ret == 0, "sockmsg_stream copy cred recv msg");
            if (ret == 0) {
                ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0,
                                    0);
                test_check(ret64 == 4, "sockmsg_stream recvmsg creds");
            }
        }
        if (ret64 == 4) {
            struct test_socket_cmsghdr got_ctrl = {0};
            struct test_socket_ucred got_cred = {0};
            ret = copy_from_user(&got_ctrl, u_ctrl, sizeof(got_ctrl));
            test_check(ret == 0, "sockmsg_stream read cred recv hdr");
            ret = copy_from_user(&got_cred, u_cred, sizeof(got_cred));
            test_check(ret == 0, "sockmsg_stream read cred recv payload");
            if (ret == 0) {
                test_check(got_ctrl.cmsg_type == TEST_SCM_CREDENTIALS,
                           "sockmsg_stream cred type");
                test_check(got_cred.pid == proc_current()->pid,
                           "sockmsg_stream cred pid");
                test_check(got_cred.uid == proc_current()->uid,
                           "sockmsg_stream cred uid");
                test_check(got_cred.gid == proc_current()->gid,
                           "sockmsg_stream cred gid");
            }
        }
    }

    if (phases & SOCKMSG_STREAM_PHASE_PEEK_MERGE) {
        int64_t ret64 = 0;

    ret = copy_to_user(u_send_buf, "PEEK", 4);
    test_check(ret == 0, "sockmsg_stream copy peek send buf");
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_ctrl, &ctrl_rights, sizeof(ctrl_rights));
    test_check(ret == 0, "sockmsg_stream copy peek rights hdr");
    if (ret == 0) {
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_rights), &rights_fd,
                           sizeof(rights_fd));
        test_check(ret == 0, "sockmsg_stream copy peek rights payload");
    }
    if (ret < 0)
        goto out;
    send_msg.msg_control = u_ctrl;
    send_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_stream copy peek send msg");
    if (ret < 0)
        goto out;
    ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream sendmsg peek rights");

    if (ret64 == 4) {
        recv_iov.iov_len = 4;
        ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
        test_check(ret == 0, "sockmsg_stream copy peek recv iov");
        recv_msg.msg_control = u_ctrl;
        recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg_stream copy peek recv msg");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, MSG_PEEK, 0,
                                0, 0);
            test_check(ret64 == 4, "sockmsg_stream recvmsg peek rights");
        }
        if (ret64 == 4) {
            char got_peek[4] = {0};
            struct test_socket_cmsghdr got_ctrl = {0};
            int32_t got_fd = -1;
            ret = copy_from_user(got_peek, u_recv_buf, sizeof(got_peek));
            test_check(ret == 0, "sockmsg_stream read peek data");
            ret = copy_from_user(&got_ctrl, u_ctrl, sizeof(got_ctrl));
            test_check(ret == 0, "sockmsg_stream read peek ctrl");
            ret = copy_from_user(&got_fd, u_rights, sizeof(got_fd));
            test_check(ret == 0, "sockmsg_stream read peek fd");
            if (ret == 0) {
                test_check(memcmp(got_peek, "PEEK", 4) == 0,
                           "sockmsg_stream peek data");
                test_check(got_ctrl.cmsg_type == TEST_SCM_RIGHTS,
                           "sockmsg_stream peek ctrl type");
                test_check(got_fd >= 0, "sockmsg_stream peek fd valid");
            }
            if (got_fd >= 0)
                (void)fd_close(proc_current(), got_fd);
        }
    }

    if (ret64 == 4) {
        recv_iov.iov_len = 4;
        ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
        test_check(ret == 0, "sockmsg_stream copy post-peek recv iov");
        recv_msg.msg_control = u_ctrl;
        recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg_stream copy post-peek recv msg");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
            test_check(ret64 == 4, "sockmsg_stream recvmsg post-peek rights");
        }
        if (ret64 == 4) {
            char got_peek2[4] = {0};
            struct test_socket_cmsghdr got_ctrl = {0};
            int32_t got_fd = -1;
            ret = copy_from_user(got_peek2, u_recv_buf, sizeof(got_peek2));
            test_check(ret == 0, "sockmsg_stream read post-peek data");
            ret = copy_from_user(&got_ctrl, u_ctrl, sizeof(got_ctrl));
            test_check(ret == 0, "sockmsg_stream read post-peek ctrl");
            ret = copy_from_user(&got_fd, u_rights, sizeof(got_fd));
            test_check(ret == 0, "sockmsg_stream read post-peek fd");
            if (ret == 0) {
                test_check(memcmp(got_peek2, "PEEK", 4) == 0,
                           "sockmsg_stream post-peek same data");
                test_check(got_ctrl.cmsg_type == TEST_SCM_RIGHTS,
                           "sockmsg_stream post-peek ctrl type");
                test_check(got_fd >= 0, "sockmsg_stream post-peek fd valid");
            }
            if (got_fd >= 0)
                (void)fd_close(proc_current(), got_fd);
        }
    }

    ret = copy_to_user(u_ctrl, &ctrl_rights, sizeof(ctrl_rights));
    test_check(ret == 0, "sockmsg_stream copy merge rights hdr a");
    rights_fd = txfd;
    if (ret == 0) {
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_rights), &rights_fd,
                           sizeof(rights_fd));
        test_check(ret == 0, "sockmsg_stream copy merge rights payload a");
    }
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_send_buf, "M1A1", 4);
    test_check(ret == 0, "sockmsg_stream copy merge send buf a");
    if (ret < 0)
        goto out;
    send_msg.msg_control = u_ctrl;
    send_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_stream copy merge send msg a");
    if (ret < 0)
        goto out;
    ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream sendmsg merge rights a");

    if (ret64 == 4) {
        ret = copy_to_user(u_ctrl, &ctrl_rights, sizeof(ctrl_rights));
        test_check(ret == 0, "sockmsg_stream copy merge rights hdr b");
        rights_fd = rxfd;
        if (ret == 0) {
            ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_rights), &rights_fd,
                               sizeof(rights_fd));
            test_check(ret == 0, "sockmsg_stream copy merge rights payload b");
        }
    }
    if (ret < 0)
        goto out;
    if (ret64 == 4) {
        ret = copy_to_user(u_send_buf, "M2B2", 4);
        test_check(ret == 0, "sockmsg_stream copy merge send buf b");
        if (ret == 0) {
            send_msg.msg_control = u_ctrl;
            send_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
            ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
            test_check(ret == 0, "sockmsg_stream copy merge send msg b");
        }
        if (ret == 0) {
            ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
            test_check(ret64 == 4, "sockmsg_stream sendmsg merge rights b");
        }
    }

    if (ret64 == 4) {
        struct test_socket_cmsghdr ctrl_rights2 = {
            .cmsg_len = sizeof(struct test_socket_cmsghdr) + sizeof(int32_t) * 2,
            .cmsg_level = SOL_SOCKET,
            .cmsg_type = TEST_SCM_RIGHTS,
        };
        recv_iov.iov_len = 8;
        ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
        test_check(ret == 0, "sockmsg_stream copy merge recv iov");
        recv_msg.msg_control = u_ctrl;
        recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights2.cmsg_len);
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg_stream copy merge recv msg");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
            test_check(ret64 == 8, "sockmsg_stream recvmsg merge rights");
        }
        if (ret64 == 8) {
            char got_merge[8] = {0};
            struct test_socket_cmsghdr got_ctrl = {0};
            int32_t got_fd0 = -1;
            int32_t got_fd1 = -1;
            struct file *src0 = NULL;
            struct file *src1 = NULL;
            struct file *got0 = NULL;
            struct file *got1 = NULL;
            ret = copy_from_user(got_merge, u_recv_buf, sizeof(got_merge));
            test_check(ret == 0, "sockmsg_stream read merge data");
            ret = copy_from_user(&got_ctrl, u_ctrl, sizeof(got_ctrl));
            test_check(ret == 0, "sockmsg_stream read merge ctrl");
            ret = copy_from_user(&got_fd0, u_rights, sizeof(got_fd0));
            test_check(ret == 0, "sockmsg_stream read merge fd0");
            ret = copy_from_user(&got_fd1, u_rights + 1, sizeof(got_fd1));
            test_check(ret == 0, "sockmsg_stream read merge fd1");
            if (ret == 0) {
                test_check(memcmp(got_merge, "M1A1M2B2", 8) == 0,
                           "sockmsg_stream merge data");
                test_check(got_ctrl.cmsg_type == TEST_SCM_RIGHTS,
                           "sockmsg_stream merge ctrl type");
                test_check(got_fd0 >= 0 && got_fd1 >= 0,
                           "sockmsg_stream merge fd valid");
            }
            if (got_fd0 >= 0 && got_fd1 >= 0) {
                src0 = fd_get(proc_current(), txfd);
                src1 = fd_get(proc_current(), rxfd);
                got0 = fd_get(proc_current(), got_fd0);
                got1 = fd_get(proc_current(), got_fd1);
                test_check(src0 != NULL && src1 != NULL && got0 != NULL && got1 != NULL,
                           "sockmsg_stream merge fd get");
                if (src0 && src1 && got0 && got1) {
                    test_check(src0 == got0, "sockmsg_stream merge fd order 0");
                    test_check(src1 == got1, "sockmsg_stream merge fd order 1");
                }
                if (src0)
                    file_put(src0);
                if (src1)
                    file_put(src1);
                if (got0)
                    file_put(got0);
                if (got1)
                    file_put(got1);
                (void)fd_close(proc_current(), got_fd0);
                (void)fd_close(proc_current(), got_fd1);
            }
        }
    }
    }

    if (phases & SOCKMSG_STREAM_PHASE_BOUNDARY_DROP) {
        int64_t ret64 = 0;

    ret = copy_to_user(u_send_buf, "AA", 2);
    test_check(ret == 0, "sockmsg_stream copy plain pre-ctrl");
    if (ret < 0)
        goto out;
    ret64 = sys_sendto((uint64_t)txfd, (uint64_t)u_send_buf, 2, 0, 0, 0);
    test_check(ret64 == 2, "sockmsg_stream sendto plain pre-ctrl");

    ret = copy_to_user(u_send_buf, "BFD1", 4);
    test_check(ret == 0, "sockmsg_stream copy rights boundary buf");
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_ctrl, &ctrl_rights, sizeof(ctrl_rights));
    test_check(ret == 0, "sockmsg_stream copy rights boundary hdr");
    if (ret == 0) {
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_rights), &rights_fd,
                           sizeof(rights_fd));
        test_check(ret == 0, "sockmsg_stream copy rights boundary payload");
    }
    if (ret < 0)
        goto out;
    send_msg.msg_control = u_ctrl;
    send_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_stream copy rights boundary send msg");
    if (ret < 0)
        goto out;
    ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream sendmsg rights boundary");

    if (ret64 == 4) {
        recv_iov.iov_len = 2;
        ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
        test_check(ret == 0, "sockmsg_stream copy pre-ctrl recv iov");
        recv_msg.msg_control = u_ctrl;
        recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg_stream copy pre-ctrl recv msg");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
            test_check(ret64 == 2, "sockmsg_stream recvmsg pre-ctrl bytes");
        }
        if (ret64 == 2) {
            char got_pre[2] = {0};
            struct test_socket_msghdr got_msg = {0};
            ret = copy_from_user(got_pre, u_recv_buf, sizeof(got_pre));
            test_check(ret == 0, "sockmsg_stream read pre-ctrl bytes");
            ret = copy_from_user(&got_msg, u_recv_msg, sizeof(got_msg));
            test_check(ret == 0, "sockmsg_stream read pre-ctrl msg");
            if (ret == 0) {
                test_check(memcmp(got_pre, "AA", 2) == 0,
                           "sockmsg_stream pre-ctrl data");
                test_check(got_msg.msg_controllen == 0,
                           "sockmsg_stream pre-ctrl no cmsg");
                test_check((got_msg.msg_flags & MSG_CTRUNC) == 0,
                           "sockmsg_stream pre-ctrl no ctrunc");
            }
        }
    }

    recv_iov.iov_len = 8;
    ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
    test_check(ret == 0, "sockmsg_stream restore recv iov");

    if (ret64 == 2) {
        recv_iov.iov_len = 4;
        ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
        test_check(ret == 0, "sockmsg_stream copy boundary recv iov");
        recv_msg.msg_control = u_ctrl;
        recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg_stream copy boundary recv msg");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
            test_check(ret64 == 4, "sockmsg_stream recvmsg boundary rights");
        }
        if (ret64 == 4) {
            char got[4] = {0};
            struct test_socket_cmsghdr got_ctrl = {0};
            int32_t got_fd = -1;
            ret = copy_from_user(got, u_recv_buf, sizeof(got));
            test_check(ret == 0, "sockmsg_stream read boundary data");
            ret = copy_from_user(&got_ctrl, u_ctrl, sizeof(got_ctrl));
            test_check(ret == 0, "sockmsg_stream read boundary ctrl");
            ret = copy_from_user(&got_fd, u_rights, sizeof(got_fd));
            test_check(ret == 0, "sockmsg_stream read boundary fd");
            if (ret == 0) {
                test_check(memcmp(got, "BFD1", 4) == 0,
                           "sockmsg_stream boundary data");
                test_check(got_ctrl.cmsg_type == TEST_SCM_RIGHTS,
                           "sockmsg_stream boundary ctrl type");
                test_check(got_fd >= 0, "sockmsg_stream boundary fd valid");
            }
            if (got_fd >= 0)
                (void)fd_close(proc_current(), got_fd);
        }
    }

    recv_iov.iov_len = 8;
    ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
    test_check(ret == 0, "sockmsg_stream restore recv iov after boundary");

    ret = copy_to_user(u_send_buf, "DROP", 4);
    test_check(ret == 0, "sockmsg_stream copy recvfrom-drop send buf");
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_ctrl, &ctrl_cred, sizeof(ctrl_cred));
    test_check(ret == 0, "sockmsg_stream copy recvfrom-drop cred hdr");
    if (ret == 0) {
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_cred), &cred,
                           sizeof(cred));
        test_check(ret == 0, "sockmsg_stream copy recvfrom-drop cred payload");
    }
    if (ret < 0)
        goto out;
    send_msg.msg_control = u_ctrl;
    send_msg.msg_controllen = test_socket_cmsg_align(ctrl_cred.cmsg_len);
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_stream copy recvfrom-drop send msg");
    if (ret < 0)
        goto out;
    ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream sendmsg recvfrom-drop");

    if (ret64 == 4) {
        ret64 = sys_recvfrom((uint64_t)rxfd, (uint64_t)u_recv_buf, 4, 0, 0, 0);
        test_check(ret64 == 4, "sockmsg_stream recvfrom consumes ctrl-data");
    }
    if (ret64 == 4) {
        char got_drop[4] = {0};
        ret = copy_from_user(got_drop, u_recv_buf, sizeof(got_drop));
        test_check(ret == 0, "sockmsg_stream read recvfrom consumed");
        if (ret == 0) {
            test_check(memcmp(got_drop, "DROP", 4) == 0,
                       "sockmsg_stream recvfrom consumed data");
        }
    }

    ret = copy_to_user(u_send_buf, "PLN1", 4);
    test_check(ret == 0, "sockmsg_stream copy post-drop plain");
    if (ret < 0)
        goto out;
    ret64 = sys_sendto((uint64_t)txfd, (uint64_t)u_send_buf, 4, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream sendto post-drop plain");
    if (ret64 == 4) {
        recv_iov.iov_len = 4;
        ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
        test_check(ret == 0, "sockmsg_stream copy post-drop recv iov");
        recv_msg.msg_control = u_ctrl;
        recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_cred.cmsg_len);
        ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
        test_check(ret == 0, "sockmsg_stream copy post-drop recv msg");
        if (ret == 0) {
            ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
            test_check(ret64 == 4, "sockmsg_stream recvmsg post-drop plain");
        }
        if (ret64 == 4) {
            char got_plain[4] = {0};
            struct test_socket_msghdr got_msg = {0};
            ret = copy_from_user(got_plain, u_recv_buf, sizeof(got_plain));
            test_check(ret == 0, "sockmsg_stream read post-drop plain");
            ret = copy_from_user(&got_msg, u_recv_msg, sizeof(got_msg));
            test_check(ret == 0, "sockmsg_stream read post-drop msg");
            if (ret == 0) {
                test_check(memcmp(got_plain, "PLN1", 4) == 0,
                           "sockmsg_stream post-drop plain data");
                test_check(got_msg.msg_controllen == 0,
                           "sockmsg_stream post-drop no stale ctrl");
                test_check((got_msg.msg_flags & MSG_CTRUNC) == 0,
                           "sockmsg_stream post-drop no ctrunc");
            }
        }
    }
    }

out:
    close_fd_if_open(&rights_nodup_fd);
    close_fd_if_open(&rights_src_fd);
    close_fd_if_open(&txfd);
    close_fd_if_open(&rxfd);
    close_socket_if_open(&tx);
    close_socket_if_open(&rx);
    if (mapped)
        user_map_end(&um);
}

static void test_unix_stream_msg_control_basic_semantics(void) {
    test_unix_stream_msg_control_semantics_phase(SOCKMSG_STREAM_PHASE_BASIC);
}

static void test_unix_stream_msg_control_peek_merge_semantics(void) {
    test_unix_stream_msg_control_semantics_phase(SOCKMSG_STREAM_PHASE_PEEK_MERGE);
}

static void test_unix_stream_msg_control_boundary_drop_semantics(void) {
    test_unix_stream_msg_control_semantics_phase(
        SOCKMSG_STREAM_PHASE_BOUNDARY_DROP);
}

static void test_unix_stream_msg_control_merge_trunc_semantics(void) {
    struct socket *tx = NULL;
    struct socket *rx = NULL;
    int txfd = -1;
    int rxfd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;

    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &tx);
    test_check(ret == 0, "sockmsg_stream_trunc create tx");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &rx);
    test_check(ret == 0, "sockmsg_stream_trunc create rx");
    if (!tx || !rx)
        goto out;

    ret = unix_socketpair_connect(tx, rx);
    test_check(ret == 0, "sockmsg_stream_trunc socketpair connect");
    if (ret < 0)
        goto out;

    txfd = socket_install_fd(&tx);
    rxfd = socket_install_fd(&rx);
    test_check(txfd >= 0, "sockmsg_stream_trunc install tx fd");
    test_check(rxfd >= 0, "sockmsg_stream_trunc install rx fd");
    if (txfd < 0 || rxfd < 0)
        goto out;

    ret = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "sockmsg_stream_trunc user map");
    if (ret < 0)
        goto out;
    mapped = true;

    struct test_socket_iovec *u_send_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x000);
    struct test_socket_iovec *u_recv_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x020);
    struct test_socket_msghdr *u_send_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x040);
    struct test_socket_msghdr *u_recv_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x080);
    char *u_send_buf = (char *)user_map_ptr(&um, 0x0C0);
    char *u_recv_buf = (char *)user_map_ptr(&um, 0x100);
    struct test_socket_cmsghdr *u_ctrl =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x140);
    int32_t *u_rights = (int32_t *)user_map_ptr(&um, 0x180);
    test_check(u_send_iov && u_recv_iov && u_send_msg && u_recv_msg &&
                   u_send_buf && u_recv_buf && u_ctrl && u_rights,
               "sockmsg_stream_trunc user pointers");
    if (!u_send_iov || !u_recv_iov || !u_send_msg || !u_recv_msg ||
        !u_send_buf || !u_recv_buf || !u_ctrl || !u_rights) {
        goto out;
    }

    struct test_socket_iovec send_iov = {
        .iov_base = u_send_buf,
        .iov_len = 4,
    };
    struct test_socket_iovec recv_iov = {
        .iov_base = u_recv_buf,
        .iov_len = 8,
    };
    ret = copy_to_user(u_send_iov, &send_iov, sizeof(send_iov));
    test_check(ret == 0, "sockmsg_stream_trunc copy send iov");
    ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
    test_check(ret == 0, "sockmsg_stream_trunc copy recv iov");
    if (ret < 0)
        goto out;

    struct test_socket_msghdr send_msg = {
        .msg_iov = u_send_iov,
        .msg_iovlen = 1,
    };
    struct test_socket_msghdr recv_msg = {
        .msg_iov = u_recv_iov,
        .msg_iovlen = 1,
    };

    int32_t rights_a[10];
    int32_t rights_b[10];
    for (size_t i = 0; i < 10; i++) {
        rights_a[i] = txfd;
        rights_b[i] = rxfd;
    }

    struct test_socket_cmsghdr ctrl_10 = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr) + sizeof(rights_a),
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = TEST_SCM_RIGHTS,
    };
    size_t ctrl_10_len = test_socket_cmsg_align(ctrl_10.cmsg_len);
    ret = copy_to_user(u_ctrl, &ctrl_10, sizeof(ctrl_10));
    test_check(ret == 0, "sockmsg_stream_trunc copy rights hdr a");
    if (ret == 0) {
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_10), rights_a,
                           sizeof(rights_a));
        test_check(ret == 0, "sockmsg_stream_trunc copy rights payload a");
    }
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_send_buf, "T001", 4);
    test_check(ret == 0, "sockmsg_stream_trunc copy send buf a");
    if (ret < 0)
        goto out;
    send_msg.msg_control = u_ctrl;
    send_msg.msg_controllen = ctrl_10_len;
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_stream_trunc copy send msg a");
    if (ret < 0)
        goto out;
    int64_t ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream_trunc sendmsg a");
    if (ret64 != 4)
        goto out;

    ret = copy_to_user(u_ctrl, &ctrl_10, sizeof(ctrl_10));
    test_check(ret == 0, "sockmsg_stream_trunc copy rights hdr b");
    if (ret == 0) {
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_10), rights_b,
                           sizeof(rights_b));
        test_check(ret == 0, "sockmsg_stream_trunc copy rights payload b");
    }
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_send_buf, "T002", 4);
    test_check(ret == 0, "sockmsg_stream_trunc copy send buf b");
    if (ret < 0)
        goto out;
    send_msg.msg_control = u_ctrl;
    send_msg.msg_controllen = ctrl_10_len;
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_stream_trunc copy send msg b");
    if (ret < 0)
        goto out;
    ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream_trunc sendmsg b");
    if (ret64 != 4)
        goto out;

    struct test_socket_cmsghdr ctrl_16 = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr) + sizeof(int32_t) * 16,
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = TEST_SCM_RIGHTS,
    };
    recv_msg.msg_control = u_ctrl;
    recv_msg.msg_controllen = test_socket_cmsg_align(ctrl_16.cmsg_len);
    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg_stream_trunc copy recv msg");
    if (ret < 0)
        goto out;
    ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
    test_check(ret64 == 8, "sockmsg_stream_trunc recvmsg merged");
    if (ret64 == 8) {
        struct test_socket_msghdr got_msg = {0};
        struct test_socket_cmsghdr got_ctrl = {0};
        int32_t got_fds[16];
        bool got_valid = true;
        bool source_ok = true;
        bool saw_tx = false;
        bool saw_rx = false;
        struct file *src_tx = fd_get(proc_current(), txfd);
        struct file *src_rx = fd_get(proc_current(), rxfd);

        memset(got_fds, -1, sizeof(got_fds));
        ret = copy_from_user(&got_msg, u_recv_msg, sizeof(got_msg));
        test_check(ret == 0, "sockmsg_stream_trunc read recv msg");
        ret = copy_from_user(&got_ctrl, u_ctrl, sizeof(got_ctrl));
        test_check(ret == 0, "sockmsg_stream_trunc read ctrl hdr");
        ret = copy_from_user(got_fds, (uint8_t *)u_ctrl + sizeof(got_ctrl),
                             sizeof(got_fds));
        test_check(ret == 0, "sockmsg_stream_trunc read ctrl fds");
        if (ret == 0) {
            test_check((got_msg.msg_flags & MSG_CTRUNC) != 0,
                       "sockmsg_stream_trunc recv ctrunc set");
            test_check(got_ctrl.cmsg_type == TEST_SCM_RIGHTS,
                       "sockmsg_stream_trunc recv ctrl type");
            test_check(got_msg.msg_controllen ==
                           test_socket_cmsg_align(ctrl_16.cmsg_len),
                       "sockmsg_stream_trunc recv controllen");
        }

        for (size_t i = 0; i < 16; i++) {
            if (got_fds[i] < 0) {
                got_valid = false;
                continue;
            }
            struct file *gotf = fd_get(proc_current(), got_fds[i]);
            if (!gotf) {
                got_valid = false;
            } else {
                if ((!src_tx || gotf != src_tx) && (!src_rx || gotf != src_rx))
                    source_ok = false;
                if (src_tx && gotf == src_tx)
                    saw_tx = true;
                if (src_rx && gotf == src_rx)
                    saw_rx = true;
                file_put(gotf);
            }
            (void)fd_close(proc_current(), got_fds[i]);
        }
        test_check(got_valid, "sockmsg_stream_trunc recv fd valid");
        test_check(source_ok, "sockmsg_stream_trunc recv fd source");
        test_check(saw_tx && saw_rx, "sockmsg_stream_trunc recv fd mixed");
        if (src_tx)
            file_put(src_tx);
        if (src_rx)
            file_put(src_rx);
    }

out:
    close_fd_if_open(&txfd);
    close_fd_if_open(&rxfd);
    close_socket_if_open(&tx);
    close_socket_if_open(&rx);
    if (mapped)
        user_map_end(&um);
}

static void test_unix_stream_recvmmsg_control_semantics(void) {
    struct socket *tx = NULL;
    struct socket *rx = NULL;
    int txfd = -1;
    int rxfd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;

    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &tx);
    test_check(ret == 0, "sockmsg_stream_mmsg create tx");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &rx);
    test_check(ret == 0, "sockmsg_stream_mmsg create rx");
    if (!tx || !rx)
        goto out;

    ret = unix_socketpair_connect(tx, rx);
    test_check(ret == 0, "sockmsg_stream_mmsg socketpair connect");
    if (ret < 0)
        goto out;

    txfd = socket_install_fd(&tx);
    rxfd = socket_install_fd(&rx);
    test_check(txfd >= 0, "sockmsg_stream_mmsg install tx fd");
    test_check(rxfd >= 0, "sockmsg_stream_mmsg install rx fd");
    if (txfd < 0 || rxfd < 0)
        goto out;

    ret = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "sockmsg_stream_mmsg user map");
    if (ret < 0)
        goto out;
    mapped = true;

    struct test_socket_iovec *u_send_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x000);
    struct test_socket_msghdr *u_send_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x040);
    char *u_send_buf = (char *)user_map_ptr(&um, 0x080);
    struct test_socket_cmsghdr *u_send_ctrl =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x0C0);

    struct test_socket_iovec *u_recv_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x140);
    struct test_socket_mmsghdr *u_recv_vec =
        (struct test_socket_mmsghdr *)user_map_ptr(&um, 0x180);
    char *u_recv_buf0 = (char *)user_map_ptr(&um, 0x220);
    char *u_recv_buf1 = (char *)user_map_ptr(&um, 0x260);
    struct test_socket_cmsghdr *u_recv_ctrl0 =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x2A0);
    struct test_socket_cmsghdr *u_recv_ctrl1 =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x2E0);
    int32_t *u_recv_rights0 = (int32_t *)user_map_ptr(&um, 0x2B0);
    int32_t *u_recv_rights1 = (int32_t *)user_map_ptr(&um, 0x2F0);
    test_check(u_send_iov && u_send_msg && u_send_buf && u_send_ctrl &&
                   u_recv_iov && u_recv_vec && u_recv_buf0 &&
                   u_recv_buf1 && u_recv_ctrl0 && u_recv_ctrl1 && u_recv_rights0 &&
                   u_recv_rights1,
               "sockmsg_stream_mmsg user pointers");
    if (!u_send_iov || !u_send_msg || !u_send_buf || !u_send_ctrl ||
        !u_recv_iov || !u_recv_vec || !u_recv_buf0 ||
        !u_recv_buf1 || !u_recv_ctrl0 || !u_recv_ctrl1 || !u_recv_rights0 ||
        !u_recv_rights1) {
        goto out;
    }

    struct test_socket_iovec send_iov = {
        .iov_base = u_send_buf,
        .iov_len = 4,
    };
    ret = copy_to_user(u_send_iov, &send_iov, sizeof(send_iov));
    test_check(ret == 0, "sockmsg_stream_mmsg copy send iov");
    if (ret < 0)
        goto out;

    struct test_socket_cmsghdr ctrl_rights = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr) + sizeof(int32_t),
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = TEST_SCM_RIGHTS,
    };
    struct test_socket_msghdr send_msg = {
        .msg_iov = u_send_iov,
        .msg_iovlen = 1,
        .msg_control = u_send_ctrl,
        .msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len),
    };
    ret = copy_to_user(u_send_ctrl, &ctrl_rights, sizeof(ctrl_rights));
    test_check(ret == 0, "sockmsg_stream_mmsg copy send ctrl hdr");
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_stream_mmsg copy send msg");
    if (ret < 0)
        goto out;

    int32_t right = txfd;
    ret = copy_to_user((uint8_t *)u_send_ctrl + sizeof(ctrl_rights), &right,
                       sizeof(right));
    test_check(ret == 0, "sockmsg_stream_mmsg copy send right a");
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_send_buf, "MMA1", 4);
    test_check(ret == 0, "sockmsg_stream_mmsg copy send buf a");
    if (ret < 0)
        goto out;
    int64_t ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream_mmsg sendmsg a");
    if (ret64 != 4)
        goto out;

    right = rxfd;
    ret = copy_to_user((uint8_t *)u_send_ctrl + sizeof(ctrl_rights), &right,
                       sizeof(right));
    test_check(ret == 0, "sockmsg_stream_mmsg copy send right b");
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_send_buf, "MMB2", 4);
    test_check(ret == 0, "sockmsg_stream_mmsg copy send buf b");
    if (ret < 0)
        goto out;
    ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream_mmsg sendmsg b");
    if (ret64 != 4)
        goto out;

    struct test_socket_iovec recv_iov0 = {
        .iov_base = u_recv_buf0,
        .iov_len = 4,
    };
    struct test_socket_iovec recv_iov1 = {
        .iov_base = u_recv_buf1,
        .iov_len = 4,
    };
    ret = copy_to_user(&u_recv_iov[0], &recv_iov0, sizeof(recv_iov0));
    test_check(ret == 0, "sockmsg_stream_mmsg copy recv iov0");
    ret = copy_to_user(&u_recv_iov[1], &recv_iov1, sizeof(recv_iov1));
    test_check(ret == 0, "sockmsg_stream_mmsg copy recv iov1");
    if (ret < 0)
        goto out;

    struct test_socket_mmsghdr recv_vec[2];
    memset(recv_vec, 0, sizeof(recv_vec));
    recv_vec[0].msg_hdr.msg_iov = &u_recv_iov[0];
    recv_vec[0].msg_hdr.msg_iovlen = 1;
    recv_vec[0].msg_hdr.msg_control = u_recv_ctrl0;
    recv_vec[0].msg_hdr.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
    recv_vec[1].msg_hdr.msg_iov = &u_recv_iov[1];
    recv_vec[1].msg_hdr.msg_iovlen = 1;
    recv_vec[1].msg_hdr.msg_control = u_recv_ctrl1;
    recv_vec[1].msg_hdr.msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len);
    ret = copy_to_user(u_recv_vec, recv_vec, sizeof(recv_vec));
    test_check(ret == 0, "sockmsg_stream_mmsg copy recv vec");
    if (ret < 0)
        goto out;

    ret64 = sys_recvmmsg((uint64_t)rxfd, (uint64_t)u_recv_vec, 2, 0, 0, 0);
    test_check(ret64 == 2, "sockmsg_stream_mmsg recvmmsg two");
    if (ret64 == 2) {
        struct test_socket_mmsghdr got_vec[2];
        char got0[4] = {0};
        char got1[4] = {0};
        struct test_socket_cmsghdr got_ctrl0 = {0};
        struct test_socket_cmsghdr got_ctrl1 = {0};
        int32_t got_fd0 = -1;
        int32_t got_fd1 = -1;
        struct file *src_tx = fd_get(proc_current(), txfd);
        struct file *src_rx = fd_get(proc_current(), rxfd);
        bool fd_ok = true;

        memset(got_vec, 0, sizeof(got_vec));
        ret = copy_from_user(got_vec, u_recv_vec, sizeof(got_vec));
        test_check(ret == 0, "sockmsg_stream_mmsg read recv vec");
        ret = copy_from_user(got0, u_recv_buf0, sizeof(got0));
        test_check(ret == 0, "sockmsg_stream_mmsg read recv buf0");
        ret = copy_from_user(got1, u_recv_buf1, sizeof(got1));
        test_check(ret == 0, "sockmsg_stream_mmsg read recv buf1");
        ret = copy_from_user(&got_ctrl0, u_recv_ctrl0, sizeof(got_ctrl0));
        test_check(ret == 0, "sockmsg_stream_mmsg read recv ctrl0");
        ret = copy_from_user(&got_ctrl1, u_recv_ctrl1, sizeof(got_ctrl1));
        test_check(ret == 0, "sockmsg_stream_mmsg read recv ctrl1");
        ret = copy_from_user(&got_fd0, u_recv_rights0, sizeof(got_fd0));
        test_check(ret == 0, "sockmsg_stream_mmsg read recv fd0");
        ret = copy_from_user(&got_fd1, u_recv_rights1, sizeof(got_fd1));
        test_check(ret == 0, "sockmsg_stream_mmsg read recv fd1");
        if (ret == 0) {
            test_check(got_vec[0].msg_len == 4 && got_vec[1].msg_len == 4,
                       "sockmsg_stream_mmsg recv lens");
            test_check(memcmp(got0, "MMA1", 4) == 0 &&
                           memcmp(got1, "MMB2", 4) == 0,
                       "sockmsg_stream_mmsg recv data");
            test_check(got_ctrl0.cmsg_type == TEST_SCM_RIGHTS &&
                           got_ctrl1.cmsg_type == TEST_SCM_RIGHTS,
                       "sockmsg_stream_mmsg recv ctrl type");
            test_check((got_vec[0].msg_hdr.msg_flags & MSG_CTRUNC) == 0 &&
                           (got_vec[1].msg_hdr.msg_flags & MSG_CTRUNC) == 0,
                       "sockmsg_stream_mmsg recv no ctrunc");
        }

        struct file *gotf0 = (got_fd0 >= 0) ? fd_get(proc_current(), got_fd0) : NULL;
        struct file *gotf1 = (got_fd1 >= 0) ? fd_get(proc_current(), got_fd1) : NULL;
        if (!gotf0 || !gotf1)
            fd_ok = false;
        if (gotf0 && (!src_tx || gotf0 != src_tx) &&
            (!src_rx || gotf0 != src_rx))
            fd_ok = false;
        if (gotf1 && (!src_tx || gotf1 != src_tx) &&
            (!src_rx || gotf1 != src_rx))
            fd_ok = false;
        test_check(fd_ok, "sockmsg_stream_mmsg recv fd valid");

        if (gotf0)
            file_put(gotf0);
        if (gotf1)
            file_put(gotf1);
        if (src_tx)
            file_put(src_tx);
        if (src_rx)
            file_put(src_rx);
        if (got_fd0 >= 0)
            (void)fd_close(proc_current(), got_fd0);
        if (got_fd1 >= 0)
            (void)fd_close(proc_current(), got_fd1);
    }

out:
    close_fd_if_open(&txfd);
    close_fd_if_open(&rxfd);
    close_socket_if_open(&tx);
    close_socket_if_open(&rx);
    if (mapped)
        user_map_end(&um);
}

static void test_unix_stream_recvmmsg_peek_control_semantics(void) {
    struct socket *tx = NULL;
    struct socket *rx = NULL;
    int txfd = -1;
    int rxfd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;

    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &tx);
    test_check(ret == 0, "sockmsg_stream_mmsg_peek create tx");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &rx);
    test_check(ret == 0, "sockmsg_stream_mmsg_peek create rx");
    if (!tx || !rx)
        goto out;

    ret = unix_socketpair_connect(tx, rx);
    test_check(ret == 0, "sockmsg_stream_mmsg_peek socketpair connect");
    if (ret < 0)
        goto out;

    txfd = socket_install_fd(&tx);
    rxfd = socket_install_fd(&rx);
    test_check(txfd >= 0, "sockmsg_stream_mmsg_peek install tx fd");
    test_check(rxfd >= 0, "sockmsg_stream_mmsg_peek install rx fd");
    if (txfd < 0 || rxfd < 0)
        goto out;

    ret = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "sockmsg_stream_mmsg_peek user map");
    if (ret < 0)
        goto out;
    mapped = true;

    struct test_socket_iovec *u_send_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x000);
    struct test_socket_msghdr *u_send_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x040);
    char *u_send_buf = (char *)user_map_ptr(&um, 0x080);
    struct test_socket_cmsghdr *u_send_ctrl =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x0C0);

    struct test_socket_iovec *u_recv_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x140);
    struct test_socket_mmsghdr *u_recv_vec =
        (struct test_socket_mmsghdr *)user_map_ptr(&um, 0x180);
    char *u_recv_buf0 = (char *)user_map_ptr(&um, 0x220);
    char *u_recv_buf1 = (char *)user_map_ptr(&um, 0x260);
    struct test_socket_cmsghdr *u_recv_ctrl0 =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x2A0);
    struct test_socket_cmsghdr *u_recv_ctrl1 =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x2E0);
    int32_t *u_recv_fd0 = (int32_t *)user_map_ptr(&um, 0x2B0);
    int32_t *u_recv_fd1 = (int32_t *)user_map_ptr(&um, 0x2F0);
    struct test_socket_msghdr *u_recv_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x340);

    test_check(u_send_iov && u_send_msg && u_send_buf && u_send_ctrl &&
                   u_recv_iov && u_recv_vec && u_recv_buf0 &&
                   u_recv_buf1 && u_recv_ctrl0 && u_recv_ctrl1 && u_recv_fd0 &&
                   u_recv_fd1 && u_recv_msg,
               "sockmsg_stream_mmsg_peek user pointers");
    if (!u_send_iov || !u_send_msg || !u_send_buf || !u_send_ctrl ||
        !u_recv_iov || !u_recv_vec || !u_recv_buf0 ||
        !u_recv_buf1 || !u_recv_ctrl0 || !u_recv_ctrl1 || !u_recv_fd0 ||
        !u_recv_fd1 || !u_recv_msg) {
        goto out;
    }

    struct test_socket_iovec send_iov = {
        .iov_base = u_send_buf,
        .iov_len = 4,
    };
    ret = copy_to_user(u_send_iov, &send_iov, sizeof(send_iov));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy send iov");
    if (ret < 0)
        goto out;

    struct test_socket_cmsghdr ctrl_right = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr) + sizeof(int32_t),
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = TEST_SCM_RIGHTS,
    };
    struct test_socket_msghdr send_msg = {
        .msg_iov = u_send_iov,
        .msg_iovlen = 1,
        .msg_control = u_send_ctrl,
        .msg_controllen = test_socket_cmsg_align(ctrl_right.cmsg_len),
    };
    ret = copy_to_user(u_send_ctrl, &ctrl_right, sizeof(ctrl_right));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy send ctrl hdr");
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy send msg");
    if (ret < 0)
        goto out;

    int32_t right = txfd;
    ret = copy_to_user((uint8_t *)u_send_ctrl + sizeof(ctrl_right), &right,
                       sizeof(right));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy send right a");
    ret = copy_to_user(u_send_buf, "PKA1", 4);
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy send buf a");
    if (ret < 0)
        goto out;
    int64_t ret64 =
        sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream_mmsg_peek sendmsg a");
    if (ret64 != 4)
        goto out;

    right = rxfd;
    ret = copy_to_user((uint8_t *)u_send_ctrl + sizeof(ctrl_right), &right,
                       sizeof(right));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy send right b");
    ret = copy_to_user(u_send_buf, "PKB2", 4);
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy send buf b");
    if (ret < 0)
        goto out;
    ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream_mmsg_peek sendmsg b");
    if (ret64 != 4)
        goto out;

    struct test_socket_iovec recv_iov0 = {
        .iov_base = u_recv_buf0,
        .iov_len = 4,
    };
    struct test_socket_iovec recv_iov1 = {
        .iov_base = u_recv_buf1,
        .iov_len = 4,
    };
    ret = copy_to_user(&u_recv_iov[0], &recv_iov0, sizeof(recv_iov0));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy recv iov0");
    ret = copy_to_user(&u_recv_iov[1], &recv_iov1, sizeof(recv_iov1));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy recv iov1");
    if (ret < 0)
        goto out;

    struct test_socket_mmsghdr recv_vec[2];
    memset(recv_vec, 0, sizeof(recv_vec));
    recv_vec[0].msg_hdr.msg_iov = &u_recv_iov[0];
    recv_vec[0].msg_hdr.msg_iovlen = 1;
    recv_vec[0].msg_hdr.msg_control = u_recv_ctrl0;
    recv_vec[0].msg_hdr.msg_controllen = test_socket_cmsg_align(ctrl_right.cmsg_len);
    recv_vec[1].msg_hdr.msg_iov = &u_recv_iov[1];
    recv_vec[1].msg_hdr.msg_iovlen = 1;
    recv_vec[1].msg_hdr.msg_control = u_recv_ctrl1;
    recv_vec[1].msg_hdr.msg_controllen = test_socket_cmsg_align(ctrl_right.cmsg_len);
    ret = copy_to_user(u_recv_vec, recv_vec, sizeof(recv_vec));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy recv vec");
    if (ret < 0)
        goto out;

    ret64 = sys_recvmmsg((uint64_t)rxfd, (uint64_t)u_recv_vec, 2, MSG_PEEK, 0, 0);
    test_check(ret64 == 2, "sockmsg_stream_mmsg_peek recvmmsg count");
    if (ret64 == 2) {
        struct test_socket_mmsghdr got_vec[2];
        char got0[4] = {0};
        char got1[4] = {0};
        struct test_socket_cmsghdr got_ctrl0 = {0};
        struct test_socket_cmsghdr got_ctrl1 = {0};
        int32_t got_fd0 = -1;
        int32_t got_fd1 = -1;
        struct file *src_tx = fd_get(proc_current(), txfd);
        struct file *fd0 = NULL;
        struct file *fd1 = NULL;

        memset(got_vec, 0, sizeof(got_vec));
        ret = copy_from_user(got_vec, u_recv_vec, sizeof(got_vec));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recv vec");
        ret = copy_from_user(got0, u_recv_buf0, sizeof(got0));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recv buf0");
        ret = copy_from_user(got1, u_recv_buf1, sizeof(got1));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recv buf1");
        ret = copy_from_user(&got_ctrl0, u_recv_ctrl0, sizeof(got_ctrl0));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recv ctrl0");
        ret = copy_from_user(&got_ctrl1, u_recv_ctrl1, sizeof(got_ctrl1));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recv ctrl1");
        ret = copy_from_user(&got_fd0, u_recv_fd0, sizeof(got_fd0));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recv fd0");
        ret = copy_from_user(&got_fd1, u_recv_fd1, sizeof(got_fd1));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recv fd1");
        if (ret == 0) {
            test_check(got_vec[0].msg_len == 4 && got_vec[1].msg_len == 4,
                       "sockmsg_stream_mmsg_peek recv lens");
            test_check(memcmp(got0, "PKA1", 4) == 0 &&
                           memcmp(got1, "PKA1", 4) == 0,
                       "sockmsg_stream_mmsg_peek recv data same");
            test_check(got_ctrl0.cmsg_type == TEST_SCM_RIGHTS &&
                           got_ctrl1.cmsg_type == TEST_SCM_RIGHTS,
                       "sockmsg_stream_mmsg_peek recv ctrl type");
        }

        fd0 = (got_fd0 >= 0) ? fd_get(proc_current(), got_fd0) : NULL;
        fd1 = (got_fd1 >= 0) ? fd_get(proc_current(), got_fd1) : NULL;
        test_check(fd0 != NULL && fd1 != NULL,
                   "sockmsg_stream_mmsg_peek recv fds valid");
        if (fd0 && src_tx)
            test_check(fd0 == src_tx, "sockmsg_stream_mmsg_peek recv fd0 source");
        if (fd1 && src_tx)
            test_check(fd1 == src_tx, "sockmsg_stream_mmsg_peek recv fd1 source");

        if (fd0)
            file_put(fd0);
        if (fd1)
            file_put(fd1);
        if (src_tx)
            file_put(src_tx);
        if (got_fd0 >= 0)
            (void)fd_close(proc_current(), got_fd0);
        if (got_fd1 >= 0)
            (void)fd_close(proc_current(), got_fd1);
    }

    struct test_socket_msghdr recv_msg = {
        .msg_iov = &u_recv_iov[0],
        .msg_iovlen = 1,
        .msg_control = u_recv_ctrl0,
        .msg_controllen = test_socket_cmsg_align(ctrl_right.cmsg_len),
    };
    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek copy recv msg");
    if (ret < 0)
        goto out;

    ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream_mmsg_peek recvmsg consume a");
    if (ret64 == 4) {
        struct test_socket_msghdr got_msg = {0};
        char got[4] = {0};
        int32_t got_fd = -1;
        struct file *src_tx = fd_get(proc_current(), txfd);
        struct file *gotf = NULL;

        ret = copy_from_user(&got_msg, u_recv_msg, sizeof(got_msg));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recvmsg a hdr");
        ret = copy_from_user(got, u_recv_buf0, sizeof(got));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recvmsg a data");
        ret = copy_from_user(&got_fd, u_recv_fd0, sizeof(got_fd));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recvmsg a fd");
        if (ret == 0) {
            test_check(memcmp(got, "PKA1", 4) == 0,
                       "sockmsg_stream_mmsg_peek recvmsg a data");
            test_check((got_msg.msg_flags & MSG_CTRUNC) == 0,
                       "sockmsg_stream_mmsg_peek recvmsg a no ctrunc");
        }

        gotf = (got_fd >= 0) ? fd_get(proc_current(), got_fd) : NULL;
        test_check(gotf != NULL, "sockmsg_stream_mmsg_peek recvmsg a fd valid");
        if (gotf && src_tx)
            test_check(gotf == src_tx, "sockmsg_stream_mmsg_peek recvmsg a source");
        if (gotf)
            file_put(gotf);
        if (src_tx)
            file_put(src_tx);
        if (got_fd >= 0)
            (void)fd_close(proc_current(), got_fd);
    }

    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg_stream_mmsg_peek recopy recv msg");
    if (ret < 0)
        goto out;

    ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_stream_mmsg_peek recvmsg consume b");
    if (ret64 == 4) {
        char got[4] = {0};
        int32_t got_fd = -1;
        struct file *src_rx = fd_get(proc_current(), rxfd);
        struct file *gotf = NULL;

        ret = copy_from_user(got, u_recv_buf0, sizeof(got));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recvmsg b data");
        ret = copy_from_user(&got_fd, u_recv_fd0, sizeof(got_fd));
        test_check(ret == 0, "sockmsg_stream_mmsg_peek read recvmsg b fd");
        if (ret == 0)
            test_check(memcmp(got, "PKB2", 4) == 0,
                       "sockmsg_stream_mmsg_peek recvmsg b data");

        gotf = (got_fd >= 0) ? fd_get(proc_current(), got_fd) : NULL;
        test_check(gotf != NULL, "sockmsg_stream_mmsg_peek recvmsg b fd valid");
        if (gotf && src_rx)
            test_check(gotf == src_rx, "sockmsg_stream_mmsg_peek recvmsg b source");
        if (gotf)
            file_put(gotf);
        if (src_rx)
            file_put(src_rx);
        if (got_fd >= 0)
            (void)fd_close(proc_current(), got_fd);
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
    uint8_t *u_buf = (uint8_t *)user_map_ptr(&um, 0x80);
    test_check(u_on != NULL, "sockabi user ptr");
    test_check(u_buf != NULL, "sockabi user buf ptr");
    if (!u_on || !u_buf)
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

    ret64 = sys_recvfrom((uint64_t)fd, (uint64_t)u_buf, 8, 0, 0, 0);
    test_check(ret64 == -EAGAIN, "sockabi recvfrom fd nonblock");

out:
    close_fd_if_open(&fd);
    if (mapped)
        user_map_end(&um);
}

static void test_socket_nonblock_syscall_semantics(void) {
    struct socket *listener = NULL;
    struct socket *client = NULL;
    struct socket *dgram = NULL;
    int listener_fd = -1;
    int client_fd = -1;
    int dgram_fd = -1;
    int accepted_fd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;

    struct sockaddr_un srv_addr;
    struct sockaddr_un dgram_addr;
    make_unix_addr(&srv_addr, SOCKET_TEST_UNIX_NB_SRV_PATH);
    make_unix_addr(&dgram_addr, SOCKET_TEST_UNIX_NB_DGRAM_PATH);

    int rc = sock_create(AF_UNIX, SOCK_STREAM, 0, &listener);
    test_check(rc == 0, "socknb create listener");
    rc = sock_create(AF_UNIX, SOCK_STREAM, 0, &client);
    test_check(rc == 0, "socknb create client");
    rc = sock_create(AF_UNIX, SOCK_DGRAM, 0, &dgram);
    test_check(rc == 0, "socknb create dgram");
    if (!listener || !client || !dgram)
        goto out;

    rc = listener->ops->bind(listener, (const struct sockaddr *)&srv_addr,
                             sizeof(srv_addr));
    test_check(rc == 0, "socknb bind listener");
    if (rc < 0)
        goto out;

    rc = listener->ops->listen(listener, 8);
    test_check(rc == 0, "socknb listen listener");
    if (rc < 0)
        goto out;

    rc = dgram->ops->bind(dgram, (const struct sockaddr *)&dgram_addr,
                          sizeof(dgram_addr));
    test_check(rc == 0, "socknb bind dgram");
    if (rc < 0)
        goto out;

    listener_fd = socket_install_fd(&listener);
    client_fd = socket_install_fd(&client);
    dgram_fd = socket_install_fd(&dgram);
    test_check(listener_fd >= 0, "socknb install listener fd");
    test_check(client_fd >= 0, "socknb install client fd");
    test_check(dgram_fd >= 0, "socknb install dgram fd");
    if (listener_fd < 0 || client_fd < 0 || dgram_fd < 0)
        goto out;

    rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "socknb user map");
    if (rc < 0)
        goto out;
    mapped = true;

    int *u_on = (int *)user_map_ptr(&um, 0x000);
    struct sockaddr_un *u_srv_addr = (struct sockaddr_un *)user_map_ptr(&um, 0x040);
    uint8_t *u_buf = (uint8_t *)user_map_ptr(&um, 0x180);
    int *u_optval = (int *)user_map_ptr(&um, 0x220);
    int *u_optlen = (int *)user_map_ptr(&um, 0x260);
    test_check(u_on && u_srv_addr && u_buf && u_optval && u_optlen,
               "socknb user pointers");
    if (!u_on || !u_srv_addr || !u_buf || !u_optval || !u_optlen)
        goto out;

    int on = 1;
    rc = copy_to_user(u_on, &on, sizeof(on));
    test_check(rc == 0, "socknb copy on");
    if (rc < 0)
        goto out;
    rc = copy_to_user(u_srv_addr, &srv_addr, sizeof(srv_addr));
    test_check(rc == 0, "socknb copy srv addr");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_ioctl((uint64_t)listener_fd, (uint64_t)FIONBIO,
                              (uint64_t)u_on, 0, 0, 0);
    test_check(ret64 == 0, "socknb listener fionbio");
    ret64 = sys_ioctl((uint64_t)client_fd, (uint64_t)FIONBIO, (uint64_t)u_on, 0,
                      0, 0);
    test_check(ret64 == 0, "socknb client fionbio");
    ret64 = sys_ioctl((uint64_t)dgram_fd, (uint64_t)FIONBIO, (uint64_t)u_on, 0, 0,
                      0);
    test_check(ret64 == 0, "socknb dgram fionbio");

    ret64 = sys_accept((uint64_t)listener_fd, 0, 0, 0, 0, 0);
    test_check(ret64 == -EAGAIN, "socknb accept nonblock eagain");

    ret64 = sys_connect((uint64_t)client_fd, (uint64_t)u_srv_addr,
                        sizeof(srv_addr), 0, 0, 0);
    test_check(ret64 == -EINPROGRESS || ret64 == 0,
               "socknb connect nonblock inprogress");

    if (ret64 == -EINPROGRESS) {
        int64_t retry = sys_connect((uint64_t)client_fd, (uint64_t)u_srv_addr,
                                    sizeof(srv_addr), 0, 0, 0);
        test_check(retry == -EALREADY, "socknb connect retry ealready");

        int64_t acc = -EAGAIN;
        for (int i = 0; i < 4000 && acc == -EAGAIN; i++) {
            acc = sys_accept((uint64_t)listener_fd, 0, 0, 0, 0, 0);
            if (acc == -EAGAIN)
                proc_yield();
        }
        test_check(acc >= 0, "socknb accept after connect");
        if (acc >= 0)
            accepted_fd = (int)acc;
    }

    ret64 = sys_connect((uint64_t)client_fd, (uint64_t)u_srv_addr,
                        sizeof(srv_addr), 0, 0, 0);
    test_check(ret64 == -EISCONN, "socknb connect after complete eisconn");

    int optlen = sizeof(int);
    rc = copy_to_user(u_optlen, &optlen, sizeof(optlen));
    test_check(rc == 0, "socknb copy optlen");
    if (rc == 0) {
        ret64 = sys_getsockopt((uint64_t)client_fd, SOL_SOCKET, SO_ERROR,
                               (uint64_t)u_optval, (uint64_t)u_optlen, 0);
        test_check(ret64 == 0, "socknb getsockopt so_error");
    }
    if (rc == 0 && ret64 == 0) {
        int soerr = -1;
        int got_optlen = 0;
        rc = copy_from_user(&soerr, u_optval, sizeof(soerr));
        test_check(rc == 0, "socknb read so_error");
        rc = copy_from_user(&got_optlen, u_optlen, sizeof(got_optlen));
        test_check(rc == 0, "socknb read so_error len");
        test_check(got_optlen == (int)sizeof(int), "socknb so_error len");
        test_check(soerr == 0, "socknb so_error clear");
    }

    ret64 = sys_recvfrom((uint64_t)dgram_fd, (uint64_t)u_buf, 8, 0, 0, 0);
    test_check(ret64 == -EAGAIN, "socknb recvfrom fd nonblock");

out:
    close_fd_if_open(&accepted_fd);
    close_fd_if_open(&dgram_fd);
    close_fd_if_open(&client_fd);
    close_fd_if_open(&listener_fd);
    close_socket_if_open(&dgram);
    close_socket_if_open(&client);
    close_socket_if_open(&listener);
    if (mapped)
        user_map_end(&um);
}

static void test_unix_stream_connect_error_transitions(void) {
    struct socket *listener = NULL;
    struct socket *client = NULL;
    struct sockaddr_un srv_addr;
    make_unix_addr(&srv_addr, SOCKET_TEST_UNIX_NB_SRV_PATH);

    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &listener);
    test_check(ret == 0, "sockconnerr create listener");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &client);
    test_check(ret == 0, "sockconnerr create client");
    if (!listener || !client)
        goto out;

    ret = listener->ops->bind(listener, (const struct sockaddr *)&srv_addr,
                              sizeof(srv_addr));
    test_check(ret == 0, "sockconnerr bind listener");
    if (ret < 0)
        goto out;

    ret = listener->ops->listen(listener, 8);
    test_check(ret == 0, "sockconnerr listen listener");
    if (ret < 0)
        goto out;

    ret = client->ops->connect(client, (const struct sockaddr *)&srv_addr,
                               sizeof(srv_addr), MSG_DONTWAIT);
    test_check(ret == -EINPROGRESS, "sockconnerr connect inprogress");
    if (ret != -EINPROGRESS)
        goto out;

    close_socket_if_open(&listener);

    bool ready = wait_socket_event(client, POLLOUT | POLLERR, POLLERR, 4000);
    test_check(ready, "sockconnerr poll error ready");
    if (ready) {
        int re = client->ops->poll(client, POLLOUT | POLLERR);
        test_check((re & POLLOUT) != 0, "sockconnerr poll writable on error");
        test_check((re & POLLERR) != 0, "sockconnerr poll err set");
    }

    int so_error = -1;
    int so_error_len = sizeof(so_error);
    ret = client->ops->getsockopt(client, SOL_SOCKET, SO_ERROR, &so_error,
                                  &so_error_len);
    test_check(ret == 0, "sockconnerr getsockopt so_error");
    test_check(so_error_len == (int)sizeof(so_error),
               "sockconnerr getsockopt so_error len");
    test_check(so_error == ECONNREFUSED, "sockconnerr so_error econnrefused");

    int re = client->ops->poll(client, POLLOUT | POLLERR);
    test_check((re & POLLERR) == 0, "sockconnerr poll err cleared");
out:
    close_socket_if_open(&client);
    close_socket_if_open(&listener);
}

static void test_socket_fcntl_nonblock_semantics(void) {
    struct socket *sock = NULL;
    int fd = -1;

    int ret = sock_create(AF_UNIX, SOCK_DGRAM, 0, &sock);
    test_check(ret == 0, "sockfcntl create dgram");
    if (ret < 0 || !sock)
        goto out;

    fd = socket_install_fd(&sock);
    test_check(fd >= 0, "sockfcntl install fd");
    if (fd < 0)
        goto out;

    int64_t fl = sys_fcntl((uint64_t)fd, F_GETFL, 0, 0, 0, 0);
    test_check(fl >= 0, "sockfcntl getfl initial");
    if (fl < 0)
        goto out;

    int64_t ret64 = sys_fcntl((uint64_t)fd, F_SETFL,
                              (uint64_t)((uint32_t)fl | O_NONBLOCK), 0, 0, 0);
    test_check(ret64 == 0, "sockfcntl setfl nonblock");

    fl = sys_fcntl((uint64_t)fd, F_GETFL, 0, 0, 0, 0);
    test_check(fl >= 0, "sockfcntl getfl nonblock");
    if (fl >= 0)
        test_check((((uint32_t)fl) & O_NONBLOCK) != 0,
                   "sockfcntl getfl has nonblock");

    ret64 = sys_recvfrom((uint64_t)fd, 0, 8, 0, 0, 0);
    test_check(ret64 == -EWOULDBLOCK, "sockfcntl recv empty ewouldblock");

    ret64 = sys_fcntl((uint64_t)fd, F_SETFL,
                      (uint64_t)((uint32_t)fl & ~O_NONBLOCK), 0, 0, 0);
    test_check(ret64 == 0, "sockfcntl clear nonblock");

    fl = sys_fcntl((uint64_t)fd, F_GETFL, 0, 0, 0, 0);
    test_check(fl >= 0, "sockfcntl getfl cleared");
    if (fl >= 0)
        test_check((((uint32_t)fl) & O_NONBLOCK) == 0,
                   "sockfcntl nonblock cleared");

out:
    close_fd_if_open(&fd);
    close_socket_if_open(&sock);
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

    ret = tmp->ops->connect(tmp, (const struct sockaddr *)&bad_addr,
                            sizeof(bad_addr), 0);
    test_check(ret == -ECONNREFUSED, "unix_dgram connect missing econnrefused");

    ret = tx->ops->connect(tx, (const struct sockaddr *)&rx_addr,
                           sizeof(rx_addr), 0);
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
                               sizeof(server_addr), 0);
    if (ret < 0) {
        goto out;
    }

    int pre = client->ops->poll(client, POLLOUT);
    if ((pre & POLLOUT) == 0) {
        goto out;
    }

    memset(buf, 0, sizeof(buf));
    int srclen = sizeof(src);
    memset(&src, 0, sizeof(src));
    ssize_t rd = server->ops->recvfrom(server, buf, sizeof(buf), MSG_DONTWAIT,
                                       (struct sockaddr *)&src, &srclen);
    if (rd != -EAGAIN)
        goto out;

    ssize_t wr = client->ops->sendto(client, "inet-udp", 8, 0, NULL, 0);
    if (wr != 8) {
        goto out;
    }

    if (!wait_socket_event(server, POLLIN, POLLIN, 3000)) {
        goto out;
    }

    srclen = sizeof(src);
    memset(&src, 0, sizeof(src));
    memset(buf, 0, sizeof(buf));
    rd = server->ops->recvfrom(server, buf, sizeof(buf), 0,
                               (struct sockaddr *)&src, &srclen);
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
    ret = listener->ops->accept(listener, &server, MSG_DONTWAIT);
    if (ret != -EAGAIN)
        goto out;

    ret = client->ops->connect(client, (const struct sockaddr *)&listener_addr,
                               sizeof(listener_addr), MSG_DONTWAIT);
    if (ret != -EINPROGRESS && ret != 0)
        goto out;

    if (ret == -EINPROGRESS) {
        int r2 = client->ops->connect(client,
                                      (const struct sockaddr *)&listener_addr,
                                      sizeof(listener_addr), MSG_DONTWAIT);
        if (r2 != -EALREADY && r2 != -EISCONN)
            goto out;
        int cre = 0;
        for (int i = 0; i < 4000; i++) {
            cre = client->ops->poll(client, POLLOUT | POLLERR);
            if (cre & (POLLOUT | POLLERR))
                break;
            proc_yield();
        }
        if ((cre & POLLOUT) == 0)
            goto out;
        int so_error = -1;
        int so_error_len = sizeof(so_error);
        ret = client->ops->getsockopt(client, SOL_SOCKET, SO_ERROR, &so_error,
                                      &so_error_len);
        if (ret < 0 || so_error_len != (int)sizeof(so_error) || so_error != 0)
            goto out;
    }

    ret = client->ops->connect(client, (const struct sockaddr *)&listener_addr,
                               sizeof(listener_addr), MSG_DONTWAIT);
    if (ret != -EISCONN)
        goto out;

    int lre = listener->ops->poll(listener, POLLIN);
    if ((lre & POLLIN) == 0)
        goto out;

    ret = listener->ops->accept(listener, &server, 0);
    if (ret < 0 || !server)
        goto out;

    memset(buf, 0, sizeof(buf));
    ssize_t rd =
        server->ops->recvfrom(server, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
    if (rd != -EAGAIN)
        goto out;

    ssize_t wr = client->ops->sendto(client, "tcp-ping", 8, 0, NULL, 0);
    if (wr != 8)
        goto out;
    if (!wait_socket_event(server, POLLIN, POLLIN, 3000))
        goto out;

    memset(buf, 0, sizeof(buf));
    rd = server->ops->recvfrom(server, buf, sizeof(buf), 0, NULL, NULL);
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

static bool run_inet_tcp_backlog_attempt(uint32_t loopback_ip,
                                         uint16_t server_port,
                                         uint16_t client1_port,
                                         uint16_t client2_port) {
    struct socket *listener = NULL;
    struct socket *client1 = NULL;
    struct socket *client2 = NULL;
    struct socket *server = NULL;
    struct socket *server2 = NULL;
    struct sockaddr_in listener_addr;
    struct sockaddr_in client1_addr;
    struct sockaddr_in client2_addr;
    bool ok = false;
    bool client2_refused = false;

    int ret = sock_create(AF_INET, SOCK_STREAM, 0, &listener);
    if (ret < 0 || !listener)
        goto out;
    ret = sock_create(AF_INET, SOCK_STREAM, 0, &client1);
    if (ret < 0 || !client1)
        goto out;
    ret = sock_create(AF_INET, SOCK_STREAM, 0, &client2);
    if (ret < 0 || !client2)
        goto out;

    make_inet_addr(&listener_addr, loopback_ip, server_port);
    make_inet_addr(&client1_addr, loopback_ip, client1_port);
    make_inet_addr(&client2_addr, loopback_ip, client2_port);

    ret = listener->ops->bind(listener, (const struct sockaddr *)&listener_addr,
                              sizeof(listener_addr));
    if (ret < 0)
        goto out;
    ret = listener->ops->listen(listener, 1);
    if (ret < 0)
        goto out;

    ret = client1->ops->bind(client1, (const struct sockaddr *)&client1_addr,
                             sizeof(client1_addr));
    if (ret < 0)
        goto out;
    ret = client2->ops->bind(client2, (const struct sockaddr *)&client2_addr,
                             sizeof(client2_addr));
    if (ret < 0)
        goto out;

    ret = client1->ops->connect(client1, (const struct sockaddr *)&listener_addr,
                                sizeof(listener_addr), MSG_DONTWAIT);
    if (ret != 0 && ret != -EINPROGRESS)
        goto out;
    if (ret == -EINPROGRESS) {
        int so_error = 0;
        if (!wait_inet_connect_so_error(client1, &so_error, 4000) || so_error != 0)
            goto out;
    }

    if (!wait_socket_event(listener, POLLIN, POLLIN, 4000))
        goto out;

    ret = client2->ops->connect(client2, (const struct sockaddr *)&listener_addr,
                                sizeof(listener_addr), MSG_DONTWAIT);
    if (ret == 0 || ret == -EINPROGRESS) {
        int so_error = 0;
        if (wait_inet_connect_so_error(client2, &so_error, 4000)) {
            if (so_error == ECONNREFUSED || so_error == ECONNRESET)
                client2_refused = true;
            else if (so_error != 0)
                goto out;
        }
    } else if (ret == -ECONNREFUSED || ret == -ECONNRESET) {
        client2_refused = true;
    } else {
        goto out;
    }

    ret = listener->ops->accept(listener, &server, 0);
    if (ret < 0 || !server)
        goto out;

    ret = listener->ops->accept(listener, &server2, MSG_DONTWAIT);
    if (ret == 0 && server2) {
        if (client2_refused)
            goto out;
    } else if (ret != -EAGAIN) {
        goto out;
    }

    ok = true;

out:
    close_socket_if_open(&server2);
    close_socket_if_open(&server);
    close_socket_if_open(&client2);
    close_socket_if_open(&client1);
    close_socket_if_open(&listener);
    return ok;
}

static void test_socket_msg_control_edge_semantics(void) {
    struct socket *tx = NULL;
    struct socket *rx = NULL;
    int txfd = -1;
    int rxfd = -1;
    struct user_map_ctx um = {0};
    bool mapped = false;

    int ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &tx);
    test_check(ret == 0, "sockmsg_edge create tx");
    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &rx);
    test_check(ret == 0, "sockmsg_edge create rx");
    if (!tx || !rx)
        goto out;

    ret = unix_socketpair_connect(tx, rx);
    test_check(ret == 0, "sockmsg_edge socketpair connect");
    if (ret < 0)
        goto out;

    txfd = socket_install_fd(&tx);
    rxfd = socket_install_fd(&rx);
    test_check(txfd >= 0, "sockmsg_edge install tx fd");
    test_check(rxfd >= 0, "sockmsg_edge install rx fd");
    if (txfd < 0 || rxfd < 0)
        goto out;

    ret = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "sockmsg_edge user map");
    if (ret < 0)
        goto out;
    mapped = true;

    struct test_socket_iovec *u_send_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x000);
    struct test_socket_iovec *u_recv_iov =
        (struct test_socket_iovec *)user_map_ptr(&um, 0x020);
    struct test_socket_msghdr *u_send_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x040);
    struct test_socket_msghdr *u_recv_msg =
        (struct test_socket_msghdr *)user_map_ptr(&um, 0x080);
    char *u_send_buf = (char *)user_map_ptr(&um, 0x0C0);
    char *u_recv_buf = (char *)user_map_ptr(&um, 0x100);
    struct test_socket_cmsghdr *u_ctrl =
        (struct test_socket_cmsghdr *)user_map_ptr(&um, 0x140);
    int32_t *u_rights = (int32_t *)user_map_ptr(&um, 0x180);
    test_check(u_send_iov && u_recv_iov && u_send_msg && u_recv_msg &&
                   u_send_buf && u_recv_buf && u_ctrl && u_rights,
               "sockmsg_edge user pointers");
    if (!u_send_iov || !u_recv_iov || !u_send_msg || !u_recv_msg ||
        !u_send_buf || !u_recv_buf || !u_ctrl || !u_rights)
        goto out;

    struct test_socket_iovec send_iov = {
        .iov_base = u_send_buf,
        .iov_len = 0,
    };
    struct test_socket_iovec recv_iov = {
        .iov_base = u_recv_buf,
        .iov_len = 8,
    };
    ret = copy_to_user(u_send_iov, &send_iov, sizeof(send_iov));
    test_check(ret == 0, "sockmsg_edge copy send iov zero");
    ret = copy_to_user(u_recv_iov, &recv_iov, sizeof(recv_iov));
    test_check(ret == 0, "sockmsg_edge copy recv iov");
    if (ret < 0)
        goto out;

    struct test_socket_cmsghdr ctrl_rights = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr) + sizeof(int32_t),
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = TEST_SCM_RIGHTS,
    };
    int32_t rights_fd = txfd;
    ret = copy_to_user(u_ctrl, &ctrl_rights, sizeof(ctrl_rights));
    test_check(ret == 0, "sockmsg_edge copy rights hdr");
    if (ret == 0) {
        ret = copy_to_user((uint8_t *)u_ctrl + sizeof(ctrl_rights), &rights_fd,
                           sizeof(rights_fd));
        test_check(ret == 0, "sockmsg_edge copy rights payload");
    }
    if (ret < 0)
        goto out;

    struct test_socket_msghdr send_msg = {
        .msg_iov = u_send_iov,
        .msg_iovlen = 1,
        .msg_control = u_ctrl,
        .msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len),
    };
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_edge copy send msg zero");
    if (ret < 0)
        goto out;

    int64_t ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 0, "sockmsg_edge sendmsg zero+rights");

    ret = copy_to_user(u_send_buf, "ZCTL", 4);
    test_check(ret == 0, "sockmsg_edge copy plain payload");
    if (ret < 0)
        goto out;
    ret64 = sys_sendto((uint64_t)txfd, (uint64_t)u_send_buf, 4, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_edge send plain after zero ctrl");

    struct test_socket_msghdr recv_msg = {
        .msg_iov = u_recv_iov,
        .msg_iovlen = 1,
        .msg_control = u_ctrl,
        .msg_controllen = test_socket_cmsg_align(ctrl_rights.cmsg_len),
    };
    ret = copy_to_user(u_recv_msg, &recv_msg, sizeof(recv_msg));
    test_check(ret == 0, "sockmsg_edge copy recv msg");
    if (ret < 0)
        goto out;

    ret64 = sys_recvmsg((uint64_t)rxfd, (uint64_t)u_recv_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_edge recv plain after zero ctrl");
    if (ret64 == 4) {
        char got[4] = {0};
        struct test_socket_msghdr got_msg = {0};
        ret = copy_from_user(got, u_recv_buf, sizeof(got));
        test_check(ret == 0, "sockmsg_edge read plain payload");
        ret = copy_from_user(&got_msg, u_recv_msg, sizeof(got_msg));
        test_check(ret == 0, "sockmsg_edge read recv msg");
        if (ret == 0) {
            test_check(memcmp(got, "ZCTL", 4) == 0,
                       "sockmsg_edge plain payload matches");
            test_check(got_msg.msg_controllen == 0,
                       "sockmsg_edge zero+ctrl does not deliver ancillary");
            test_check((got_msg.msg_flags & MSG_CTRUNC) == 0,
                       "sockmsg_edge zero+ctrl no ctrunc");
        }
    }

    struct test_socket_cmsghdr ctrl_other = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr),
        .cmsg_level = IPPROTO_UDP,
        .cmsg_type = 1,
    };
    send_iov.iov_len = 4;
    ret = copy_to_user(u_send_iov, &send_iov, sizeof(send_iov));
    test_check(ret == 0, "sockmsg_edge copy send iov data");
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_ctrl, &ctrl_other, sizeof(ctrl_other));
    test_check(ret == 0, "sockmsg_edge copy non-sol ctrl");
    if (ret < 0)
        goto out;
    ret = copy_to_user(u_send_buf, "LVL1", 4);
    test_check(ret == 0, "sockmsg_edge copy non-sol payload");
    if (ret < 0)
        goto out;
    send_msg.msg_control = u_ctrl;
    send_msg.msg_controllen = test_socket_cmsg_align(ctrl_other.cmsg_len);
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_edge copy send msg non-sol");
    if (ret < 0)
        goto out;
    ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == 4, "sockmsg_edge sendmsg non-sol control tolerated");
    if (ret64 == 4) {
        ret64 = sys_recvfrom((uint64_t)rxfd, (uint64_t)u_recv_buf, 4, 0, 0, 0);
        test_check(ret64 == 4, "sockmsg_edge recv non-sol payload");
    }
    if (ret64 == 4) {
        char got[4] = {0};
        ret = copy_from_user(got, u_recv_buf, sizeof(got));
        test_check(ret == 0, "sockmsg_edge read non-sol payload");
        if (ret == 0)
            test_check(memcmp(got, "LVL1", 4) == 0,
                       "sockmsg_edge non-sol payload matches");
    }

    struct test_socket_cmsghdr ctrl_bad = {
        .cmsg_len = sizeof(struct test_socket_cmsghdr),
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = 0x1234,
    };
    ret = copy_to_user(u_ctrl, &ctrl_bad, sizeof(ctrl_bad));
    test_check(ret == 0, "sockmsg_edge copy unknown sol ctrl");
    if (ret < 0)
        goto out;
    send_msg.msg_controllen = test_socket_cmsg_align(ctrl_bad.cmsg_len);
    ret = copy_to_user(u_send_msg, &send_msg, sizeof(send_msg));
    test_check(ret == 0, "sockmsg_edge copy send msg unknown sol");
    if (ret < 0)
        goto out;
    ret64 = sys_sendmsg((uint64_t)txfd, (uint64_t)u_send_msg, 0, 0, 0, 0);
    test_check(ret64 == -EOPNOTSUPP, "sockmsg_edge unknown sol ctrl eopnotsupp");

out:
    close_fd_if_open(&txfd);
    close_fd_if_open(&rxfd);
    close_socket_if_open(&tx);
    close_socket_if_open(&rx);
    if (mapped)
        user_map_end(&um);
}

static void test_socket_sockopt_semantics(void) {
    struct socket *us = NULL;
    struct socket *is = NULL;
    struct sockaddr_un uaddr;
    int ret;
    int one = 1;
    int zero = 0;
    int value = 0;
    int len = sizeof(value);

    ret = sock_create(AF_UNIX, SOCK_STREAM, 0, &us);
    test_check(ret == 0, "sockopt create unix");
    if (ret < 0 || !us)
        goto out;

    ret = us->ops->setsockopt(us, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    test_check(ret == 0, "sockopt unix set keepalive");
    len = sizeof(value);
    ret = us->ops->getsockopt(us, SOL_SOCKET, SO_KEEPALIVE, &value, &len);
    test_check(ret == 0, "sockopt unix get keepalive");
    if (ret == 0) {
        test_check(len == (int)sizeof(value), "sockopt unix keepalive len");
        test_check(value == 1, "sockopt unix keepalive value");
    }

    len = sizeof(value);
    ret = us->ops->getsockopt(us, SOL_SOCKET, SO_TYPE, &value, &len);
    test_check(ret == 0, "sockopt unix get type");
    if (ret == 0)
        test_check(value == SOCK_STREAM, "sockopt unix type stream");

    len = sizeof(value);
    ret = us->ops->getsockopt(us, SOL_SOCKET, SO_ACCEPTCONN, &value, &len);
    test_check(ret == 0, "sockopt unix get acceptconn pre-listen");
    if (ret == 0)
        test_check(value == 0, "sockopt unix acceptconn pre-listen zero");

    make_unix_addr(&uaddr, SOCKET_TEST_UNIX_SOCKOPT_PATH);
    ret = us->ops->bind(us, (const struct sockaddr *)&uaddr, sizeof(uaddr));
    test_check(ret == 0, "sockopt unix bind");
    if (ret == 0) {
        ret = us->ops->listen(us, 2);
        test_check(ret == 0, "sockopt unix listen");
    }
    if (ret == 0) {
        len = sizeof(value);
        ret = us->ops->getsockopt(us, SOL_SOCKET, SO_ACCEPTCONN, &value, &len);
        test_check(ret == 0, "sockopt unix get acceptconn listen");
        if (ret == 0)
            test_check(value == 1, "sockopt unix acceptconn listen one");
    }

    ret = us->ops->setsockopt(us, SOL_SOCKET, SO_SNDBUF, &zero, sizeof(zero));
    test_check(ret == -EINVAL, "sockopt unix set sndbuf zero einval");
    ret = us->ops->setsockopt(us, SOL_SOCKET, 0x7777, &one, sizeof(one));
    test_check(ret == -EOPNOTSUPP, "sockopt unix set unknown eopnotsupp");
    len = sizeof(value);
    ret = us->ops->getsockopt(us, SOL_SOCKET, 0x7777, &value, &len);
    test_check(ret == -EOPNOTSUPP, "sockopt unix get unknown eopnotsupp");

    ret = sock_create(AF_INET, SOCK_STREAM, 0, &is);
    test_check(ret == 0, "sockopt create inet");
    if (ret < 0 || !is)
        goto out;

    ret = is->ops->setsockopt(is, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    test_check(ret == 0, "sockopt inet set reuseaddr");
    len = sizeof(value);
    ret = is->ops->getsockopt(is, SOL_SOCKET, SO_REUSEADDR, &value, &len);
    test_check(ret == 0, "sockopt inet get reuseaddr");
    if (ret == 0)
        test_check(value == 1, "sockopt inet reuseaddr value");

    value = 8192;
    ret = is->ops->setsockopt(is, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value));
    test_check(ret == 0, "sockopt inet set sndbuf");
    value = 0;
    len = sizeof(value);
    ret = is->ops->getsockopt(is, SOL_SOCKET, SO_SNDBUF, &value, &len);
    test_check(ret == 0, "sockopt inet get sndbuf");
    if (ret == 0)
        test_check(value == 8192, "sockopt inet sndbuf value");

    value = 0;
    ret = is->ops->setsockopt(is, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));
    test_check(ret == -EINVAL, "sockopt inet set rcvbuf zero einval");

    len = sizeof(value);
    ret = is->ops->getsockopt(is, SOL_SOCKET, SO_TYPE, &value, &len);
    test_check(ret == 0, "sockopt inet get type");
    if (ret == 0)
        test_check(value == SOCK_STREAM, "sockopt inet type stream");

    len = sizeof(value);
    ret = is->ops->getsockopt(is, SOL_SOCKET, 0x7777, &value, &len);
    test_check(ret == -EOPNOTSUPP, "sockopt inet get unknown eopnotsupp");
    ret = is->ops->setsockopt(is, SOL_SOCKET, 0x7777, &one, sizeof(one));
    test_check(ret == -EOPNOTSUPP, "sockopt inet set unknown eopnotsupp");

out:
    close_socket_if_open(&is);
    close_socket_if_open(&us);
}

struct inet_attempt_ctx {
    uint32_t loopback_ip;
    uint16_t server_port;
    uint16_t client_port;
    uint16_t client2_port;
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

static int inet_tcp_backlog_attempt_worker(void *arg) {
    struct inet_attempt_ctx *ctx = (struct inet_attempt_ctx *)arg;
    ctx->ok = run_inet_tcp_backlog_attempt(ctx->loopback_ip, ctx->server_port,
                                           ctx->client_port,
                                           ctx->client2_port);
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
            .client2_port = 0,
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
            .client2_port = 0,
            .ok = false,
        };
        if (run_inet_attempt_with_timeout(inet_tcp_attempt_worker, &ctx, "intcp",
                                          8000)) {
            ok = true;
            break;
        }
    }

    if (ok) {
        test_check(true, "inet_tcp loopback");
        bool backlog_ok = false;
        for (size_t i = 0; i < sizeof(loopback_ips) / sizeof(loopback_ips[0]); i++) {
            struct inet_attempt_ctx ctx = {
                .loopback_ip = loopback_ips[i],
                .server_port = (uint16_t)(46000 + i),
                .client_port = (uint16_t)(47000 + i),
                .client2_port = (uint16_t)(48000 + i),
                .ok = false,
            };
            if (run_inet_attempt_with_timeout(inet_tcp_backlog_attempt_worker, &ctx,
                                              "intcpb", 8000)) {
                backlog_ok = true;
                break;
            }
        }
        test_check(backlog_ok, "inet_tcp backlog limit");
    } else {
        test_skip("inet_tcp (loopback tcp unavailable)");
    }
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
    test_unix_stream_msg_control_basic_semantics();
    test_unix_stream_msg_control_peek_merge_semantics();
    test_unix_stream_msg_control_merge_trunc_semantics();
    test_unix_stream_recvmmsg_control_semantics();
    test_unix_stream_recvmmsg_peek_control_semantics();
    test_unix_stream_msg_control_boundary_drop_semantics();
    test_socket_msg_control_edge_semantics();
    test_socket_sockopt_semantics();
    test_socket_syscall_abi_width_edges();
    test_socket_nonblock_syscall_semantics();
    test_unix_stream_connect_error_transitions();
    test_socket_fcntl_nonblock_semantics();
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
