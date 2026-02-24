/**
 * kernel/include/kairos/socket.h - Socket abstraction layer
 */

#ifndef _KAIROS_SOCKET_H
#define _KAIROS_SOCKET_H

#include <kairos/types.h>
#include <kairos/sync.h>
#include <kairos/pollwait.h>

struct vnode;

/* Address families */
#define AF_UNSPEC 0
#define AF_UNIX   1
#define AF_LOCAL  AF_UNIX
#define AF_INET   2

/* Socket types */
#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOCK_RAW    3

/* Socket type flags */
#define SOCK_NONBLOCK 04000
#define SOCK_CLOEXEC  02000000

/* Protocols */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Shutdown flags */
#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2

/* Message flags */
#define MSG_DONTWAIT 0x40
#define MSG_NOSIGNAL 0x4000
#define MSG_CTRUNC   0x8
#define MSG_CMSG_CLOEXEC 0x40000000

/* Socket options levels */
#define SOL_SOCKET 1

/* Socket options */
#define SO_REUSEADDR 2
#define SO_ERROR     4
#define SO_KEEPALIVE 9
#define SO_SNDBUF    7
#define SO_RCVBUF    8

/* Socket states */
#define SS_UNCONNECTED 0
#define SS_BOUND       1
#define SS_LISTENING   2
#define SS_CONNECTED   3
#define SS_CONNECTING  4

struct sockaddr {
    uint16_t sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t sin_zero[8];
};

#define UNIX_PATH_MAX 108

struct sockaddr_un {
    uint16_t sun_family;
    char sun_path[UNIX_PATH_MAX];
};

struct sockaddr_storage {
    uint16_t ss_family;
    char __ss_padding[126];
};

#define SOCKET_MAX_RIGHTS 16

struct socket_ucred {
    int32_t pid;
    uint32_t uid;
    uint32_t gid;
};

struct file;
struct socket_control {
    bool has_creds;
    struct socket_ucred creds;
    size_t rights_count;
    struct file *rights[SOCKET_MAX_RIGHTS];
};

struct socket;

/* Protocol operations - each address family implements these */
struct proto_ops {
    int (*bind)(struct socket *sock, const struct sockaddr *addr, int addrlen);
    int (*connect)(struct socket *sock, const struct sockaddr *addr,
                   int addrlen, int flags);
    int (*listen)(struct socket *sock, int backlog);
    int (*accept)(struct socket *sock, struct socket **newsock, int flags);
    ssize_t (*sendto)(struct socket *sock, const void *buf, size_t len,
                      int flags, const struct sockaddr *dest, int addrlen);
    ssize_t (*recvfrom)(struct socket *sock, void *buf, size_t len, int flags,
                        struct sockaddr *src, int *addrlen);
    ssize_t (*sendmsg)(struct socket *sock, const void *buf, size_t len,
                       int flags, const struct sockaddr *dest, int addrlen,
                       const struct socket_control *control);
    ssize_t (*recvmsg)(struct socket *sock, void *buf, size_t len, int flags,
                       struct sockaddr *src, int *addrlen,
                       struct socket_control *control);
    int (*shutdown)(struct socket *sock, int how);
    int (*close)(struct socket *sock);
    int (*poll)(struct socket *sock, uint32_t events);
    int (*getsockname)(struct socket *sock, struct sockaddr *addr,
                       int *addrlen);
    int (*getpeername)(struct socket *sock, struct sockaddr *addr,
                       int *addrlen);
    int (*setsockopt)(struct socket *sock, int level, int optname,
                      const void *optval, int optlen);
    int (*getsockopt)(struct socket *sock, int level, int optname,
                      void *optval, int *optlen);
};

/* Core socket structure */
struct socket {
    int domain;
    int type;
    int protocol;
    int state;
    const struct proto_ops *ops;
    struct vnode *vnode;
    void *proto_data;
    struct mutex lock;
    struct poll_wait_head pollers;
};

/* Socket layer API */
int sock_create(int domain, int type, int protocol, struct socket **out);
void sock_destroy(struct socket *sock);
struct socket *sock_from_vnode(struct vnode *vn);

/* Protocol family registration */
int sock_register_family(int domain, const struct proto_ops *stream_ops,
                         const struct proto_ops *dgram_ops);

/* Protocol family init */
void af_unix_init(void);
void af_inet_init(void);
void lwip_net_init(void);
int unix_socketpair_connect(struct socket *sock0, struct socket *sock1);

/* Feed received ethernet frame into lwIP */
void lwip_netif_input(const void *data, size_t len);

#endif /* _KAIROS_SOCKET_H */
