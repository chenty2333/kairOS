/**
 * kernel/include/kairos/epoll.h - epoll definitions
 */

#ifndef _KAIROS_EPOLL_H
#define _KAIROS_EPOLL_H

#include <kairos/types.h>

/* epoll_ctl operations */
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

/* epoll event bits (aligned with poll bits for now) */
#define EPOLLIN 0x0001
#define EPOLLOUT 0x0004
#define EPOLLERR 0x0008
#define EPOLLHUP 0x0010

struct epoll_event {
    uint32_t events;
    uint64_t data;
};

#endif
