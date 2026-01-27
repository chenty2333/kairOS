/**
 * kernel/include/kairos/poll.h - Poll definitions
 */

#ifndef _KAIROS_POLL_H
#define _KAIROS_POLL_H

#include <kairos/types.h>

#define POLLIN 0x0001
#define POLLPRI 0x0002
#define POLLOUT 0x0004
#define POLLERR 0x0008
#define POLLHUP 0x0010
#define POLLNVAL 0x0020

struct pollfd {
    int fd;
    short events;
    short revents;
};

#endif
