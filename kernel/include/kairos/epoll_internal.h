/**
 * kernel/include/kairos/epoll_internal.h - Internal epoll helpers
 */

#ifndef _KAIROS_EPOLL_INTERNAL_H
#define _KAIROS_EPOLL_INTERNAL_H

#include <kairos/epoll.h>
#include <kairos/types.h>

struct file;

struct epoll_snapshot_item {
    int fd;
    uint32_t events;
    uint64_t data;
};

int epoll_create_file(struct file **out);
int epoll_ctl_fd(int epfd, int op, int fd, const struct epoll_event *ev);
ssize_t epoll_snapshot(int epfd, struct epoll_snapshot_item *items, size_t max);
int epoll_wait_events(int epfd, struct epoll_event *events, size_t maxevents,
                      int timeout_ms);

#endif
