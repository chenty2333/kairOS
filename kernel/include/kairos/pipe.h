/**
 * kernel/include/kairos/pipe.h - Pipe helpers
 */

#ifndef _KAIROS_PIPE_H
#define _KAIROS_PIPE_H

#include <kairos/pollwait.h>
#include <kairos/types.h>

struct file;
struct vnode;

int pipe_create(struct file **read_pipe, struct file **write_pipe);
void pipe_close_end(struct file *file);
ssize_t pipe_read_file(struct file *file, void *buf, size_t len);
ssize_t pipe_write_file(struct file *file, const void *buf, size_t len);
int pipe_poll_file(struct file *file, uint32_t events);
void pipe_poll_register_file(struct file *file, struct poll_waiter *waiter,
                             uint32_t events);
void pipe_poll_watch_vnode(struct vnode *vn, struct poll_watch *watch,
                           uint32_t events);
void pipe_poll_wake_vnode(struct vnode *vn, uint32_t events);

#endif
