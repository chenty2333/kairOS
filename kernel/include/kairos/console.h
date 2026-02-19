/**
 * kernel/include/kairos/console.h - Console device interface
 */

#ifndef _KAIROS_CONSOLE_H
#define _KAIROS_CONSOLE_H

#include <kairos/types.h>

struct vnode;
struct tty_struct;

/* VFS shim entry points (called by devfs) */
void console_attach_vnode(struct vnode *vn);
void console_poll_input(void);
ssize_t console_read(struct vnode *vn, void *buf, size_t len, off_t off, uint32_t flags);
ssize_t console_write(struct vnode *vn, const void *buf, size_t len, off_t off, uint32_t flags);
int console_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg);
int console_poll(struct vnode *vn, uint32_t events);

/* Access the console tty_struct (from console_tty.c) */
struct tty_struct *console_tty_get(void);

#endif
