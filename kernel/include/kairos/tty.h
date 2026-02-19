/**
 * kernel/include/kairos/tty.h - TTY abstraction layer
 */

#ifndef _KAIROS_TTY_H
#define _KAIROS_TTY_H

#include <kairos/ioctl.h>
#include <kairos/ringbuf.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>

#define TTY_INPUT_BUF_SIZE  1024
#define TTY_CANON_BUF_SIZE  256

#define TTY_HUPPED          (1UL << 0)
#define TTY_PTY_MASTER      (1UL << 1)

#define TTY_MAX_DRIVERS     4

struct tty_struct;
struct tty_driver;
struct tty_port;
struct vnode;
struct process;

struct tty_ldisc_ops {
    int     (*open)(struct tty_struct *tty);
    void    (*close)(struct tty_struct *tty);
    ssize_t (*read)(struct tty_struct *tty, uint8_t *buf, size_t count,
                    uint32_t flags);
    ssize_t (*write)(struct tty_struct *tty, const uint8_t *buf, size_t count,
                     uint32_t flags);
    void    (*receive_buf)(struct tty_struct *tty, const uint8_t *buf,
                           size_t count, bool *pushed, uint32_t *sig_mask);
    int     (*poll)(struct tty_struct *tty, uint32_t events);
    void    (*flush_buffer)(struct tty_struct *tty);
};

struct tty_ldisc {
    const struct tty_ldisc_ops *ops;
};

struct tty_driver_ops {
    int     (*open)(struct tty_struct *tty);
    void    (*close)(struct tty_struct *tty);
    ssize_t (*write)(struct tty_struct *tty, const uint8_t *buf, size_t count);
    void    (*put_char)(struct tty_struct *tty, uint8_t ch);
    void    (*set_termios)(struct tty_struct *tty, struct termios *old);
    void    (*hangup)(struct tty_struct *tty);
};

struct tty_driver {
    const char              *name;
    int                     major;
    int                     minor_start;
    int                     num;
    const struct tty_driver_ops *ops;
};

struct tty_port_ops {
    int     (*activate)(struct tty_port *port, struct tty_struct *tty);
    void    (*shutdown)(struct tty_port *port);
};

struct tty_port {
    const struct tty_port_ops *ops;
    struct tty_struct       *tty;
    int                     count;
    bool                    active;
};

struct tty_struct {
    int                 index;
    unsigned long       flags;
    struct tty_driver   *driver;
    struct tty_ldisc    ldisc;

    struct termios      termios;
    struct winsize      winsize;
    pid_t               session;
    pid_t               fg_pgrp;

    struct ringbuf      input_rb;
    uint8_t             input_buf[TTY_INPUT_BUF_SIZE];
    uint8_t             canon_buf[TTY_CANON_BUF_SIZE];
    uint32_t            canon_len;
    bool                eof_pending;

    struct tty_port     *port;
    struct tty_struct   *link;          /* PTY peer */
    spinlock_t          lock;
    struct vnode        *vnode;
    int                 count;
    void                *driver_data;
};

struct tty_struct *tty_alloc(struct tty_driver *driver, int index);
void tty_free(struct tty_struct *tty);
int tty_open(struct tty_struct *tty);
void tty_close(struct tty_struct *tty);
void tty_hangup(struct tty_struct *tty);

ssize_t tty_read(struct tty_struct *tty, uint8_t *buf, size_t count,
                 uint32_t flags);
ssize_t tty_write(struct tty_struct *tty, const uint8_t *buf, size_t count,
                  uint32_t flags);
int tty_ioctl(struct tty_struct *tty, uint64_t cmd, uint64_t arg);
int tty_poll(struct tty_struct *tty, uint32_t events);
void tty_detach_ctty(struct process *p);

void tty_receive_buf(struct tty_struct *tty, const uint8_t *buf, size_t count);
void tty_port_init(struct tty_port *port, const struct tty_port_ops *ops);
int tty_register_driver(struct tty_driver *driver);
void tty_unregister_driver(struct tty_driver *driver);

#endif
