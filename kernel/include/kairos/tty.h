/**
 * kernel/include/kairos/tty.h - TTY abstraction layer
 *
 * Core data structures for the three-layer TTY architecture:
 *   tty_struct  → per-terminal instance (termios, buffers, ldisc)
 *   tty_driver  → backend driver interface (console, pty)
 *   tty_port    → hardware abstraction (minimal for console)
 *   vc_data     → virtual console stub (reserved for VT switching)
 */

#ifndef _KAIROS_TTY_H
#define _KAIROS_TTY_H

#include <kairos/ioctl.h>
#include <kairos/ringbuf.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>

/* Buffer sizes */
#define TTY_INPUT_BUF_SIZE  1024
#define TTY_CANON_BUF_SIZE  256

/* TTY flags */
#define TTY_HUPPED          (1UL << 0)
#define TTY_PTY_MASTER      (1UL << 1)
#define TTY_EXCLUSIVE       (1UL << 2)

/* Max registered drivers */
#define TTY_MAX_DRIVERS     4

struct tty_struct;
struct tty_driver;
struct tty_port;
struct vc_data;
struct vnode;

/* ── Line discipline ops ─────────────────────────────────────────── */

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

/* ── Driver ops ──────────────────────────────────────────────────── */

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
    int                     num;        /* number of devices */
    const struct tty_driver_ops *ops;
    struct tty_struct       **ttys;     /* per-minor tty pointers */
};

/* ── Port (hardware abstraction) ─────────────────────────────────── */

struct tty_port_ops {
    int     (*activate)(struct tty_port *port, struct tty_struct *tty);
    void    (*shutdown)(struct tty_port *port);
    int     (*carrier_raised)(struct tty_port *port);
    void    (*dtr_rts)(struct tty_port *port, int on);
};

struct tty_port {
    const struct tty_port_ops *ops;
    struct tty_struct       *tty;       /* back pointer */
    int                     count;
    bool                    active;
};

/* ── Virtual console stub ────────────────────────────────────────── */

struct vc_data {
    int                     vc_num;
    struct tty_struct       *tty;       /* back pointer */
    /* Future: cursor position, screen buffer, etc. */
};

/* ── Per-terminal instance ───────────────────────────────────────── */

struct tty_struct {
    int                 index;          /* minor / device index */
    unsigned long       flags;          /* TTY_HUPPED, TTY_PTY_MASTER, etc. */
    struct tty_driver   *driver;

    /* Line discipline */
    struct tty_ldisc    ldisc;

    /* Terminal state */
    struct termios      termios;
    struct winsize      winsize;
    pid_t               session;        /* session leader pid */
    pid_t               fg_pgrp;        /* foreground process group */

    /* Input buffers */
    struct ringbuf      input_rb;
    char                input_buf[TTY_INPUT_BUF_SIZE];
    char                canon_buf[TTY_CANON_BUF_SIZE];
    uint32_t            canon_len;
    bool                eof_pending;

    /* Hardware / VC */
    struct tty_port     *port;
    struct vc_data      *vc;            /* NULL for pty */

    /* PTY peer */
    struct tty_struct   *link;

    /* Synchronization */
    spinlock_t          lock;

    /* Poll / wait */
    struct vnode        *vnode;

    /* Reference count */
    int                 count;

    /* Driver private data */
    void                *driver_data;
};

/* ── API ─────────────────────────────────────────────────────────── */

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

void tty_receive_buf(struct tty_struct *tty, const uint8_t *buf, size_t count);
void tty_wakeup_readers(struct tty_struct *tty);

void tty_port_init(struct tty_port *port, const struct tty_port_ops *ops);

int tty_register_driver(struct tty_driver *driver);
void tty_unregister_driver(struct tty_driver *driver);

#endif
