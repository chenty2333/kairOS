/**
 * kernel/drivers/tty/console_tty.c - Console TTY driver
 *
 * Thin wrapper around arch_early_putchar/getchar for the console TTY.
 * This is the hardware backend; all line discipline logic lives in n_tty.c.
 */

#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/tty.h>
#include <kairos/tty_driver.h>
#include <kairos/tty_ldisc.h>

/* ── Driver ops ──────────────────────────────────────────────────── */

static int console_tty_open(struct tty_struct *tty) {
    (void)tty;
    return 0;  /* UART already initialized at boot */
}

static void console_tty_close(struct tty_struct *tty) {
    (void)tty;  /* Physical console stays active */
}

static ssize_t console_tty_write(struct tty_struct *tty, const uint8_t *buf,
                                  size_t count) {
    (void)tty;
    for (size_t i = 0; i < count; i++)
        arch_early_putchar((char)buf[i]);
    return (ssize_t)count;
}

static void console_tty_put_char(struct tty_struct *tty, uint8_t ch) {
    (void)tty;
    arch_early_putchar((char)ch);
}

static void console_tty_set_termios(struct tty_struct *tty,
                                     struct termios *old) {
    (void)tty;
    (void)old;  /* No hardware config needed for SBI/UART console */
}

static void console_tty_hangup(struct tty_struct *tty) {
    (void)tty;  /* Physical console cannot hang up */
}

static const struct tty_driver_ops console_tty_ops = {
    .open        = console_tty_open,
    .close       = console_tty_close,
    .write       = console_tty_write,
    .put_char    = console_tty_put_char,
    .set_termios = console_tty_set_termios,
    .hangup      = console_tty_hangup,
};

/* ── Static instances ────────────────────────────────────────────── */

static struct tty_struct *console_tty_ptrs[1];
static struct tty_port console_port;
static struct vc_data console_vc;

struct tty_driver console_tty_driver = {
    .name        = "console",
    .major       = 5,
    .minor_start = 1,
    .num         = 1,
    .ops         = &console_tty_ops,
    .ttys        = console_tty_ptrs,
};

/* The single console tty_struct, accessible to console.c */
static struct tty_struct *console_tty;

struct tty_struct *console_tty_get(void) {
    return console_tty;
}

/* ── Init ────────────────────────────────────────────────────────── */

int console_tty_driver_init(void) {
    tty_port_init(&console_port, NULL);
    memset(&console_vc, 0, sizeof(console_vc));
    console_vc.vc_num = 0;

    console_tty = tty_alloc(&console_tty_driver, 0);
    if (!console_tty) {
        pr_err("console_tty: failed to allocate tty_struct\n");
        return -1;
    }

    console_tty->port = &console_port;
    console_tty->vc = &console_vc;
    console_port.tty = console_tty;
    console_vc.tty = console_tty;
    console_tty_ptrs[0] = console_tty;

    tty_register_driver(&console_tty_driver);
    tty_open(console_tty);

    pr_info("console_tty: initialized\n");
    return 0;
}
