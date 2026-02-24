/**
 * kernel/drivers/tty/console_tty.c - Console TTY driver
 */

#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/tty.h>
#include <kairos/tty_driver.h>
#include <kairos/tty_ldisc.h>

static int console_tty_open(struct tty_struct *tty) {
    (void)tty;
    return 0;
}

static void console_tty_close(struct tty_struct *tty) {
    (void)tty;
}

static ssize_t console_tty_write(struct tty_struct *tty, const uint8_t *buf,
                                 size_t count, uint32_t flags) {
    (void)tty;
    (void)flags;
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
    (void)old;
}

static void console_tty_hangup(struct tty_struct *tty) {
    (void)tty;
}

static const struct tty_driver_ops console_tty_ops = {
    .open        = console_tty_open,
    .close       = console_tty_close,
    .write       = console_tty_write,
    .put_char    = console_tty_put_char,
    .set_termios = console_tty_set_termios,
    .hangup      = console_tty_hangup,
};

static struct tty_port console_port;

struct tty_driver console_tty_driver = {
    .name        = "console",
    .major       = 5,
    .minor_start = 1,
    .num         = 1,
    .ops         = &console_tty_ops,
};

static struct tty_struct *console_tty;

struct tty_struct *console_tty_get(void) {
    return console_tty;
}

int console_tty_driver_init(void) {
    tty_port_init(&console_port, NULL);

    console_tty = tty_alloc(&console_tty_driver, 0);
    if (!console_tty) {
        pr_err("console_tty: failed to allocate tty_struct\n");
        return -1;
    }

    console_tty->port = &console_port;
    console_port.tty = console_tty;

    tty_register_driver(&console_tty_driver);
    tty_open(console_tty);

    pr_info("console_tty: initialized\n");
    return 0;
}
