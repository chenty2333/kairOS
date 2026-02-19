/**
 * kernel/include/kairos/tty_driver.h - TTY driver registration
 */

#ifndef _KAIROS_TTY_DRIVER_H
#define _KAIROS_TTY_DRIVER_H

struct tty_driver;

extern struct tty_driver console_tty_driver;
int console_tty_driver_init(void);

extern struct tty_driver pty_master_driver;
extern struct tty_driver pty_slave_driver;
int pty_driver_init(void);

#endif
