/**
 * kernel/include/kairos/tty_ldisc.h - TTY line discipline interface
 */

#ifndef _KAIROS_TTY_LDISC_H
#define _KAIROS_TTY_LDISC_H

struct tty_struct;
struct tty_ldisc_ops;

/* Line discipline numbers */
#define N_TTY   0

/* N_TTY line discipline */
extern const struct tty_ldisc_ops n_tty_ops;
void n_tty_init(struct tty_struct *tty);

#endif
