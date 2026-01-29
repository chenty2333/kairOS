/**
 * kernel/include/kairos/ioctl.h - IOCTL definitions
 */

#ifndef _KAIROS_IOCTL_H
#define _KAIROS_IOCTL_H

#include <kairos/types.h>

/* termios types (minimal) */
typedef unsigned int tcflag_t;
typedef unsigned char cc_t;
typedef unsigned int speed_t;

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_line;
    cc_t c_cc[32];
    speed_t c_ispeed;
    speed_t c_ospeed;
};

struct winsize {
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
};

/* Minimal termios flags (Linux-compatible values) */
#define IGNCR  0000200
#define INLCR  0000100
#define ICRNL  0000400

#define OPOST  0000001
#define ONLCR  0000004

#define ISIG   0000001
#define ICANON 0000002
#define ECHO   0000010
#define ECHOE  0000020
#define ECHOK  0000040

/* termios c_cc indexes (subset) */
#define VINTR  0
#define VQUIT  1
#define VERASE 2
#define VKILL  3
#define VEOF   4
#define VTIME  5
#define VMIN   6
#define VSUSP  10

#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404
#define TIOCSCTTY 0x540E
#define TIOCGPGRP 0x540F
#define TIOCSPGRP 0x5410
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define FIONBIO 0x5421
#define FIONREAD 0x541B
#define BLKGETSIZE 0x1260
#define BLKROGET 0x125e
#define BLKSSZGET 0x1268
#define BLKGETSIZE64 0x80081272

#endif
