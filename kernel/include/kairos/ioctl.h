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
#define ECHOCTL 0001000

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
/* Additional TTY ioctls */
#define TIOCNOTTY  0x5422
#define TIOCGSID   0x5429
#define TCFLSH     0x540B
#define TCSBRK     0x5409
#define TCSBRKP    0x5425

/* Block device ioctls */
#define BLKGETSIZE 0x1260
#define BLKROGET 0x125e
#define BLKSSZGET 0x1268
#define BLKGETSIZE64 0x80081272

/* Network ioctls */
#define SIOCGIFCONF    0x8912
#define SIOCGIFFLAGS   0x8913
#define SIOCSIFFLAGS   0x8914
#define SIOCGIFADDR    0x8915
#define SIOCSIFADDR    0x8916
#define SIOCGIFNETMASK 0x891b
#define SIOCSIFNETMASK 0x891c
#define SIOCGIFHWADDR  0x8927
#define SIOCGIFMTU     0x8921
#define SIOCSIFMTU     0x8922
#define SIOCADDRT      0x890B
#define SIOCDELRT      0x890C

/* Network ABI structures */
#define IFNAMSIZ 16

struct sockaddr_kairos {
    uint16_t sa_family;
    char sa_data[14];
};

struct ifreq {
    char ifr_name[IFNAMSIZ];
    union {
        struct sockaddr_kairos ifr_addr;
        struct sockaddr_kairos ifr_netmask;
        struct sockaddr_kairos ifr_hwaddr;
        short ifr_flags;
        int ifr_mtu;
    };
};

struct ifconf {
    int ifc_len;
    union {
        char *ifc_buf;
        struct ifreq *ifc_req;
    };
};

#endif
