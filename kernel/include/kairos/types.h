/**
 * kernel/include/kairos/types.h - Basic type definitions
 */

#ifndef _KAIROS_TYPES_H
#define _KAIROS_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int32_t pid_t;
typedef uint32_t uid_t, gid_t, mode_t, dev_t, blksize_t;
typedef int64_t off_t, ssize_t, time_t, suseconds_t;
typedef uint64_t ino_t, blkcnt_t, nlink_t, useconds_t, paddr_t, vaddr_t,
    pgoff_t;
struct timeval {
    time_t tv_sec;
    suseconds_t tv_usec;
};

struct timespec {
    time_t tv_sec;
    int64_t tv_nsec;
};

struct rlimit {
    uint64_t rlim_cur;
    uint64_t rlim_max;
};

#define RLIMIT_STACK 3
#define RLIMIT_NOFILE 7
#define RLIM_NLIMITS 16
#define RLIM_INFINITY (~0ULL)

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

/* Error codes */
#define EPERM 1
#define ENOENT 2
#define ESRCH 3
#define EINTR 4
#define EIO 5
#define ENXIO 6
#define E2BIG 7
#define ENOEXEC 8
#define EBADF 9
#define ECHILD 10
#define EAGAIN 11
#define ENOMEM 12
#define EACCES 13
#define EFAULT 14
#define EBUSY 16
#define EEXIST 17
#define EXDEV 18
#define ENODEV 19
#define ENOTDIR 20
#define EISDIR 21
#define EINVAL 22
#define ENFILE 23
#define EMFILE 24
#define ENOTTY 25
#define EFBIG 27
#define ENOSPC 28
#define ESPIPE 29
#define EROFS 30
#define EMLINK 31
#define EPIPE 32
#define ENOSYS 38
#define ENOTEMPTY 39
#define ELOOP 40
#define ERANGE 34
#define ENAMETOOLONG 36
#define EOPNOTSUPP 95
#define ENOTSUP EOPNOTSUPP
#define ETIMEDOUT 110
#define ESTALE 116

#undef NULL
#define NULL ((void *)0)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((a) - 1))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __unused __attribute__((unused))
#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))
#define noreturn _Noreturn

#define container_of(ptr, type, member)                                        \
    ({                                                                         \
        const typeof(((type *)0)->member) *__mptr = (ptr);                     \
        (type *)((char *)__mptr - offsetof(type, member));                     \
    })

#endif
