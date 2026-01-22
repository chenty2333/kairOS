/**
 * kairos/types.h - Basic type definitions
 */

#ifndef _KAIROS_TYPES_H
#define _KAIROS_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Process and user IDs */
typedef int32_t  pid_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;

/* File system types */
typedef int64_t  off_t;
typedef int64_t  ssize_t;
typedef uint32_t mode_t;
typedef uint32_t dev_t;
typedef uint64_t ino_t;
typedef uint64_t blkcnt_t;
typedef uint32_t blksize_t;
typedef uint64_t nlink_t;

/* Time types */
typedef int64_t  time_t;
typedef uint64_t useconds_t;
typedef int64_t  suseconds_t;

/* Memory types */
typedef uint64_t paddr_t;   /* Physical address */
typedef uint64_t vaddr_t;   /* Virtual address */
typedef uint64_t pgoff_t;   /* Page offset */

/* Error codes (negative values) */
#define EPERM           1   /* Operation not permitted */
#define ENOENT          2   /* No such file or directory */
#define ESRCH           3   /* No such process */
#define EINTR           4   /* Interrupted system call */
#define EIO             5   /* I/O error */
#define ENXIO           6   /* No such device or address */
#define E2BIG           7   /* Argument list too long */
#define ENOEXEC         8   /* Exec format error */
#define EBADF           9   /* Bad file number */
#define ECHILD          10  /* No child processes */
#define EAGAIN          11  /* Try again */
#define ENOMEM          12  /* Out of memory */
#define EACCES          13  /* Permission denied */
#define EFAULT          14  /* Bad address */
#define EBUSY           16  /* Device or resource busy */
#define EEXIST          17  /* File exists */
#define EXDEV           18  /* Cross-device link */
#define ENODEV          19  /* No such device */
#define ENOTDIR         20  /* Not a directory */
#define EISDIR          21  /* Is a directory */
#define EINVAL          22  /* Invalid argument */
#define ENFILE          23  /* File table overflow */
#define EMFILE          24  /* Too many open files */
#define ENOTTY          25  /* Not a typewriter */
#define EFBIG           27  /* File too large */
#define ENOSPC          28  /* No space left on device */
#define ESPIPE          29  /* Illegal seek */
#define EROFS           30  /* Read-only file system */
#define EMLINK          31  /* Too many links */
#define EPIPE           32  /* Broken pipe */
#define ENOSYS          38  /* Function not implemented */
#define ENOTEMPTY       39  /* Directory not empty */

/* Utility macros */
#ifndef NULL
#define NULL            ((void *)0)
#endif
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))
#define ALIGN_UP(x, a)  (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x,a) ((x) & ~((a) - 1))
#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#define MAX(a, b)       ((a) > (b) ? (a) : (b))

/* Compiler hints */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#define __unused        __attribute__((unused))
#define __packed        __attribute__((packed))
#define __aligned(x)    __attribute__((aligned(x)))
#define noreturn        _Noreturn

/* Container of */
#define container_of(ptr, type, member) ({                      \
    const typeof(((type *)0)->member) *__mptr = (ptr);          \
    (type *)((char *)__mptr - offsetof(type, member)); })

#endif /* _KAIROS_TYPES_H */
