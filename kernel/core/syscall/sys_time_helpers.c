/**
 * kernel/core/syscall/sys_time_helpers.c - Time syscall helpers (internal)
 */

#include <kairos/types.h>
#include <kairos/uaccess.h>

#include "sys_time_helpers.h"

#define NS_PER_SEC 1000000000ULL

int sys_copy_timespec(uint64_t ptr, struct timespec *out, bool allow_null) {
    if (!out) {
        return -EINVAL;
    }
    if (!ptr) {
        return allow_null ? 0 : -EFAULT;
    }
    if (copy_from_user(out, (const void *)ptr, sizeof(*out)) < 0) {
        return -EFAULT;
    }
    if (out->tv_sec < 0 || out->tv_nsec < 0 ||
        out->tv_nsec >= (int64_t)NS_PER_SEC) {
        return -EINVAL;
    }
    return 1;
}
