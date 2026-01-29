/**
 * kernel/core/syscall/sys_time_helpers.h - Time syscall helpers (internal)
 */

#ifndef _KAIROS_SYS_TIME_HELPERS_H
#define _KAIROS_SYS_TIME_HELPERS_H

#include <kairos/types.h>

int sys_copy_timespec(uint64_t ptr, struct timespec *out, bool allow_null);

#endif
