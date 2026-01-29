/**
 * kernel/include/kairos/time.h - Kernel time helpers
 */

#ifndef _KAIROS_TIME_H
#define _KAIROS_TIME_H

#include <kairos/types.h>

uint64_t time_now_ns(void);
time_t time_now_sec(void);

#endif
