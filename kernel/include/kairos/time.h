/**
 * kernel/include/kairos/time.h - Kernel time helpers
 */

#ifndef _KAIROS_TIME_H
#define _KAIROS_TIME_H

#include <kairos/types.h>

uint64_t time_now_ns(void);
time_t time_now_sec(void);
uint64_t time_realtime_ns(void);
uint64_t time_realtime_generation(void);
int time_set_realtime_ns(uint64_t realtime_ns);

#endif
