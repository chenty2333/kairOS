/**
 * kernel/include/kairos/futex.h - Minimal futex interface
 */

#ifndef _KAIROS_FUTEX_H
#define _KAIROS_FUTEX_H

#include <kairos/types.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_BITSET_MATCH_ANY 0xffffffffU

#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)

void futex_init(void);
int futex_wait(uint64_t uaddr, uint32_t val, const struct timespec *timeout);
int futex_wake(uint64_t uaddr, int nr_wake);

#endif
