/**
 * kernel/core/time/time.c - Core time helpers
 */

#include <kairos/arch.h>
#include <kairos/time.h>

uint64_t time_now_ns(void) {
    return arch_timer_ticks_to_ns(arch_timer_ticks());
}

time_t time_now_sec(void) {
    return (time_t)(time_now_ns() / 1000000000ULL);
}
