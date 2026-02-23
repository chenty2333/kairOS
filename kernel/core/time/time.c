/**
 * kernel/core/time/time.c - Core time helpers
 */

#include <kairos/arch.h>
#include <kairos/time.h>

/*
 * CLOCK_MONOTONIC is derived directly from hardware ticks.
 * CLOCK_REALTIME is represented as MONOTONIC + adjustable offset.
 */
static int64_t realtime_offset_ns = 0;

uint64_t time_now_ns(void) {
    return arch_timer_ticks_to_ns(arch_timer_ticks());
}

time_t time_now_sec(void) {
    return (time_t)(time_now_ns() / 1000000000ULL);
}

uint64_t time_realtime_ns(void) {
    uint64_t mono = time_now_ns();
    int64_t off = __atomic_load_n(&realtime_offset_ns, __ATOMIC_RELAXED);
    if (off >= 0)
        return mono + (uint64_t)off;

    uint64_t neg = (uint64_t)(-off);
    return (mono > neg) ? (mono - neg) : 0;
}

int time_set_realtime_ns(uint64_t realtime_ns) {
    uint64_t mono = time_now_ns();
    int64_t off = 0;
    const uint64_t max_off = ~(1ULL << 63);

    if (realtime_ns >= mono) {
        uint64_t delta = realtime_ns - mono;
        if (delta > max_off)
            return -ERANGE;
        off = (int64_t)delta;
    } else {
        uint64_t delta = mono - realtime_ns;
        if (delta > max_off)
            return -ERANGE;
        off = -(int64_t)delta;
    }

    __atomic_store_n(&realtime_offset_ns, off, __ATOMIC_RELAXED);
    return 0;
}
