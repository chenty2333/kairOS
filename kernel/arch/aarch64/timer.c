/**
 * kernel/arch/aarch64/timer.c - AArch64 timer
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/printk.h>
#include <kairos/types.h>

static uint64_t timer_freq;

static inline uint64_t cntfrq(void) {
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}

static inline uint64_t cntpct(void) {
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntpct_el0" : "=r"(val));
    return val;
}

void arch_timer_init(uint64_t hz) {
    if (!hz)
        hz = CONFIG_HZ;
    timer_freq = cntfrq();
    uint64_t interval = timer_freq / hz;
    __asm__ __volatile__("msr cntp_tval_el0, %0" :: "r"(interval));
    __asm__ __volatile__("msr cntp_ctl_el0, %0" :: "r"((uint64_t)1));
    pr_info("Timer: %lu Hz\n", (unsigned long)hz);
}

uint64_t arch_timer_ticks(void) { return cntpct(); }
uint64_t arch_timer_freq(void) { return timer_freq; }
uint64_t arch_timer_ticks_to_ns(uint64_t t) { return (t * 1000000000ULL) / timer_freq; }
uint64_t arch_timer_ns_to_ticks(uint64_t ns) { return (ns * timer_freq) / 1000000000ULL; }
void arch_timer_set_next(uint64_t t) { __asm__ __volatile__("msr cntp_tval_el0, %0" :: "r"(t)); }
void arch_timer_ack(void) {}
uint64_t arch_timer_get_ticks(void) { return cntpct(); }
