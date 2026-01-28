/**
 * kernel/arch/riscv64/timer.c - RISC-V 64 Timer Implementation
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/console.h>
#include <kairos/pollwait.h>
#include <kairos/printk.h>
#include <kairos/sched.h>
#include <kairos/types.h>

#define SBI_EXT_TIME 0x54494D45
#define TIMER_FREQ 10000000 /* 10 MHz */

static uint64_t timer_freq = TIMER_FREQ;
static uint64_t ticks_per_int;
extern volatile uint64_t system_ticks;

void arch_timer_init(uint64_t hz) {
    if (!hz)
        hz = CONFIG_HZ;
    ticks_per_int = timer_freq / hz;
    sbi_call(SBI_EXT_TIME, 0, rdtime() + ticks_per_int, 0, 0);
    pr_info("Timer: %lu Hz, interval %lu ticks\n", (unsigned long)timer_freq,
            (unsigned long)ticks_per_int);
}

uint64_t arch_timer_ticks(void) {
    return rdtime();
}
uint64_t arch_timer_freq(void) {
    return timer_freq;
}
uint64_t arch_timer_ticks_to_ns(uint64_t t) {
    return (t * 1000000000UL) / timer_freq;
}
uint64_t arch_timer_ns_to_ticks(uint64_t ns) {
    return (ns * timer_freq) / 1000000000UL;
}
void arch_timer_set_next(uint64_t t) {
    sbi_call(SBI_EXT_TIME, 0, rdtime() + t, 0, 0);
}
void arch_timer_ack(void) {}

void timer_interrupt_handler(void) {
    /* Use a single CPU as the timekeeper to avoid SMP races. */
    uint64_t tick = 0;
    if (arch_cpu_id() == 0) {
        tick = __atomic_add_fetch(&system_ticks, 1, __ATOMIC_RELAXED);
    }
    sbi_call(SBI_EXT_TIME, 0, rdtime() + ticks_per_int, 0, 0);
    console_poll_input();
    if (tick && (tick % CONFIG_HZ == 0))
        pr_debug("tick: %lu sec\n", tick / CONFIG_HZ);
    if (tick)
        poll_sleep_tick(tick);
    sched_tick();
    struct trap_frame *tf = arch_get_percpu()->current_tf;
    if (tf && !(tf->sstatus & SSTATUS_SPP) && sched_need_resched())
        schedule();
}

uint64_t arch_timer_get_ticks(void) {
    return __atomic_load_n(&system_ticks, __ATOMIC_RELAXED);
}
