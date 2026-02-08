/**
 * kernel/core/time/tick.c - Core timer tick policy
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/pollwait.h>
#include <kairos/printk.h>
#include <kairos/sched.h>
#include <kairos/tick.h>

static volatile uint64_t system_ticks;

void tick_policy_init(void) {
    __atomic_store_n(&system_ticks, 0, __ATOMIC_RELAXED);
}

void tick_policy_on_timer_irq(struct trap_frame *tf, bool from_user) {
    uint64_t tick = 0;

    if (arch_cpu_id() == 0) {
        tick = __atomic_add_fetch(&system_ticks, 1, __ATOMIC_RELAXED);
    }

    if (tick && (tick % CONFIG_HZ == 0)) {
        pr_debug("tick: %lu sec\n", tick / CONFIG_HZ);
    }
    if (tick) {
        poll_sleep_tick(tick);
    }

    sched_tick();
    if (tf && from_user && sched_need_resched()) {
        schedule();
    }
}

uint64_t tick_policy_get_ticks(void) {
    return __atomic_load_n(&system_ticks, __ATOMIC_RELAXED);
}
