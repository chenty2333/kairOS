/**
 * kernel/core/time/tick.c - Core timer tick policy
 */

#include <kairos/arch.h>
#include <kairos/console.h>
#include <kairos/config.h>
#include <kairos/pollwait.h>
#include <kairos/preempt.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/trap_core.h>
#include <kairos/tick.h>

static volatile uint64_t system_ticks;
static int tick_timekeeper_cpu;

void tick_policy_init(int timekeeper_cpu) {
    __atomic_store_n(&system_ticks, 0, __ATOMIC_RELAXED);
    tick_timekeeper_cpu = timekeeper_cpu;
}

void tick_policy_on_timer_irq(const struct trap_core_event *ev) {
    uint64_t tick = 0;
    bool from_user = ev && ev->from_user;
    bool is_timekeeper = (arch_cpu_id() == tick_timekeeper_cpu);

    if (is_timekeeper) {
        tick = __atomic_add_fetch(&system_ticks, 1, __ATOMIC_RELAXED);
        console_poll_input();
    }

    if (tick && (tick % CONFIG_HZ == 0)) {
        pr_debug("tick: %lu sec\n", tick / CONFIG_HZ);
    }
    if (tick) {
        poll_sleep_tick(tick);
    }

    sched_tick();
    if (sched_need_resched()) {
        if (from_user) {
            schedule();
        } else if (proc_current() == arch_get_percpu()->idle_proc) {
            schedule();
        } else if (!in_atomic()) {
            /* Kernel preemption: safe to reschedule when preempt_count == 0 */
            schedule();
        }
    }
}

uint64_t tick_policy_get_ticks(void) {
    return __atomic_load_n(&system_ticks, __ATOMIC_RELAXED);
}
