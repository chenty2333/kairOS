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
extern void timerfd_tick(uint64_t now_ticks);

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
        timerfd_tick(tick);
    }

    sched_tick();
    if (!sched_need_resched())
        return;

    if (from_user) {
        schedule();
        return;
    }

    if (proc_current() == arch_get_percpu()->idle_proc) {
        schedule();
        return;
    }

    /*
     * Defer kernel-thread preemption to explicit reschedule points.
     * Calling schedule() directly from a kernel-mode timer IRQ can switch
     * context while unwinding trap state and corrupt return control flow.
     */
}

uint64_t tick_policy_get_ticks(void) {
    return __atomic_load_n(&system_ticks, __ATOMIC_RELAXED);
}
