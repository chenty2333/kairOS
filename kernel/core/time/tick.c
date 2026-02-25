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
static volatile uint64_t tick_irq_seq;
static volatile uint64_t tick_timekeeper_last_irq_seq;
extern void timerfd_tick(uint64_t now_ticks);

#define TICK_TK_STALL_IRQ_WINDOW \
    (((uint64_t)CONFIG_HZ / 20ULL) > 4ULL ? ((uint64_t)CONFIG_HZ / 20ULL) : 4ULL)

void tick_policy_init(int timekeeper_cpu) {
    __atomic_store_n(&system_ticks, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_irq_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_timekeeper_last_irq_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_timekeeper_cpu, timekeeper_cpu, __ATOMIC_RELAXED);
}

void tick_policy_on_timer_irq(const struct trap_core_event *ev) {
    uint64_t tick = 0;
    bool from_user = ev && ev->from_user;
    int cpu = arch_cpu_id();
    uint64_t irq_seq = __atomic_add_fetch(&tick_irq_seq, 1, __ATOMIC_RELAXED);
    int tk_cpu = __atomic_load_n(&tick_timekeeper_cpu, __ATOMIC_RELAXED);
    bool is_timekeeper = (cpu == tk_cpu);

    if (is_timekeeper) {
        tick = __atomic_add_fetch(&system_ticks, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&tick_timekeeper_last_irq_seq, irq_seq, __ATOMIC_RELAXED);
        console_poll_input();
    } else {
        // WARN: Timer IRQ routing can drift; migrate timekeeper if BSP stalls.
        uint64_t last_tk_irq =
            __atomic_load_n(&tick_timekeeper_last_irq_seq, __ATOMIC_RELAXED);
        bool never_seen = (last_tk_irq == 0);
        bool stalled = !never_seen &&
                       ((irq_seq - last_tk_irq) > TICK_TK_STALL_IRQ_WINDOW);
        if (never_seen || stalled) {
            __atomic_store_n(&tick_timekeeper_cpu, cpu, __ATOMIC_RELAXED);
            __atomic_store_n(&tick_timekeeper_last_irq_seq, irq_seq,
                             __ATOMIC_RELAXED);
            tick = __atomic_add_fetch(&system_ticks, 1, __ATOMIC_RELAXED);
            console_poll_input();
            if (!never_seen)
                pr_warn("tick: migrate timekeeper cpu%d->cpu%d\n", tk_cpu, cpu);
        }
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
