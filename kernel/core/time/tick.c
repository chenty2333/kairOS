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
static volatile uint64_t tick_irq_seq;
static volatile uint64_t tick_timekeeper_state;
static volatile uint64_t tick_timekeeper_heartbeat;
static volatile uint64_t tick_timekeeper_epoch_start_irq_seq;
static volatile uint64_t tick_timekeeper_all_online_irq_seq;
static volatile uint64_t tick_timekeeper_last_migrate_irq_seq;
static volatile uint64_t tick_timekeeper_last_warn_irq_seq;
extern void timerfd_tick(uint64_t now_ticks);

#define TICK_TK_TAG_SEQ_BITS 48
#define TICK_TK_TAG_SEQ_MASK ((1ULL << TICK_TK_TAG_SEQ_BITS) - 1ULL)

#define TICK_TK_STALL_IRQ_WINDOW \
    (((uint64_t)CONFIG_HZ / 20ULL) > 4ULL ? ((uint64_t)CONFIG_HZ / 20ULL) : 4ULL)
#define TICK_TK_LEASE_IRQ_WINDOW \
    (((uint64_t)CONFIG_HZ / 4ULL) > 12ULL ? ((uint64_t)CONFIG_HZ / 4ULL) : 12ULL)
#define TICK_TK_MIN_RESIDENCY_IRQ_WINDOW \
    (((uint64_t)CONFIG_HZ / 2ULL) > 20ULL ? ((uint64_t)CONFIG_HZ / 2ULL) : 20ULL)
#define TICK_TK_WARN_IRQ_WINDOW \
    ((((uint64_t)CONFIG_HZ * 5ULL) > 1ULL) ? ((uint64_t)CONFIG_HZ * 5ULL) : 1ULL)
#define TICK_TK_WARN_WARMUP_IRQ_WINDOW \
    ((((uint64_t)CONFIG_HZ * 60ULL) > 1ULL) ? ((uint64_t)CONFIG_HZ * 60ULL) : 1ULL)

static inline uint64_t tick_tk_state_pack(uint16_t epoch, int cpu) {
    return ((uint64_t)epoch << 48) | (uint64_t)(uint32_t)cpu;
}

static inline uint16_t tick_tk_state_epoch(uint64_t state) {
    return (uint16_t)(state >> 48);
}

static inline int tick_tk_state_cpu(uint64_t state) {
    return (int)(uint32_t)state;
}

static inline uint64_t tick_tk_tag_pack(uint16_t epoch, uint64_t irq_seq) {
    return ((uint64_t)epoch << TICK_TK_TAG_SEQ_BITS) |
           (irq_seq & TICK_TK_TAG_SEQ_MASK);
}

static inline uint16_t tick_tk_tag_epoch(uint64_t tag) {
    return (uint16_t)(tag >> TICK_TK_TAG_SEQ_BITS);
}

static inline uint64_t tick_tk_tag_irq_seq(uint64_t tag) {
    return tag & TICK_TK_TAG_SEQ_MASK;
}

static inline uint64_t tick_tk_tag_delta(uint64_t newer, uint64_t older) {
    return (newer - older) & TICK_TK_TAG_SEQ_MASK;
}

static inline uint64_t tick_tk_scaled_window(uint64_t base, int active_cpus) {
    if (active_cpus < 1)
        active_cpus = 1;
    return base * (uint64_t)active_cpus;
}

void tick_policy_init(int timekeeper_cpu) {
    uint64_t init_state = tick_tk_state_pack(0, timekeeper_cpu);
    __atomic_store_n(&system_ticks, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_irq_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_timekeeper_state, init_state, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_timekeeper_heartbeat, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_timekeeper_epoch_start_irq_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_timekeeper_all_online_irq_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_timekeeper_last_migrate_irq_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tick_timekeeper_last_warn_irq_seq, 0, __ATOMIC_RELAXED);
}

void tick_policy_on_timer_irq(const struct trap_core_event *ev) {
    uint64_t tick = 0;
    bool from_user = ev && ev->from_user;
    int cpu = arch_cpu_id();
    int active_cpus = sched_cpu_count();
    if (active_cpus < 1)
        active_cpus = 1;
    int total_cpus = arch_cpu_count();
    if (total_cpus < 1)
        total_cpus = 1;
    uint64_t irq_seq = __atomic_add_fetch(&tick_irq_seq, 1, __ATOMIC_RELAXED);
    if (active_cpus >= total_cpus) {
        uint64_t expected = 0;
        __atomic_compare_exchange_n(&tick_timekeeper_all_online_irq_seq, &expected,
                                    irq_seq, false, __ATOMIC_RELAXED,
                                    __ATOMIC_RELAXED);
    }
    uint64_t all_online_irq_seq = __atomic_load_n(
        &tick_timekeeper_all_online_irq_seq, __ATOMIC_RELAXED);
    uint64_t tk_state =
        __atomic_load_n(&tick_timekeeper_state, __ATOMIC_ACQUIRE);
    uint16_t tk_epoch = tick_tk_state_epoch(tk_state);
    int tk_cpu = tick_tk_state_cpu(tk_state);
    bool is_timekeeper = (cpu == tk_cpu);

    if (is_timekeeper) {
        tick = __atomic_add_fetch(&system_ticks, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&tick_timekeeper_heartbeat,
                         tick_tk_tag_pack(tk_epoch, irq_seq), __ATOMIC_RELEASE);
        console_poll_input();
    } else {
        // WARN: Timer IRQ routing can drift; migrate timekeeper if owner stalls.
        uint64_t heartbeat =
            __atomic_load_n(&tick_timekeeper_heartbeat, __ATOMIC_ACQUIRE);
        bool heartbeat_valid = (tick_tk_tag_epoch(heartbeat) == tk_epoch);
        uint64_t last_tk_irq = heartbeat_valid ? tick_tk_tag_irq_seq(heartbeat) : 0;
        bool startup_never_seen =
            (tk_epoch == 0) && (!heartbeat_valid || (last_tk_irq == 0));
        uint64_t since_last_tk_irq =
            heartbeat_valid ? tick_tk_tag_delta(irq_seq, last_tk_irq) : 0;

        uint64_t stall_irq_window =
            tick_tk_scaled_window(TICK_TK_STALL_IRQ_WINDOW, active_cpus);
        uint64_t lease_irq_window =
            tick_tk_scaled_window(TICK_TK_LEASE_IRQ_WINDOW, active_cpus);
        bool stalled = heartbeat_valid && (since_last_tk_irq > stall_irq_window);
        bool lease_expired =
            heartbeat_valid && (since_last_tk_irq > lease_irq_window);

        uint64_t epoch_start_tag = __atomic_load_n(
            &tick_timekeeper_epoch_start_irq_seq, __ATOMIC_ACQUIRE);
        bool epoch_start_valid = (tick_tk_tag_epoch(epoch_start_tag) == tk_epoch);
        uint64_t epoch_start_irq = epoch_start_valid
                                       ? tick_tk_tag_irq_seq(epoch_start_tag)
                                       : last_tk_irq;
        uint64_t min_residency_irq_window =
            tick_tk_scaled_window(TICK_TK_MIN_RESIDENCY_IRQ_WINDOW, active_cpus);
        bool residency_ok = !epoch_start_valid ||
                            (tick_tk_tag_delta(irq_seq, epoch_start_irq) >
                             min_residency_irq_window);

        if (startup_never_seen || (stalled && lease_expired && residency_ok)) {
            uint16_t next_epoch = (uint16_t)(tk_epoch + 1);
            uint64_t next_state = tick_tk_state_pack(next_epoch, cpu);
            bool migrated = __atomic_compare_exchange_n(
                &tick_timekeeper_state, &tk_state, next_state, false,
                __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
            if (migrated) {
                uint64_t epoch_tag = tick_tk_tag_pack(next_epoch, irq_seq);
                __atomic_store_n(&tick_timekeeper_epoch_start_irq_seq, epoch_tag,
                                 __ATOMIC_RELEASE);
                __atomic_store_n(&tick_timekeeper_heartbeat, epoch_tag,
                                 __ATOMIC_RELEASE);
                tick = __atomic_add_fetch(&system_ticks, 1, __ATOMIC_RELAXED);
                console_poll_input();
                if (stalled) {
                    uint64_t warmup_irq_window =
                        tick_tk_scaled_window(TICK_TK_WARN_WARMUP_IRQ_WINDOW,
                                              active_cpus);
                    if (all_online_irq_seq != 0 &&
                        ((irq_seq - all_online_irq_seq) > warmup_irq_window)) {
                        uint64_t warn_irq_window = tick_tk_scaled_window(
                            TICK_TK_WARN_IRQ_WINDOW, active_cpus);
                        uint64_t last_migrate_irq_seq = __atomic_load_n(
                            &tick_timekeeper_last_migrate_irq_seq,
                            __ATOMIC_RELAXED);
                        __atomic_store_n(&tick_timekeeper_last_migrate_irq_seq,
                                         irq_seq, __ATOMIC_RELAXED);
                        bool frequent_migrate =
                            (last_migrate_irq_seq != 0) &&
                            ((irq_seq - last_migrate_irq_seq) <=
                             warn_irq_window);
                        if (frequent_migrate) {
                            uint64_t last_warn_irq_seq = __atomic_load_n(
                                &tick_timekeeper_last_warn_irq_seq,
                                __ATOMIC_RELAXED);
                            bool warn_due = (last_warn_irq_seq == 0) ||
                                            ((irq_seq - last_warn_irq_seq) >
                                             warn_irq_window);
                            if (warn_due &&
                                __atomic_compare_exchange_n(
                                    &tick_timekeeper_last_warn_irq_seq,
                                    &last_warn_irq_seq, irq_seq, false,
                                    __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
                                pr_warn("tick: migrate timekeeper cpu%d->cpu%d\n",
                                        tk_cpu, cpu);
                            }
                        }
                    }
                }
            }
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
