/**
 * kernel/core/sched/sched.c - Scalable CFS Implementation with Per-CPU Locks
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/rbtree.h>
#include <kairos/sched.h>
#include <kairos/string.h>

/* CFS Scheduler Tunables */
#define SCHED_LATENCY_NS 6000000UL
#define SCHED_MIN_GRANULARITY_NS 1000000UL
#define SCHED_WAKEUP_GRANULARITY_NS 2000000UL

static inline uint64_t sched_clock_ns(void) {
    return arch_timer_ticks_to_ns(arch_timer_ticks());
}

const int sched_nice_to_weight[40] = {
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
    9548,  7620,  6100,  4904,  3906,  3121,  2501,  1991,  1586,  1277,
    1024,  820,   655,   526,   423,   335,   272,   215,   172,   137,
    110,   87,    70,    56,    45,    36,    29,    23,    18,    15,
};

struct percpu_data cpu_data[CONFIG_MAX_CPUS];
static int nr_cpus_online = 1;

static inline int sched_nr_cpus(void) {
    return __atomic_load_n(&nr_cpus_online, __ATOMIC_ACQUIRE);
}

static bool sched_steal_enabled = false;

static inline void sched_stat_inc(uint64_t *counter) {
    __atomic_fetch_add(counter, 1, __ATOMIC_RELAXED);
}

static inline uint64_t sched_stat_load(const uint64_t *counter) {
    return __atomic_load_n(counter, __ATOMIC_RELAXED);
}

static inline bool sched_steal_is_enabled(void) {
    return __atomic_load_n(&sched_steal_enabled, __ATOMIC_ACQUIRE);
}

static const char *sched_trace_event_name(uint16_t type) {
    switch (type) {
    case SCHED_TRACE_ENQUEUE: return "enqueue";
    case SCHED_TRACE_DEQUEUE: return "dequeue";
    case SCHED_TRACE_PICK: return "pick";
    case SCHED_TRACE_SWITCH: return "switch";
    case SCHED_TRACE_IDLE: return "idle";
    case SCHED_TRACE_STEAL: return "steal";
    case SCHED_TRACE_SLEEP: return "sleep";
    case SCHED_TRACE_WAKEUP: return "wakeup";
    case SCHED_TRACE_TRAP: return "trap";
    case SCHED_TRACE_MIGRATE: return "migrate";
    default: return "unknown";
    }
}

static const char *sched_proc_state_name(int state) {
    switch (state) {
    case PROC_UNUSED: return "unused";
    case PROC_EMBRYO: return "embryo";
    case PROC_RUNNABLE: return "runnable";
    case PROC_RUNNING: return "running";
    case PROC_SLEEPING: return "sleeping";
    case PROC_ZOMBIE: return "zombie";
    case PROC_REAPING: return "reaping";
    default: return "?";
    }
}

static const char *sched_se_state_name(uint32_t state) {
    switch (state) {
    case SE_STATE_BLOCKED: return "blocked";
    case SE_STATE_RUNNABLE: return "runnable";
    case SE_STATE_QUEUED: return "queued";
    case SE_STATE_RUNNING: return "running";
    default: return "?";
    }
}

void sched_trace_event(enum sched_trace_event_type type,
                       const struct process *p,
                       uint64_t arg0, uint64_t arg1) {
    int cpu = arch_cpu_id();
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        cpu = 0;
    struct percpu_data *cd = &cpu_data[cpu];
    uint32_t seq = __atomic_fetch_add(&cd->trace_head, 1, __ATOMIC_RELAXED) + 1;
    uint32_t idx = (seq - 1) & SCHED_TRACE_PER_CPU_MASK;
    struct sched_trace_entry *ent = &cd->trace_buf[idx];

    ent->ticks = arch_timer_get_ticks();
    ent->cpu = (uint32_t)cpu;
    ent->type = (uint16_t)type;
    ent->pid = p ? p->pid : -1;
    ent->proc_state = p ? p->state : -1;
    ent->se_cpu = p ? p->se.cpu : -1;
    ent->se_state =
        p ? __atomic_load_n(&p->se.run_state, __ATOMIC_ACQUIRE) : 0;
    ent->arg0 = arg0;
    ent->arg1 = arg1;
    ent->seq = seq;
}

void sched_trace_dump_recent(int max_events) {
    if (max_events <= 0)
        return;

    int online = sched_nr_cpus();
    int total = SCHED_TRACE_PER_CPU * online;
    if (max_events > total)
        max_events = total;

    /* Per-CPU cursors for merge-sort output */
    int pos[CONFIG_MAX_CPUS];
    int count[CONFIG_MAX_CPUS];
    for (int c = 0; c < online; c++) {
        uint32_t head = cpu_data[c].trace_head;
        int n = (head < SCHED_TRACE_PER_CPU) ? (int)head : SCHED_TRACE_PER_CPU;
        count[c] = n;
        /* Start from oldest entry */
        pos[c] = (n < SCHED_TRACE_PER_CPU) ? 0 : (int)(head & SCHED_TRACE_PER_CPU_MASK);
    }

    pr_err("sched trace: dumping up to %d events (per-cpu, %d cpus)\n",
           max_events, online);

    int emitted = 0;
    while (emitted < max_events) {
        /* Find CPU with oldest (smallest ticks) entry */
        int best = -1;
        uint64_t best_ticks = ~0ULL;
        for (int c = 0; c < online; c++) {
            if (count[c] == 0)
                continue;
            struct sched_trace_entry *ent = &cpu_data[c].trace_buf[pos[c]];
            if (ent->ticks < best_ticks) {
                best_ticks = ent->ticks;
                best = c;
            }
        }
        if (best < 0)
            break;

        struct sched_trace_entry *ent = &cpu_data[best].trace_buf[pos[best]];
        pr_err("  t=%llu cpu=%u ev=%s pid=%d p=%s se=%s se_cpu=%d a0=%p a1=%p\n",
               (unsigned long long)ent->ticks, ent->cpu,
               sched_trace_event_name(ent->type), ent->pid,
               sched_proc_state_name(ent->proc_state),
               sched_se_state_name(ent->se_state), ent->se_cpu,
               (void *)ent->arg0, (void *)ent->arg1);

        pos[best] = (pos[best] + 1) & SCHED_TRACE_PER_CPU_MASK;
        count[best]--;
        emitted++;
    }
}

#if CONFIG_DEBUG
static inline int sched_violation_cpu(const struct process *p) {
    if (p && p->se.cpu >= 0 && p->se.cpu < CONFIG_MAX_CPUS)
        return p->se.cpu;
    int cpu = arch_cpu_id();
    if (cpu >= 0 && cpu < CONFIG_MAX_CPUS)
        return cpu;
    return 0;
}
#endif

static inline uint32_t se_state_load(const struct sched_entity *se) {
    return __atomic_load_n(&se->run_state, __ATOMIC_ACQUIRE);
}

static inline bool se_try_transition(struct sched_entity *se, uint32_t from,
                                     uint32_t to) {
    uint32_t expected = from;
    return __atomic_compare_exchange_n(&se->run_state, &expected, to, false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline void se_set_state(struct sched_entity *se, uint32_t state) {
    __atomic_store_n(&se->run_state, state, __ATOMIC_RELEASE);
}

static inline void se_mark_queued(struct sched_entity *se, int cpu_id) {
    se->cpu = cpu_id;
    se_set_state(se, SE_STATE_QUEUED);
}

static inline void se_mark_running(struct sched_entity *se) {
    se_set_state(se, SE_STATE_RUNNING);
}

static inline void se_mark_runnable(struct sched_entity *se) {
    se_set_state(se, SE_STATE_RUNNABLE);
}

static inline void se_mark_blocked(struct sched_entity *se) {
    se_set_state(se, SE_STATE_BLOCKED);
}

#if CONFIG_DEBUG
static void sched_validate_entity(struct process *p, const char *where) {
    struct sched_entity *se = &p->se;
    uint32_t state = se_state_load(se);
    (void)state;
    (void)where;
    /* With on_rq/on_cpu derived from run_state, the old cross-checks are
     * tautological.  Keep the hook for future invariant checks. */
}
#else
static inline void sched_validate_entity(struct process *p
                                         __attribute__((unused)),
                                         const char *where
                                         __attribute__((unused))) {}
#endif

static inline int __weight(int nice) {
    int idx = (nice < NICE_MIN) ? 0 : (nice > NICE_MAX) ? 39 : nice - NICE_MIN;
    return sched_nice_to_weight[idx];
}

static uint64_t calc_delta_fair(uint64_t delta, int weight) {
    return (delta * NICE_0_WEIGHT) / (weight > 0 ? weight : NICE_0_WEIGHT);
}

static void update_min_vruntime(struct cfs_rq *rq) {
    uint64_t v = rq->min_vruntime;
    if (rq->curr_se && (!rq->idle || rq->curr_se != &rq->idle->se) &&
        rq->curr_se->vruntime > v)
        v = rq->curr_se->vruntime;
    struct rb_node *left = rb_first(&rq->tasks_timeline);
    if (left) {
        struct sched_entity *se = rb_entry(left, struct sched_entity, sched_node);
        if (se->vruntime < v) v = se->vruntime;
    }
    if (v > rq->min_vruntime) rq->min_vruntime = v;
}

static void __enqueue_entity(struct cfs_rq *rq, struct sched_entity *se) {
    struct rb_node **link = &rq->tasks_timeline.rb_node, *parent = NULL;
    while (*link) {
        parent = *link;
        if (se->vruntime < rb_entry(parent, struct sched_entity, sched_node)->vruntime)
            link = &parent->rb_left;
        else
            link = &parent->rb_right;
    }
    rb_link_node(&se->sched_node, parent, link);
    rb_insert_color(&se->sched_node, &rq->tasks_timeline);
}

static uint64_t update_curr(struct cfs_rq *rq) {
    struct sched_entity *curr_se = rq->curr_se;
    if (!curr_se) return 0;

    uint64_t now = sched_clock_ns();
    uint64_t delta = (now > curr_se->last_run_time) ? now - curr_se->last_run_time : 0;
    if (delta == 0) return 0;

    curr_se->vruntime += calc_delta_fair(delta, __weight(curr_se->nice));
    curr_se->last_run_time = now;
    update_min_vruntime(rq);
    return delta;
}

static void place_entity(struct cfs_rq *rq, struct sched_entity *se, bool initial) {
    uint64_t v = rq->min_vruntime;
    if (initial) v += calc_delta_fair(SCHED_LATENCY_NS, __weight(se->nice));
    if (se->vruntime < v) se->vruntime = v;
}

void sched_init(void) {
    /* Initialize local CPU. Secondary CPUs call sched_init_cpu. */
    sched_init_cpu(arch_cpu_id());
    sched_cpu_online(arch_cpu_id());
}

void sched_init_cpu(int cpu) {
    struct percpu_data *d = &cpu_data[cpu];
    memset(d, 0, sizeof(*d));
    d->cpu_id = cpu;
    d->runqueue.tasks_timeline = RB_ROOT;
    spin_init(&d->runqueue.lock);
    spin_init(&d->ipi_call_lock);
    d->prev_task = NULL;
}

void sched_post_switch_cleanup(void) {
    struct percpu_data *cpu = arch_get_percpu();
    if (cpu->prev_task) {
        struct process *prev = cpu->prev_task;
        /* prev was RUNNING; now it has finished its context switch.
         * If it went to sleep/exit, schedule() already set BLOCKED.
         * If it was re-enqueued, schedule() already set QUEUED.
         * Nothing to do here for state — the authoritative run_state
         * was already updated before the context switch. */
        cpu->prev_task = NULL;
        /* Zombie finished context switch — notify waiting parent */
        if (prev->state == PROC_ZOMBIE && prev->parent) {
            wait_queue_wakeup_all(&prev->parent->exit_wait);
        }
    }
}

void sched_enqueue(struct process *p) {
    if (!p)
        return;
    if (!se_try_transition(&p->se, SE_STATE_BLOCKED, SE_STATE_RUNNABLE))
        return;

    /* Find target CPU - currently simple: stay on current or preferred */
    int cpu = (p->se.cpu >= 0 && p->se.cpu < sched_nr_cpus()) ? p->se.cpu : arch_cpu_id();
    struct cfs_rq *rq = &cpu_data[cpu].runqueue;

    bool state = arch_irq_save();
    spin_lock(&rq->lock);

    if (se_is_on_rq(&p->se)) {
        spin_unlock(&rq->lock);
        if (!se_try_transition(&p->se, SE_STATE_RUNNABLE, SE_STATE_QUEUED))
            se_try_transition(&p->se, SE_STATE_RUNNABLE, SE_STATE_BLOCKED);
        arch_irq_restore(state);
        return;
    }

    place_entity(rq, &p->se, p->se.vruntime == 0);
    int prev_cpu = p->se.cpu;
    __enqueue_entity(rq, &p->se);
    se_mark_queued(&p->se, cpu);
    rq->nr_running++;
    update_min_vruntime(rq);
    sched_stat_inc(&cpu_data[cpu].stats.enqueue_count);
    sched_trace_event(SCHED_TRACE_ENQUEUE, p, (uint64_t)cpu, p->se.vruntime);
    if (cpu != prev_cpu && prev_cpu >= 0)
        sched_trace_event(SCHED_TRACE_MIGRATE, p, (uint64_t)prev_cpu, (uint64_t)cpu);
    sched_validate_entity(p, "sched_enqueue");

    /* Snapshot preemption decision while still holding the lock */
    struct sched_entity *curr_se = rq->curr_se;
    bool need_resched = false;
    if (curr_se && curr_se != &p->se) {
        if (p->se.vruntime + SCHED_WAKEUP_GRANULARITY_NS < curr_se->vruntime) {
            need_resched = true;
        }
    }

    spin_unlock(&rq->lock);

    if (need_resched) {
        cpu_data[cpu].resched_needed = true;
    }

    if (cpu != arch_cpu_id())
        arch_send_ipi(cpu, IPI_RESCHEDULE);

    arch_irq_restore(state);
}

void sched_dequeue(struct process *p) {
    if (!p) return;

    int cpu = p->se.cpu;
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        return;
    struct cfs_rq *rq = &cpu_data[cpu].runqueue;
    bool state = arch_irq_save();
    spin_lock(&rq->lock);

    /* Re-check under lock: steal can change state/cpu concurrently */
    if (!se_is_on_rq(&p->se) || p->se.cpu != cpu) {
        spin_unlock(&rq->lock);
        arch_irq_restore(state);
        return;
    }

    rb_erase(&p->se.sched_node, &rq->tasks_timeline);
    se_mark_blocked(&p->se);
    rq->nr_running--;
    update_min_vruntime(rq);
    sched_stat_inc(&cpu_data[cpu].stats.dequeue_count);
    sched_trace_event(SCHED_TRACE_DEQUEUE, p, (uint64_t)cpu, 0);
    sched_validate_entity(p, "sched_dequeue");

    spin_unlock(&rq->lock);
    arch_irq_restore(state);
}

/**
 * sched_steal_task - Try to steal from other CPUs
 * Uses strict locking order (ascending CPU ID) to prevent deadlocks.
 */
static struct process *sched_steal_task(int self_id) {
    struct sched_cpu_stats *self_stats = &cpu_data[self_id].stats;
    int online = sched_nr_cpus();
    for (int i = 0; i < online; i++) {
        if (i == self_id) continue;
        sched_stat_inc(&self_stats->steal_attempt_count);

        struct cfs_rq *remote_rq = &cpu_data[i].runqueue;

        /* Attempt to lock remote queue without deadlocking */
        if (!spin_trylock(&remote_rq->lock)) continue;

        struct process *p = NULL;
        if (remote_rq->nr_running > 0) {
            for (struct rb_node *node = rb_first(&remote_rq->tasks_timeline);
                 node; node = rb_next(node)) {
                struct sched_entity *se =
                    rb_entry(node, struct sched_entity, sched_node);
                struct process *cand = container_of(se, struct process, se);
                if (remote_rq->curr_se == se)
                    continue;
                if (cand->state != PROC_RUNNABLE)
                    continue;
                if (se_state_load(se) != SE_STATE_QUEUED)
                    continue;
                if (se_is_on_cpu(se))
                    continue;

                rb_erase(&se->sched_node, &remote_rq->tasks_timeline);
                se_mark_runnable(se);
                se->cpu = self_id;
                remote_rq->nr_running--;
                update_min_vruntime(remote_rq);
                sched_validate_entity(cand, "sched_steal_task");
                p = cand;
                break;
            }
        }
        spin_unlock(&remote_rq->lock);
        if (p) {
            sched_stat_inc(&self_stats->steal_success_count);
            sched_trace_event(SCHED_TRACE_STEAL, p, (uint64_t)self_id,
                              (uint64_t)i);
            return p;
        }
    }
    return NULL;
}

void schedule(void) {
    struct percpu_data *cpu = arch_get_percpu();
    struct sched_cpu_stats *stats = &cpu->stats;
    struct process *prev = proc_current(), *next;
    struct cfs_rq *rq = &cpu->runqueue;
    bool state = arch_irq_save();

    spin_lock(&rq->lock);
    cpu->resched_needed = false;

    if (prev && prev != cpu->idle_proc) {
        (void)update_curr(rq);
        /*
         * Temporarily mark prev as RUNNING so that se_mark_runnable /
         * se_mark_queued below perform a clean state transition.
         * This is invisible to other CPUs because we hold rq->lock.
         */
        se_mark_running(&prev->se);

        /*
         * A wakeup can race with sleep/yield just before schedule(), leaving
         * current as RUNNABLE. Treat it like RUNNING and enqueue instead of
         * misclassifying it as blocked.
         */
        if (prev->state == PROC_RUNNING || prev->state == PROC_RUNNABLE) {
            prev->state = PROC_RUNNABLE;
            se_mark_runnable(&prev->se);
            __enqueue_entity(rq, &prev->se);
            se_mark_queued(&prev->se, cpu->cpu_id);
            rq->nr_running++;
            sched_stat_inc(&stats->enqueue_count);
        } else {
            if (se_is_on_rq(&prev->se)) {
                rb_erase(&prev->se.sched_node, &rq->tasks_timeline);
                rq->nr_running--;
                sched_stat_inc(&stats->dequeue_count);
            }
            se_mark_blocked(&prev->se);
        }
        sched_validate_entity(prev, "schedule-prev");
    }

    struct rb_node *left = rb_first(&rq->tasks_timeline);
    if (left) {
        struct sched_entity *se = rb_entry(left, struct sched_entity, sched_node);
        next = container_of(se, struct process, se);
        rb_erase(&se->sched_node, &rq->tasks_timeline);
        se_mark_runnable(se);           /* removed from rq */
        rq->nr_running--;
        sched_stat_inc(&stats->pick_count);
        sched_trace_event(SCHED_TRACE_PICK, next, (uint64_t)cpu->cpu_id,
                          (uint64_t)rq->nr_running);
    } else {
        /* Local empty - attempt stealing without holding local lock to simplify */
        bool steal_allowed = sched_steal_is_enabled() && sched_nr_cpus() > 1;
        if (steal_allowed) {
            spin_unlock(&rq->lock);
            next = sched_steal_task(cpu->cpu_id);
            spin_lock(&rq->lock);
        } else {
            next = NULL;
        }

        /* Re-check local queue: tasks may have been enqueued while lock was dropped */
        if (!next) {
            struct rb_node *recheck = rb_first(&rq->tasks_timeline);
            if (recheck) {
                struct sched_entity *se = rb_entry(recheck, struct sched_entity, sched_node);
                next = container_of(se, struct process, se);
                rb_erase(&se->sched_node, &rq->tasks_timeline);
                se_mark_runnable(se);           /* removed from rq */
                rq->nr_running--;
                sched_stat_inc(&stats->pick_count);
                sched_trace_event(SCHED_TRACE_PICK, next,
                                  (uint64_t)cpu->cpu_id,
                                  (uint64_t)rq->nr_running);
            } else {
                next = cpu->idle_proc;
            }
        }
    }

    if (next == cpu->idle_proc) {
        sched_stat_inc(&stats->idle_pick_count);
        sched_trace_event(SCHED_TRACE_IDLE, next, (uint64_t)cpu->cpu_id,
                          (uint64_t)rq->nr_running);
    }

    if (prev && next == prev && prev->state == PROC_ZOMBIE && prev != cpu->idle_proc) {
        pr_err("SCHED: CPU %d trying to re-schedule ZOMBIE PID %d. idle_proc PID %d\n",
               cpu->cpu_id, prev->pid, cpu->idle_proc ? cpu->idle_proc->pid : -1);
        panic("SCHED: Zombie Rescheduling");
    }

    if (next != prev) {
        sched_stat_inc(&stats->switch_count);
        sched_trace_event(SCHED_TRACE_SWITCH, next,
                          (uint64_t)(prev ? prev->pid : -1),
                          (uint64_t)(next ? next->pid : -1));
        next->se.last_run_time = sched_clock_ns();
        rq->curr_se = &next->se;
        next->state = PROC_RUNNING;
        se_mark_running(&next->se);
        __atomic_store_n(&cpu->curr_proc, next, __ATOMIC_RELEASE);
        proc_set_current(next);
        sched_validate_entity(next, "schedule-next");

        if (next->mm) {
            arch_mmu_switch(next->mm->pgdir);
        } else {
            arch_mmu_switch(arch_mmu_get_kernel_pgdir());
        }

        if (next->context) {
            uint64_t kstack = arch_context_kernel_stack(next->context);
            if (kstack)
                arch_tss_set_rsp0(kstack);
        }

        if (next->context) arch_context_set_cpu(next->context, cpu->cpu_id);

        cpu->prev_task = prev;

        spin_unlock(&rq->lock);
        if (prev && prev->context) arch_context_switch(prev->context, next->context);

        sched_post_switch_cleanup();

        arch_irq_restore(state);
    } else {
        next->state = PROC_RUNNING;
        se_mark_running(&next->se);
        rq->curr_se = &next->se;
        if (cpu->prev_task) sched_post_switch_cleanup();
        spin_unlock(&rq->lock);
        arch_irq_restore(state);
    }
}

void sched_tick(void) {
    struct percpu_data *cpu = arch_get_percpu();
    struct cfs_rq *rq = &cpu->runqueue;
    struct process *curr = proc_current();

    cpu->ticks++;
    if (spin_trylock(&rq->lock)) {
        if (curr && curr != cpu->idle_proc) {
            rq->curr_se = &curr->se;
            uint64_t delta = update_curr(rq);
            uint32_t nr = rq->nr_running + 1;
            uint64_t slice = SCHED_LATENCY_NS / nr;
            if (slice < SCHED_MIN_GRANULARITY_NS)
                slice = SCHED_MIN_GRANULARITY_NS;
            if (delta >= slice)
                cpu->resched_needed = true;
        } else if (rq->nr_running > 0) {
            cpu->resched_needed = true;
        }
        spin_unlock(&rq->lock);
    }

    /* Wake processes whose sleep deadline has expired (CPU 0 only) */
    if (arch_cpu_id() == 0)
        proc_wake_expired_sleepers(arch_timer_get_ticks());
}

int sched_setnice(struct process *p, int nice) {
    if (!p) return -1;
    nice = (nice < NICE_MIN) ? NICE_MIN : (nice > NICE_MAX) ? NICE_MAX : nice;

    int cpu = p->se.cpu;
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS) return -1;
    struct cfs_rq *rq = &cpu_data[cpu].runqueue;
    bool state = arch_irq_save();
    spin_lock(&rq->lock);
    /* Re-check: steal can move this task between lock acquire */
    if (p->se.cpu != cpu) {
        spin_unlock(&rq->lock);
        arch_irq_restore(state);
        return -EAGAIN;
    }
    bool on_rq = se_is_on_rq(&p->se);
    if (on_rq) rb_erase(&p->se.sched_node, &rq->tasks_timeline);
    p->se.nice = nice;
    if (on_rq) __enqueue_entity(rq, &p->se);
    spin_unlock(&rq->lock);
    arch_irq_restore(state);
    return 0;
}

int sched_getnice(struct process *p) { return p ? p->se.nice : 0; }
int sched_cpu_id(void) { return arch_cpu_id(); }
struct cfs_rq *sched_cpu_rq(void) { return this_rq; }
bool sched_need_resched(void) { return arch_get_percpu()->resched_needed; }
void sched_set_idle(struct process *p) {
    struct percpu_data *cpu = arch_get_percpu();
    cpu->idle_proc = p;
    cpu->runqueue.idle = p;
}
int sched_cpu_count(void) { return sched_nr_cpus(); }
void sched_set_steal_enabled(bool enabled) {
    __atomic_store_n(&sched_steal_enabled, enabled, __ATOMIC_RELEASE);
}

void sched_get_stats(struct sched_stats *out) {
    if (!out)
        return;
    memset(out, 0, sizeof(*out));

    int cpu_count = sched_nr_cpus();
    if (cpu_count < 1)
        cpu_count = 1;
    if (cpu_count > CONFIG_MAX_CPUS)
        cpu_count = CONFIG_MAX_CPUS;
    out->cpu_count = (uint32_t)cpu_count;
    out->steal_enabled = sched_steal_is_enabled();

    for (int i = 0; i < cpu_count; i++) {
        struct sched_cpu_stats *dst = &out->cpu[i];
        const struct sched_cpu_stats *src = &cpu_data[i].stats;
        dst->enqueue_count = sched_stat_load(&src->enqueue_count);
        dst->dequeue_count = sched_stat_load(&src->dequeue_count);
        dst->pick_count = sched_stat_load(&src->pick_count);
        dst->switch_count = sched_stat_load(&src->switch_count);
        dst->idle_pick_count = sched_stat_load(&src->idle_pick_count);
        dst->steal_attempt_count = sched_stat_load(&src->steal_attempt_count);
        dst->steal_success_count = sched_stat_load(&src->steal_success_count);
        dst->state_violation_count =
            sched_stat_load(&src->state_violation_count);
    }
}

void sched_debug_dump_cpu(int cpu_id) {
    if (cpu_id < 0 || cpu_id >= sched_nr_cpus()) {
        pr_warn("sched: debug dump invalid cpu=%d (online=%d)\n",
                cpu_id, sched_nr_cpus());
        return;
    }

    struct sched_stats snapshot;
    sched_get_stats(&snapshot);
    struct percpu_data *cpu = &cpu_data[cpu_id];
    struct sched_cpu_stats *stats = &snapshot.cpu[cpu_id];
    uint32_t nr_running = sched_rq_nr_running(cpu_id);
    uint64_t min_vruntime = sched_rq_min_vruntime(cpu_id);

    pr_info("sched: cpu%d rq(nr_running=%u min_vruntime=%llu) ticks=%llu resched=%d\n",
            cpu_id, nr_running, (unsigned long long)min_vruntime,
            (unsigned long long)cpu->ticks, cpu->resched_needed);
    pr_info("sched: cpu%d stats enq=%llu deq=%llu pick=%llu switch=%llu idle_pick=%llu steal=%llu/%llu violations=%llu\n",
            cpu_id, (unsigned long long)stats->enqueue_count,
            (unsigned long long)stats->dequeue_count,
            (unsigned long long)stats->pick_count,
            (unsigned long long)stats->switch_count,
            (unsigned long long)stats->idle_pick_count,
            (unsigned long long)stats->steal_success_count,
            (unsigned long long)stats->steal_attempt_count,
            (unsigned long long)stats->state_violation_count);
}

void sched_cpu_online(int cpu) {
    if (cpu >= 0 && cpu < CONFIG_MAX_CPUS && cpu >= sched_nr_cpus())
        __atomic_store_n(&nr_cpus_online, cpu + 1, __ATOMIC_RELEASE);
}
struct percpu_data *sched_cpu_data(int cpu) {
    return (cpu < 0 || cpu >= CONFIG_MAX_CPUS) ? NULL : &cpu_data[cpu];
}

/* --- Public accessor API --- */

bool sched_is_on_cpu(const struct process *p) {
    return p ? se_is_on_cpu(&p->se) : false;
}

int sched_entity_cpu(const struct process *p) {
    return p ? p->se.cpu : -1;
}

void sched_init_idle_entity(struct process *p, int cpu) {
    if (!p) return;
    p->se.nice = 19;
    p->se.cpu = cpu;
    se_set_state(&p->se, SE_STATE_RUNNING);
}

uint32_t sched_rq_nr_running(int cpu) {
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS) return 0;
    return __atomic_load_n(&cpu_data[cpu].runqueue.nr_running, __ATOMIC_RELAXED);
}

uint64_t sched_rq_min_vruntime(int cpu) {
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS) return 0;
    return __atomic_load_n(&cpu_data[cpu].runqueue.min_vruntime, __ATOMIC_RELAXED);
}

void sched_debug_dump_process(const struct process *p) {
    if (!p) return;
    uint32_t st = __atomic_load_n(&p->se.run_state, __ATOMIC_ACQUIRE);
    pr_err("  sched: pid=%d se_state=%s cpu=%d vruntime=%llu nice=%d\n",
           p->pid, sched_se_state_name(st), p->se.cpu,
           (unsigned long long)p->se.vruntime, p->se.nice);
}

void sched_fork(struct process *child, struct process *parent) {
    sched_entity_init(&child->se);
    child->se.vruntime = parent->se.vruntime;
    child->se.nice = parent->se.nice;
    child->se.cpu = parent->se.cpu;
}
