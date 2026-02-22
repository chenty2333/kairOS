/**
 * kernel/core/sched/sched.c - Scheduler core with sched_class dispatch
 *
 * The core scheduler (schedule, sched_tick, sched_enqueue, sched_dequeue)
 * dispatches through struct sched_class function pointers.  The EEVDF
 * implementation lives in fair_sched_class at the bottom of this file.
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/rbtree.h>
#include <kairos/sched.h>
#include <kairos/sched_class.h>
#include <kairos/string.h>

/* EEVDF Scheduler Tunables */
#define SCHED_SLICE_NS          3000000UL   /* 3ms default time slice */
#define SCHED_LATENCY_NS        6000000UL   /* 6ms scheduling latency target */
#define SCHED_MIN_GRANULARITY_NS 500000UL   /* 0.5ms minimum granularity */

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

/* Spinlock preemption control — sync.c provides these when CONFIG_DEBUG_LOCKS is on. */
#if !CONFIG_DEBUG_LOCKS
void __spin_preempt_disable(void) {
    struct percpu_data *cpu = arch_get_percpu();
    cpu->preempt_count++;
    __asm__ volatile("" ::: "memory");
}

void __spin_preempt_enable(void) {
    __asm__ volatile("" ::: "memory");
    arch_get_percpu()->preempt_count--;
}
#endif

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

static void update_min_vruntime(struct cfs_rq *cfs_rq) {
    uint64_t v = cfs_rq->min_vruntime;
    if (cfs_rq->curr_se && cfs_rq->curr_se->vruntime > v)
        v = cfs_rq->curr_se->vruntime;
    struct rb_node *left = rb_first(&cfs_rq->tasks_timeline);
    if (left) {
        struct sched_entity *se = rb_entry(left, struct sched_entity, sched_node);
        if (se->vruntime < v) v = se->vruntime;
    }
    if (v > cfs_rq->min_vruntime) cfs_rq->min_vruntime = v;
}

static void se_recompute_min_deadline(struct rb_node *node);

/* Insert entity into RB-tree ordered by vruntime */
static void __enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se) {
    struct rb_node **link = &cfs_rq->tasks_timeline.rb_node, *parent = NULL;
    bool rightmost = true;
    while (*link) {
        parent = *link;
        if (se->vruntime < rb_entry(parent, struct sched_entity, sched_node)->vruntime) {
            link = &parent->rb_left;
            rightmost = false;
        } else {
            link = &parent->rb_right;
        }
    }
    rb_link_node(&se->sched_node, parent, link);
    rb_insert_color(&se->sched_node, &cfs_rq->tasks_timeline);
    if (rightmost)
        cfs_rq->rb_rightmost = &se->sched_node;
    se->min_deadline = se->deadline;
    se_recompute_min_deadline(cfs_rq->tasks_timeline.rb_node);
}

static uint64_t update_curr(struct cfs_rq *cfs_rq) {
    struct sched_entity *curr_se = cfs_rq->curr_se;
    if (!curr_se) return 0;

    uint64_t now = sched_clock_ns();
    uint64_t delta = (now > curr_se->last_run_time) ? now - curr_se->last_run_time : 0;
    if (delta == 0) return 0;

    curr_se->vruntime += calc_delta_fair(delta, __weight(curr_se->nice));
    curr_se->last_run_time = now;
    update_min_vruntime(cfs_rq);
    return delta;
}

/* --- EEVDF helpers --- */

static inline uint64_t calc_vslice(struct sched_entity *se) {
    uint64_t slice = se->slice ? se->slice : SCHED_SLICE_NS;
    return calc_delta_fair(slice, __weight(se->nice));
}

static inline bool entity_eligible(struct cfs_rq *cfs_rq, struct sched_entity *se) {
    return (int64_t)(se->vruntime - cfs_rq->min_vruntime) <= 0;
}

static inline bool deadline_before(struct sched_entity *a, struct sched_entity *b) {
    return (int64_t)(a->deadline - b->deadline) < 0;
}

/* Augmented RB-tree: subtree-min-deadline propagation */

/* Recompute min_deadline from self + children; return true if changed */
static inline bool se_update_min_deadline(struct sched_entity *se) {
    uint64_t min_dl = se->deadline;
    struct rb_node *left = se->sched_node.rb_left;
    struct rb_node *right = se->sched_node.rb_right;
    if (left) {
        struct sched_entity *l = rb_entry(left, struct sched_entity, sched_node);
        if (l->min_deadline < min_dl)
            min_dl = l->min_deadline;
    }
    if (right) {
        struct sched_entity *r = rb_entry(right, struct sched_entity, sched_node);
        if (r->min_deadline < min_dl)
            min_dl = r->min_deadline;
    }
    if (se->min_deadline == min_dl)
        return false;
    se->min_deadline = min_dl;
    return true;
}

static void se_recompute_min_deadline(struct rb_node *node) {
    if (!node)
        return;
    se_recompute_min_deadline(node->rb_left);
    se_recompute_min_deadline(node->rb_right);
    se_update_min_deadline(rb_entry(node, struct sched_entity, sched_node));
}

/* rb_erase + post-order min_deadline recompute + rightmost maintenance */
static void sched_rb_erase(struct sched_entity *se, struct cfs_rq *cfs_rq) {
    if (cfs_rq->rb_rightmost == &se->sched_node)
        cfs_rq->rb_rightmost = rb_prev(&se->sched_node);
    rb_erase(&se->sched_node, &cfs_rq->tasks_timeline);
    se_recompute_min_deadline(cfs_rq->tasks_timeline.rb_node);
}

/*
 * pick_eevdf — O(log n) exact pick via augmented min_deadline.
 * Recurses into right subtree only when both sides are worth exploring.
 */
static inline bool deadline_before_val(uint64_t a, uint64_t b) {
    return (int64_t)(a - b) < 0;
}

static inline bool subtree_has_better(struct rb_node *node,
                                       struct sched_entity *best) {
    if (!node) return false;
    if (!best) return true;
    struct sched_entity *se = rb_entry(node, struct sched_entity, sched_node);
    return deadline_before_val(se->min_deadline, best->deadline);
}

static struct sched_entity *__pick_eevdf(struct cfs_rq *cfs_rq,
                                          struct rb_node *node,
                                          struct sched_entity *best) {
    while (node) {
        struct sched_entity *se = rb_entry(node, struct sched_entity, sched_node);

        if (best && !deadline_before_val(se->min_deadline, best->deadline))
            break;

        if (entity_eligible(cfs_rq, se)) {
            if (!best || deadline_before(se, best))
                best = se;

            if (subtree_has_better(node->rb_left, best)) {
                if (subtree_has_better(node->rb_right, best))
                    best = __pick_eevdf(cfs_rq, node->rb_right, best);
                node = node->rb_left;
            } else {
                node = node->rb_right;
            }
        } else {
            /* Ineligible: right has larger vruntime, go left */
            node = node->rb_left;
        }
    }
    return best;
}

static struct sched_entity *pick_eevdf(struct cfs_rq *cfs_rq) {
    struct sched_entity *best =
        __pick_eevdf(cfs_rq, cfs_rq->tasks_timeline.rb_node, NULL);

    /* Fallback to leftmost if nothing eligible */
    if (!best) {
        struct rb_node *left = rb_first(&cfs_rq->tasks_timeline);
        if (left)
            best = rb_entry(left, struct sched_entity, sched_node);
    }

    return best;
}

/*
 * place_entity_eevdf - Set vruntime and deadline when entity enters the queue
 *
 * On wakeup: restore lag (se->vruntime = V - vlag), clamped to one vslice.
 * On initial/fork: set vruntime to min_vruntime + vslice (fork penalty).
 */
static void place_entity_eevdf(struct cfs_rq *cfs_rq, struct sched_entity *se,
                                int flags) {
    uint64_t vslice = calc_vslice(se);
    uint64_t V = cfs_rq->min_vruntime;

    if (flags & ENQUEUE_WAKEUP) {
        /* Restore lag: vruntime = V - vlag */
        int64_t lag = se->vlag;
        se->vruntime = V - lag;
        /* Clamp: don't let lag exceed one vslice */
        if ((int64_t)(V - se->vruntime) > (int64_t)vslice)
            se->vruntime = V - vslice;
        /* Don't go below min_vruntime - vslice */
        if ((int64_t)(se->vruntime - V) > (int64_t)vslice)
            se->vruntime = V;
    } else {
        /* Initial placement or fork: slight penalty to prevent fork bombs */
        if (se->vruntime < V)
            se->vruntime = V;
    }

    /* Set deadline */
    se->deadline = se->vruntime + vslice;
    if (!se->slice)
        se->slice = SCHED_SLICE_NS;
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
    struct rq *rq = &d->runqueue;
    spin_init(&rq->lock);
    rq->cfs.tasks_timeline = RB_ROOT;
    rq->cfs.rb_rightmost = NULL;
    rq->cfs.nr_running = 0;
    rq->cfs.min_vruntime = 0;
    rq->cfs.curr_se = NULL;
    rq->nr_running = 0;
    rq->idle = NULL;
    rq->curr_class = &fair_sched_class;
    spin_init(&d->ipi_call_lock);
    d->prev_task = NULL;
}

void sched_post_switch_cleanup(void) {
    struct percpu_data *cpu = arch_get_percpu();
    if (cpu->prev_task) {
        struct process *prev = cpu->prev_task;
        /* State already updated before context switch; nothing to do. */
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

    /* Unify p->state with se.run_state — callers no longer need to set this */
    p->state = PROC_RUNNABLE;

    /* Assign sched_class if not yet set */
    if (!p->se.sched_class)
        p->se.sched_class = &fair_sched_class;

    /* Find target CPU - currently simple: stay on current or preferred */
    int cpu = (p->se.cpu >= 0 && p->se.cpu < sched_nr_cpus()) ? p->se.cpu : arch_cpu_id();

    /* Push migration: if preferred CPU is busy, try to find an idle one */
    if (sched_steal_is_enabled() && sched_nr_cpus() > 1) {
        uint32_t nr = __atomic_load_n(&cpu_data[cpu].runqueue.nr_running,
                                       __ATOMIC_RELAXED);
        if (nr > 0) {
            int online = sched_nr_cpus();
            for (int i = 0; i < online; i++) {
                if (i == cpu) continue;
                if (__atomic_load_n(&cpu_data[i].runqueue.nr_running,
                                     __ATOMIC_RELAXED) == 0) {
                    cpu = i;
                    p->se.cpu = cpu;
                    break;
                }
            }
        }
    }

    struct rq *rq = &cpu_data[cpu].runqueue;

    bool state = arch_irq_save();
    spin_lock(&rq->lock);

    if (se_is_on_rq(&p->se)) {
        pr_err("BUG: sched_enqueue: pid=%d on rq after BLOCKED->RUNNABLE\n",
               p->pid);
        spin_unlock(&rq->lock);
        se_set_state(&p->se, SE_STATE_BLOCKED);
        arch_irq_restore(state);
        return;
    }

    p->se.sched_class->enqueue_task(rq, p, ENQUEUE_WAKEUP);
    sched_stat_inc(&cpu_data[cpu].stats.enqueue_count);
    sched_trace_event(SCHED_TRACE_ENQUEUE, p, (uint64_t)cpu, p->se.vruntime);
    int prev_cpu = p->se.cpu;
    se_mark_queued(&p->se, cpu);
    rq->nr_running++;
    if (cpu != prev_cpu && prev_cpu >= 0)
        sched_trace_event(SCHED_TRACE_MIGRATE, p, (uint64_t)prev_cpu, (uint64_t)cpu);
    sched_validate_entity(p, "sched_enqueue");

    /* Check preemption via class */
    p->se.sched_class->check_preempt_curr(rq, p);
    bool need_resched = cpu_data[cpu].resched_needed;

    spin_unlock(&rq->lock);

    if (need_resched && cpu != arch_cpu_id())
        arch_send_ipi(cpu, IPI_RESCHEDULE);

    arch_irq_restore(state);
}

void sched_dequeue(struct process *p) {
    if (!p) return;

    int cpu = p->se.cpu;
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        return;
    struct rq *rq = &cpu_data[cpu].runqueue;
    bool state = arch_irq_save();
    spin_lock(&rq->lock);

    /* Re-check under lock: steal can change state/cpu concurrently */
    if (!se_is_on_rq(&p->se) || p->se.cpu != cpu) {
        spin_unlock(&rq->lock);
        arch_irq_restore(state);
        return;
    }

    if (p->se.sched_class)
        p->se.sched_class->dequeue_task(rq, p, DEQUEUE_SLEEP);
    se_mark_blocked(&p->se);
    rq->nr_running--;
    sched_stat_inc(&cpu_data[cpu].stats.dequeue_count);
    sched_trace_event(SCHED_TRACE_DEQUEUE, p, (uint64_t)cpu, 0);
    sched_validate_entity(p, "sched_dequeue");

    spin_unlock(&rq->lock);
    arch_irq_restore(state);
}

/**
 * sched_steal_task - Try to steal a task from another CPU.
 *
 * Randomizes start CPU, does lockless nr_running pre-check, and
 * dispatches through sched_class->steal_task.
 */
static struct process *sched_steal_task(int self_id) {
    struct sched_cpu_stats *self_stats = &cpu_data[self_id].stats;
    int online = sched_nr_cpus();
    if (online <= 1)
        return NULL;

    /* Start from a pseudo-random CPU to spread steal pressure */
    uint32_t start = (uint32_t)(cpu_data[self_id].ticks) % (uint32_t)online;

    for (int j = 0; j < online; j++) {
        int i = (int)((start + (uint32_t)j) % (uint32_t)online);
        if (i == self_id) continue;
        sched_stat_inc(&self_stats->steal_attempt_count);

        /* Lockless pre-check: skip if remote has <= 1 task */
        if (__atomic_load_n(&cpu_data[i].runqueue.cfs.nr_running,
                            __ATOMIC_RELAXED) <= 1)
            continue;

        struct rq *remote_rq = &cpu_data[i].runqueue;
        if (!spin_trylock(&remote_rq->lock)) continue;

        struct process *p = NULL;
        if (fair_sched_class.steal_task)
            p = fair_sched_class.steal_task(remote_rq, self_id);

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
    struct rq *rq = &cpu->runqueue;
    bool state = arch_irq_save();

    spin_lock(&rq->lock);
    cpu->resched_needed = false;

    /* Put prev task back via its sched_class */
    if (prev && prev != cpu->idle_proc) {
        const struct sched_class *cls = prev->se.sched_class;
        if (cls)
            cls->put_prev_task(rq, prev);
        else {
            se_mark_blocked(&prev->se);
        }
        sched_validate_entity(prev, "schedule-prev");
    } else if (prev == cpu->idle_proc) {
        /* Idle was running — clear curr_se so update_min_vruntime
         * doesn't consider idle's stale vruntime. */
        rq->cfs.curr_se = NULL;
    }

    /* Pick next task: iterate sched_classes by priority */
    next = fair_sched_class.pick_next_task(rq, prev);

    if (!next) {
        /* Local empty — attempt stealing */
        bool steal_allowed = sched_steal_is_enabled() && sched_nr_cpus() > 1;
        if (steal_allowed) {
            spin_unlock(&rq->lock);
            struct process *stolen = sched_steal_task(cpu->cpu_id);
            spin_lock(&rq->lock);

            if (stolen) {
                /* Adapt stolen task to local vruntime domain and enqueue */
                struct cfs_rq *cfs = &rq->cfs;
                place_entity_eevdf(cfs, &stolen->se, ENQUEUE_WAKEUP);
                __enqueue_entity(cfs, &stolen->se);
                se_mark_queued(&stolen->se, cpu->cpu_id);
                cfs->nr_running++;
                rq->nr_running++;
                update_min_vruntime(cfs);
            }
        }

        /* Pick from local queue (now includes any stolen task) */
        next = fair_sched_class.pick_next_task(rq, prev);

        if (!next)
            next = cpu->idle_proc;
    }

    if (next != cpu->idle_proc) {
        sched_stat_inc(&stats->pick_count);
        sched_trace_event(SCHED_TRACE_PICK, next, (uint64_t)cpu->cpu_id,
                          (uint64_t)rq->nr_running);
    } else {
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
        rq->cfs.curr_se = &next->se;
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
        rq->cfs.curr_se = &next->se;
        if (cpu->prev_task) sched_post_switch_cleanup();
        spin_unlock(&rq->lock);
        arch_irq_restore(state);
    }
}

void sched_tick(void) {
    struct percpu_data *cpu = arch_get_percpu();
    struct rq *rq = &cpu->runqueue;
    struct process *curr = proc_current();

    cpu->ticks++;
    if (spin_trylock(&rq->lock)) {
        if (curr && curr != cpu->idle_proc) {
            const struct sched_class *cls = curr->se.sched_class;
            if (cls)
                cls->task_tick(rq, curr);
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
    struct rq *rq = &cpu_data[cpu].runqueue;
    bool state = arch_irq_save();
    spin_lock(&rq->lock);
    /* Re-check: steal can move this task between lock acquire */
    if (p->se.cpu != cpu) {
        spin_unlock(&rq->lock);
        arch_irq_restore(state);
        return -EAGAIN;
    }
    if (p->se.sched_class && p->se.sched_class->set_nice) {
        int ret = p->se.sched_class->set_nice(rq, p, nice);
        spin_unlock(&rq->lock);
        arch_irq_restore(state);
        return ret;
    }
    p->se.nice = nice;
    spin_unlock(&rq->lock);
    arch_irq_restore(state);
    return 0;
}

int sched_getnice(struct process *p) { return p ? p->se.nice : 0; }
int sched_cpu_id(void) { return arch_cpu_id(); }
struct rq *sched_cpu_rq(void) { return this_rq; }
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
    p->se.sched_class = &fair_sched_class;
    se_set_state(&p->se, SE_STATE_RUNNING);
}

uint32_t sched_rq_nr_running(int cpu) {
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS) return 0;
    return __atomic_load_n(&cpu_data[cpu].runqueue.cfs.nr_running, __ATOMIC_RELAXED);
}

uint64_t sched_rq_min_vruntime(int cpu) {
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS) return 0;
    return __atomic_load_n(&cpu_data[cpu].runqueue.cfs.min_vruntime, __ATOMIC_RELAXED);
}

void sched_debug_dump_process(const struct process *p) {
    if (!p) return;
    uint32_t st = __atomic_load_n(&p->se.run_state, __ATOMIC_ACQUIRE);
    pr_err("  sched: pid=%d se_state=%s cpu=%d vruntime=%llu deadline=%llu vlag=%lld nice=%d\n",
           p->pid, sched_se_state_name(st), p->se.cpu,
           (unsigned long long)p->se.vruntime,
           (unsigned long long)p->se.deadline,
           (long long)p->se.vlag, p->se.nice);
}

/* ================================================================== */
/*  fair_sched_class — EEVDF implementation behind sched_class        */
/* ================================================================== */

static void fair_enqueue_task(struct rq *rq, struct process *p, int flags) {
    struct cfs_rq *cfs = &rq->cfs;
    if (!p->se.slice)
        p->se.slice = SCHED_SLICE_NS;
    place_entity_eevdf(cfs, &p->se, flags);
    __enqueue_entity(cfs, &p->se);
    cfs->nr_running++;
    update_min_vruntime(cfs);
}

static void fair_dequeue_task(struct rq *rq, struct process *p,
                              int flags __attribute__((unused))) {
    struct cfs_rq *cfs = &rq->cfs;
    /* Save lag for wakeup restoration */
    p->se.vlag = (int64_t)(cfs->min_vruntime - p->se.vruntime);
    sched_rb_erase(&p->se, cfs);
    cfs->nr_running--;
    update_min_vruntime(cfs);
}

static struct process *fair_pick_next_task(struct rq *rq,
                                           struct process *prev
                                           __attribute__((unused))) {
    struct cfs_rq *cfs = &rq->cfs;
    struct sched_entity *se = pick_eevdf(cfs);
    if (!se)
        return NULL;
    struct process *next = container_of(se, struct process, se);
    sched_rb_erase(se, cfs);
    se_mark_runnable(se);
    cfs->nr_running--;
    rq->nr_running--;
    return next;
}

static void fair_put_prev_task(struct rq *rq, struct process *prev) {
    struct cfs_rq *cfs = &rq->cfs;
    (void)update_curr(cfs);

    if (prev->state == PROC_RUNNING || prev->state == PROC_RUNNABLE) {
        /* Still runnable — re-enqueue onto RB-tree for next pick */
        prev->state = PROC_RUNNABLE;
        /* Refresh deadline if slice expired */
        if ((int64_t)(prev->se.vruntime - prev->se.deadline) >= 0) {
            uint64_t vslice = calc_vslice(&prev->se);
            prev->se.deadline = prev->se.vruntime + vslice;
        }
        __enqueue_entity(cfs, &prev->se);
        se_mark_queued(&prev->se, prev->se.cpu);
        cfs->nr_running++;
        rq->nr_running++;
        update_min_vruntime(cfs);
        return;
    }

    /*
     * Non-runnable (sleeping/zombie): save lag for wakeup placement.
     * The running task was removed from the tree by pick_next_task,
     * so se_is_on_rq should be false here — the check is defensive.
     */
    prev->se.vlag = (int64_t)(cfs->min_vruntime - prev->se.vruntime);
    if (se_is_on_rq(&prev->se)) {
        sched_rb_erase(&prev->se, cfs);
        cfs->nr_running--;
        rq->nr_running--;
    }
    se_mark_blocked(&prev->se);
}

static void fair_task_tick(struct rq *rq, struct process *p) {
    struct cfs_rq *cfs = &rq->cfs;
    int cpu_id = p->se.cpu;
    struct percpu_data *cpu = (cpu_id >= 0 && cpu_id < CONFIG_MAX_CPUS)
                              ? &cpu_data[cpu_id] : arch_get_percpu();

    cfs->curr_se = &p->se;
    uint64_t delta = update_curr(cfs);

    /* Check if current has exceeded its slice */
    if ((int64_t)(p->se.vruntime - p->se.deadline) >= 0) {
        cpu->resched_needed = true;
        return;
    }

    /* Also check minimum granularity */
    if (cfs->nr_running == 0)
        return;
    uint32_t nr = cfs->nr_running + 1;
    uint64_t gran = SCHED_LATENCY_NS / nr;
    if (gran < SCHED_MIN_GRANULARITY_NS)
        gran = SCHED_MIN_GRANULARITY_NS;
    if (delta >= gran)
        cpu->resched_needed = true;
}

static void fair_task_fork(struct process *child, struct process *parent) {
    child->se.vruntime = parent->se.vruntime;
    child->se.nice = parent->se.nice;
    child->se.cpu = parent->se.cpu;
    child->se.slice = SCHED_SLICE_NS;
    child->se.vlag = 0;  /* no lag advantage for new forks */
    child->se.deadline = child->se.vruntime + calc_delta_fair(SCHED_SLICE_NS,
                         __weight(child->se.nice));
    child->se.sched_class = &fair_sched_class;
}

static int fair_set_nice(struct rq *rq, struct process *p, int nice) {
    struct cfs_rq *cfs = &rq->cfs;
    bool on_rq = se_is_on_rq(&p->se);
    if (on_rq) sched_rb_erase(&p->se, cfs);
    p->se.nice = nice;
    /* Recalculate deadline with new weight */
    uint64_t vslice = calc_vslice(&p->se);
    p->se.deadline = p->se.vruntime + vslice;
    if (on_rq) __enqueue_entity(cfs, &p->se);
    return 0;
}

static void fair_check_preempt_curr(struct rq *rq, struct process *p) {
    struct cfs_rq *cfs = &rq->cfs;
    struct sched_entity *curr_se = cfs->curr_se;
    if (!curr_se || curr_se == &p->se)
        return;

    /* EEVDF preemption: if new task is eligible and has earlier deadline */
    if (entity_eligible(cfs, &p->se) && deadline_before(&p->se, curr_se)) {
        int cpu_id = p->se.cpu;
        if (cpu_id >= 0 && cpu_id < CONFIG_MAX_CPUS)
            cpu_data[cpu_id].resched_needed = true;
    }
}

static struct process *fair_steal_task(struct rq *rq, int dst_cpu) {
    struct cfs_rq *cfs = &rq->cfs;
    if (cfs->nr_running == 0)
        return NULL;

    /*
     * Steal strategy: take the rightmost node (largest vruntime) —
     * the task that has consumed the most virtual CPU time and is
     * therefore least owed.  rb_rightmost is cached O(1); we walk
     * left via rb_prev only if the rightmost fails the state check.
     */
    struct sched_entity *best_se = NULL;
    struct process *best = NULL;

    for (struct rb_node *node = cfs->rb_rightmost;
         node; node = rb_prev(node)) {
        struct sched_entity *se =
            rb_entry(node, struct sched_entity, sched_node);
        struct process *cand = container_of(se, struct process, se);
        if (cand->state != PROC_RUNNABLE)
            continue;
        if (se_state_load(se) != SE_STATE_QUEUED)
            continue;
        best_se = se;
        best = cand;
        break;
    }

    if (!best_se)
        return NULL;

    sched_rb_erase(best_se, cfs);
    /* Save lag relative to source CPU for destination placement */
    best_se->vlag = (int64_t)(cfs->min_vruntime - best_se->vruntime);
    se_mark_runnable(best_se);
    best_se->cpu = dst_cpu;
    cfs->nr_running--;
    rq->nr_running--;
    update_min_vruntime(cfs);
    sched_validate_entity(best, "fair_steal_task");
    return best;
}

const struct sched_class fair_sched_class = {
    .enqueue_task       = fair_enqueue_task,
    .dequeue_task       = fair_dequeue_task,
    .pick_next_task     = fair_pick_next_task,
    .put_prev_task      = fair_put_prev_task,
    .task_tick          = fair_task_tick,
    .task_fork          = fair_task_fork,
    .set_nice           = fair_set_nice,
    .check_preempt_curr = fair_check_preempt_curr,
    .steal_task         = fair_steal_task,
    .priority           = 100,
};

void sched_fork(struct process *child, struct process *parent) {
    sched_entity_init(&child->se);
    child->se.sched_class = &fair_sched_class;
    if (fair_sched_class.task_fork)
        fair_sched_class.task_fork(child, parent);
}
