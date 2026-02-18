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

extern struct process proc_table[CONFIG_MAX_PROCESSES];

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
static bool sched_steal_enabled = false;

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
    se->on_rq = true;
    se_set_state(se, SE_STATE_QUEUED);
}

static inline void se_mark_running(struct sched_entity *se) {
    se->on_rq = false;
    __atomic_store_n(&se->on_cpu, true, __ATOMIC_RELEASE);
    se_set_state(se, SE_STATE_RUNNING);
}

static inline void se_mark_runnable(struct sched_entity *se) {
    se->on_rq = false;
    se_set_state(se, SE_STATE_RUNNABLE);
}

static inline void se_mark_blocked(struct sched_entity *se) {
    se->on_rq = false;
    se_set_state(se, SE_STATE_BLOCKED);
}

#if CONFIG_DEBUG
static void sched_validate_entity(struct process *p, const char *where) {
    struct sched_entity *se = &p->se;
    uint32_t state = se_state_load(se);

    if (se->on_rq && state != SE_STATE_QUEUED) {
        panic("sched: invalid on_rq state at %s pid=%d state=%u on_rq=%d on_cpu=%d",
              where, p->pid, state, se->on_rq, se->on_cpu);
    }
    if (state == SE_STATE_QUEUED && !se->on_rq) {
        panic("sched: invalid queued state at %s pid=%d state=%u on_rq=%d on_cpu=%d",
              where, p->pid, state, se->on_rq, se->on_cpu);
    }
    if (state == SE_STATE_RUNNING && !__atomic_load_n(&se->on_cpu, __ATOMIC_ACQUIRE)) {
        panic("sched: invalid running state at %s pid=%d state=%u on_rq=%d on_cpu=%d",
              where, p->pid, state, se->on_rq, se->on_cpu);
    }
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

static void update_curr(struct cfs_rq *rq) {
    struct sched_entity *curr_se = rq->curr_se;
    if (!curr_se) return;

    uint64_t now = sched_clock_ns();
    uint64_t delta = (now > curr_se->last_run_time) ? now - curr_se->last_run_time : 0;
    if (delta == 0) return;

    curr_se->vruntime += calc_delta_fair(delta, __weight(curr_se->nice));
    curr_se->last_run_time = now;
    update_min_vruntime(rq);
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
        __atomic_store_n(&prev->se.on_cpu, false, __ATOMIC_RELEASE);
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
    int cpu = (p->se.cpu >= 0 && p->se.cpu < nr_cpus_online) ? p->se.cpu : arch_cpu_id();
    struct cfs_rq *rq = &cpu_data[cpu].runqueue;

    bool state = arch_irq_save();
    spin_lock(&rq->lock);

    if (p->se.on_rq) {
        spin_unlock(&rq->lock);
        se_set_state(&p->se, SE_STATE_QUEUED);
        arch_irq_restore(state);
        return;
    }

    place_entity(rq, &p->se, p->se.vruntime == 0);
    __enqueue_entity(rq, &p->se);
    se_mark_queued(&p->se, cpu);
    __atomic_store_n(&p->se.on_cpu, false, __ATOMIC_RELEASE);
    rq->nr_running++;
    update_min_vruntime(rq);
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
    if (!p || !p->se.on_rq) return;

    struct cfs_rq *rq = &cpu_data[p->se.cpu].runqueue;
    bool state = arch_irq_save();
    spin_lock(&rq->lock);

    rb_erase(&p->se.sched_node, &rq->tasks_timeline);
    se_mark_blocked(&p->se);
    rq->nr_running--;
    update_min_vruntime(rq);
    sched_validate_entity(p, "sched_dequeue");

    spin_unlock(&rq->lock);
    arch_irq_restore(state);
}

/**
 * sched_steal_task - Try to steal from other CPUs
 * Uses strict locking order (ascending CPU ID) to prevent deadlocks.
 */
static struct process *sched_steal_task(int self_id) {
    for (int i = 0; i < nr_cpus_online; i++) {
        if (i == self_id) continue;

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
                if (__atomic_load_n(&se->on_cpu, __ATOMIC_ACQUIRE))
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
        if (p) return p;
    }
    return NULL;
}

void schedule(void) {
    struct percpu_data *cpu = arch_get_percpu();
    struct process *prev = proc_current(), *next;
    struct cfs_rq *rq = &cpu->runqueue;
    bool state = arch_irq_save();

    spin_lock(&rq->lock);
    cpu->resched_needed = false;

    if (prev && prev != cpu->idle_proc) {
        update_curr(rq);
        __atomic_store_n(&prev->se.on_cpu, true, __ATOMIC_RELEASE);
        se_set_state(&prev->se, SE_STATE_RUNNING);

        if (prev->state == PROC_RUNNING) {
            prev->state = PROC_RUNNABLE;
            se_mark_runnable(&prev->se);
            __enqueue_entity(rq, &prev->se);
            se_mark_queued(&prev->se, cpu->cpu_id);
            rq->nr_running++;
        } else {
            if (prev->se.on_rq) {
                rb_erase(&prev->se.sched_node, &rq->tasks_timeline);
                prev->se.on_rq = false;
                rq->nr_running--;
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
        se_mark_running(se);
        rq->nr_running--;
    } else {
        /* Local empty - attempt stealing without holding local lock to simplify */
        bool steal_allowed =
            __atomic_load_n(&sched_steal_enabled, __ATOMIC_ACQUIRE) &&
            nr_cpus_online > 1;
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
                se_mark_running(se);
                rq->nr_running--;
            } else {
                next = cpu->idle_proc;
            }
        }
    }

    if (next == prev && prev->state == PROC_ZOMBIE && prev != cpu->idle_proc) {
        pr_err("SCHED: CPU %d trying to re-schedule ZOMBIE PID %d. idle_proc PID %d\n",
               cpu->cpu_id, prev->pid, cpu->idle_proc ? cpu->idle_proc->pid : -1);
        panic("SCHED: Zombie Rescheduling");
    }

    if (next != prev) {
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
    uint64_t now = sched_clock_ns();
    uint64_t delta = (curr && now > curr->se.last_run_time) ? now - curr->se.last_run_time : 0;
    if (spin_trylock(&rq->lock)) {
        if (curr && curr != cpu->idle_proc) {
            rq->curr_se = &curr->se;
            update_curr(rq);
        }
        if (curr && curr != cpu->idle_proc) {
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

    /* Wake processes whose sleep deadline has expired */
    uint64_t now_ticks = arch_timer_get_ticks();
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        struct process *p = &proc_table[i];
        uint64_t dl = __atomic_load_n(&p->sleep_deadline, __ATOMIC_ACQUIRE);
        if (dl != 0 && dl <= now_ticks && p->state == PROC_SLEEPING) {
            proc_wakeup(p);
        }
    }
}

int sched_setnice(struct process *p, int nice) {
    if (!p) return -1;
    nice = (nice < NICE_MIN) ? NICE_MIN : (nice > NICE_MAX) ? NICE_MAX : nice;

    struct cfs_rq *rq = &cpu_data[p->se.cpu].runqueue;
    bool state = arch_irq_save();
    spin_lock(&rq->lock);
    bool on_rq = p->se.on_rq;
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
int sched_cpu_count(void) { return nr_cpus_online; }
void sched_set_steal_enabled(bool enabled) {
    __atomic_store_n(&sched_steal_enabled, enabled, __ATOMIC_RELEASE);
}
void sched_cpu_online(int cpu) {
    if (cpu >= 0 && cpu < CONFIG_MAX_CPUS && cpu >= nr_cpus_online)
        nr_cpus_online = cpu + 1;
}
struct percpu_data *sched_cpu_data(int cpu) {
    return (cpu < 0 || cpu >= CONFIG_MAX_CPUS) ? NULL : &cpu_data[cpu];
}

void sched_fork(struct process *child, struct process *parent) {
    sched_entity_init(&child->se);
    child->se.vruntime = parent->se.vruntime;
    child->se.nice = parent->se.nice;
}
