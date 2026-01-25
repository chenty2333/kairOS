/**
 * kernel/core/sched/sched.c - CFS (Completely Fair Scheduler) Implementation
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
#define SCHED_MIN_GRANULARITY 750000UL
#define SCHED_WAKEUP_GRANULARITY 1000000UL
#define TICK_NS (1000000000UL / CONFIG_HZ)

const int sched_nice_to_weight[40] = {
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
    9548,  7620,  6100,  4904,  3906,  3121,  2501,  1991,  1586,  1277,
    1024,  820,   655,   526,   423,   335,   272,   215,   172,   137,
    110,   87,    70,    56,    45,    36,    29,    23,    18,    15,
};

struct percpu_data cpu_data[CONFIG_MAX_CPUS];
static int nr_cpus_online = 1;
static spinlock_t sched_lock = SPINLOCK_INIT;

static inline int __weight(int nice) {
    int idx = (nice < NICE_MIN) ? 0 : (nice > NICE_MAX) ? 39 : nice - NICE_MIN;
    return sched_nice_to_weight[idx];
}

static uint64_t calc_delta_fair(uint64_t delta, int weight) {
    return (delta * NICE_0_WEIGHT) / (weight > 0 ? weight : NICE_0_WEIGHT);
}

static void update_min_vruntime(struct cfs_rq *rq) {
    uint64_t v = rq->min_vruntime;
    if (rq->curr && rq->curr != rq->idle && rq->curr->vruntime > v)
        v = rq->curr->vruntime;
    struct rb_node *left = rb_first(&rq->tasks_timeline);
    if (left) {
        struct process *p = rb_entry(left, struct process, sched_node);
        if (p->vruntime < v)
            v = p->vruntime;
    }
    if (v > rq->min_vruntime)
        rq->min_vruntime = v;
}

static void __enqueue_entity(struct cfs_rq *rq, struct process *p) {
    struct rb_node **link = &rq->tasks_timeline.rb_node, *parent = NULL;
    while (*link) {
        parent = *link;
        if (p->vruntime <
            rb_entry(parent, struct process, sched_node)->vruntime)
            link = &parent->rb_left;
        else
            link = &parent->rb_right;
    }
    rb_link_node(&p->sched_node, parent, link);
    rb_insert_color(&p->sched_node, &rq->tasks_timeline);
}

static void update_curr(struct cfs_rq *rq) {
    struct process *curr = rq->curr;
    if (!curr || curr == rq->idle)
        return;

    uint64_t now = arch_timer_ticks() * TICK_NS;
    uint64_t delta =
        (now > curr->last_run_time) ? now - curr->last_run_time : 0;
    if (delta == 0)
        return;

    curr->vruntime += calc_delta_fair(delta, __weight(curr->nice));
    curr->last_run_time = now;
    curr->stime++;
    update_min_vruntime(rq);
}

static void place_entity(struct cfs_rq *rq, struct process *p, bool initial) {
    uint64_t v = rq->min_vruntime;
    if (initial)
        v += calc_delta_fair(SCHED_LATENCY_NS, __weight(p->nice));
    if (p->vruntime < v)
        p->vruntime = v;
}

static bool check_preempt(struct cfs_rq *rq) {
    struct process *curr = rq->curr;
    if (!curr || curr == rq->idle)
        return rq->nr_running > 0;

    uint64_t ideal =
        SCHED_LATENCY_NS / (rq->nr_running > 0 ? rq->nr_running : 1);
    if (ideal < SCHED_MIN_GRANULARITY)
        ideal = SCHED_MIN_GRANULARITY;

    if ((arch_timer_ticks() * TICK_NS) - curr->last_run_time > ideal)
        return true;

    struct rb_node *left = rb_first(&rq->tasks_timeline);
    if (left) {
        struct process *next = rb_entry(left, struct process, sched_node);
        if ((int64_t)(curr->vruntime - next->vruntime) >
            (int64_t)SCHED_WAKEUP_GRANULARITY)
            return true;
    }
    return false;
}

void sched_init_cpu(int cpu) {
    struct percpu_data *d = &cpu_data[cpu];
    memset(d, 0, sizeof(*d));
    d->cpu_id = cpu;
    d->runqueue.tasks_timeline = RB_ROOT;
    spin_init(&d->runqueue.lock);
    spin_init(&d->ipi_call_lock);
}

void sched_init(void) {
    spin_init(&sched_lock);
    sched_init_cpu(arch_cpu_id());
    sched_cpu_online(arch_cpu_id());
}

static void __sched_enqueue(struct process *p) {
    if (p->on_rq)
        return;
    int cpu = (p->cpu >= 0 && p->cpu < nr_cpus_online) ? p->cpu : arch_cpu_id();
    struct cfs_rq *rq = &cpu_data[cpu].runqueue;

    place_entity(rq, p, p->vruntime == 0);
    __enqueue_entity(rq, p);
    p->on_rq = true;
    p->cpu = cpu;
    rq->nr_running++;
    update_min_vruntime(rq);

    if (cpu != arch_cpu_id())
        arch_send_ipi(cpu, IPI_RESCHEDULE);
}

static void __sched_dequeue(struct process *p) {
    if (!p->on_rq)
        return;
    struct cfs_rq *rq = &cpu_data[p->cpu].runqueue;
    rb_erase(&p->sched_node, &rq->tasks_timeline);
    p->on_rq = false;
    rq->nr_running--;
    update_min_vruntime(rq);
}

void sched_enqueue(struct process *p) {
    if (!p || p->on_rq)
        return;
    bool state = arch_irq_save();
    spin_lock(&sched_lock);
    __sched_enqueue(p);
    spin_unlock(&sched_lock);
    arch_irq_restore(state);
}

void sched_dequeue(struct process *p) {
    if (!p || !p->on_rq)
        return;
    bool state = arch_irq_save();
    spin_lock(&sched_lock);
    __sched_dequeue(p);
    spin_unlock(&sched_lock);
    arch_irq_restore(state);
}

/**
 * sched_steal_task - Try to steal a task from another CPU
 * 
 * Returns a pointer to the stolen process, or NULL if nothing found.
 * Must be called with sched_lock held.
 */
static struct process *sched_steal_task(void) {
    int self = arch_cpu_id();
    
    for (int i = 0; i < nr_cpus_online; i++) {
        if (i == self) continue;
        
        struct cfs_rq *remote_rq = &cpu_data[i].runqueue;
        if (remote_rq->nr_running > 0) {
            struct rb_node *left = rb_first(&remote_rq->tasks_timeline);
            if (left) {
                struct process *p = rb_entry(left, struct process, sched_node);
                
                /* The Heist: Remove from remote queue */
                rb_erase(&p->sched_node, &remote_rq->tasks_timeline);
                p->on_rq = false;
                remote_rq->nr_running--;
                
                /* Update process affinity */
                p->cpu = self;
                
                return p;
            }
        }
    }
    return NULL;
}

void schedule(void) {
    struct percpu_data *cpu = arch_get_percpu();
    struct process *prev = proc_current(), *next;
    struct cfs_rq *rq = &cpu->runqueue;
    bool state = arch_irq_save();

    spin_lock(&sched_lock);
    cpu->resched_needed = false;

    /* 1. Update current task state */
    if (prev && prev != cpu->idle_proc) {
        update_curr(rq);
        if (prev->state == PROC_RUNNING) {
            prev->state = PROC_RUNNABLE;
            __enqueue_entity(rq, prev);
            prev->on_rq = true;
            rq->nr_running++;
        } else if (prev->on_rq) {
            rb_erase(&prev->sched_node, &rq->tasks_timeline);
            prev->on_rq = false;
            rq->nr_running--;
        }
    }

    /* 2. Pick next task */
    struct rb_node *left = rb_first(&rq->tasks_timeline);
    if (left) {
        next = rb_entry(left, struct process, sched_node);
        rb_erase(&next->sched_node, &rq->tasks_timeline);
        next->on_rq = false;
        rq->nr_running--;
    } else {
        /* Local queue is empty - TRY TO STEAL! */
        next = sched_steal_task();
        
        /* If still nothing, fall back to idle */
        if (!next) {
            next = cpu->idle_proc;
        }
    }

    /* 3. Perform the switch */
    if (next != prev) {
        next->last_run_time = arch_timer_ticks() * TICK_NS;
        rq->curr = next;
        next->state = PROC_RUNNING;
        cpu->curr_proc = next;
        proc_set_current(next);

        if (next->mm)
            arch_mmu_switch(next->mm->pgdir);

        spin_unlock(&sched_lock);
        if (prev && prev->context) {
            arch_context_switch(prev->context, next->context);
        }
        spin_lock(&sched_lock);
    } else {
        /* Even if we don't switch, ensure the state is correct */
        next->state = PROC_RUNNING;
        rq->curr = next;
    }

    spin_unlock(&sched_lock);
    arch_irq_restore(state);
}

void sched_tick(void) {
    struct percpu_data *cpu = arch_get_percpu();
    struct cfs_rq *rq = &cpu->runqueue;
    struct process *curr = proc_current();

    cpu->ticks++;
    spin_lock(&sched_lock);
    if (curr && curr != cpu->idle_proc) {
        rq->curr = curr;
        update_curr(rq);
    }
    if (check_preempt(rq))
        cpu->resched_needed = true;
    spin_unlock(&sched_lock);
}

int sched_setnice(struct process *p, int nice) {
    if (!p)
        return -1;
    nice = (nice < NICE_MIN) ? NICE_MIN : (nice > NICE_MAX) ? NICE_MAX : nice;

    bool state = arch_irq_save();
    spin_lock(&sched_lock);
    bool on_rq = p->on_rq;
    if (on_rq)
        __sched_dequeue(p);
    p->nice = nice;
    if (on_rq)
        __sched_enqueue(p);
    spin_unlock(&sched_lock);
    arch_irq_restore(state);
    return 0;
}

int sched_getnice(struct process *p) {
    return p ? p->nice : 0;
}
int sched_cpu_id(void) {
    return arch_cpu_id();
}
struct cfs_rq *sched_cpu_rq(void) {
    return this_rq;
}
struct cfs_rq *sched_rq(int cpu) {
    return &cpu_data[(cpu < 0 || cpu >= CONFIG_MAX_CPUS) ? 0 : cpu].runqueue;
}
bool sched_need_resched(void) {
    return arch_get_percpu()->resched_needed;
}
void sched_set_idle(struct process *p) {
    struct percpu_data *cpu = arch_get_percpu();
    cpu->idle_proc = p;
    cpu->runqueue.idle = p;
}
int sched_cpu_count(void) {
    return nr_cpus_online;
}
void sched_cpu_online(int cpu) {
    if (cpu >= 0 && cpu < CONFIG_MAX_CPUS && cpu >= nr_cpus_online)
        nr_cpus_online = cpu + 1;
}
struct percpu_data *sched_cpu_data(int cpu) {
    return (cpu < 0 || cpu >= CONFIG_MAX_CPUS) ? NULL : &cpu_data[cpu];
}