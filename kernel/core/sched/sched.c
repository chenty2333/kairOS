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
#define TICK_NS (1000000000UL / CONFIG_HZ)

const int sched_nice_to_weight[40] = {
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
    9548,  7620,  6100,  4904,  3906,  3121,  2501,  1991,  1586,  1277,
    1024,  820,   655,   526,   423,   335,   272,   215,   172,   137,
    110,   87,    70,    56,    45,    36,    29,    23,    18,    15,
};

struct percpu_data cpu_data[CONFIG_MAX_CPUS];
static int nr_cpus_online = 1;

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
        if (p->vruntime < v) v = p->vruntime;
    }
    if (v > rq->min_vruntime) rq->min_vruntime = v;
}

static void __enqueue_entity(struct cfs_rq *rq, struct process *p) {
    struct rb_node **link = &rq->tasks_timeline.rb_node, *parent = NULL;
    while (*link) {
        parent = *link;
        if (p->vruntime < rb_entry(parent, struct process, sched_node)->vruntime)
            link = &parent->rb_left;
        else
            link = &parent->rb_right;
    }
    rb_link_node(&p->sched_node, parent, link);
    rb_insert_color(&p->sched_node, &rq->tasks_timeline);
}

static void update_curr(struct cfs_rq *rq) {
    struct process *curr = rq->curr;
    if (!curr || curr == rq->idle) return;

    uint64_t now = arch_timer_ticks() * TICK_NS;
    uint64_t delta = (now > curr->last_run_time) ? now - curr->last_run_time : 0;
    if (delta == 0) return;

    curr->vruntime += calc_delta_fair(delta, __weight(curr->nice));
    curr->last_run_time = now;
    update_min_vruntime(rq);
}

static void place_entity(struct cfs_rq *rq, struct process *p, bool initial) {
    uint64_t v = rq->min_vruntime;
    if (initial) v += calc_delta_fair(SCHED_LATENCY_NS, __weight(p->nice));
    if (p->vruntime < v) p->vruntime = v;
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
        cpu->prev_task->on_cpu = false;
        cpu->prev_task = NULL;
    }
}

void sched_enqueue(struct process *p) {
    if (!p || p->on_rq) return;
    
    /* Find target CPU - currently simple: stay on current or preferred */
    int cpu = (p->cpu >= 0 && p->cpu < nr_cpus_online) ? p->cpu : arch_cpu_id();
    struct cfs_rq *rq = &cpu_data[cpu].runqueue;

    bool state = arch_irq_save();
    spin_lock(&rq->lock);
    
    place_entity(rq, p, p->vruntime == 0);
    __enqueue_entity(rq, p);
    p->on_rq = true;
    p->cpu = cpu;
    p->on_cpu = false; /* Ensure it's marked as not running if it was just created/woken */
    rq->nr_running++;
    update_min_vruntime(rq);

    spin_unlock(&rq->lock);
    
    if (cpu != arch_cpu_id())
        arch_send_ipi(cpu, IPI_RESCHEDULE);
        
    arch_irq_restore(state);
}

void sched_dequeue(struct process *p) {
    if (!p || !p->on_rq) return;
    
    struct cfs_rq *rq = &cpu_data[p->cpu].runqueue;
    bool state = arch_irq_save();
    spin_lock(&rq->lock);
    
    rb_erase(&p->sched_node, &rq->tasks_timeline);
    p->on_rq = false;
    rq->nr_running--;
    update_min_vruntime(rq);
    
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
            struct rb_node *left = rb_first(&remote_rq->tasks_timeline);
            if (left) {
                p = rb_entry(left, struct process, sched_node);
                
                /* CRITICAL: Do not steal a task that is currently running on the remote CPU! */
                if (p->on_cpu) {
                    spin_unlock(&remote_rq->lock);
                    continue;
                }

                rb_erase(&p->sched_node, &remote_rq->tasks_timeline);
                p->on_rq = false;
                remote_rq->nr_running--;
                p->cpu = self_id;
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
        /* Mark prev as currently running on this CPU */
        prev->on_cpu = true;
        
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

    struct rb_node *left = rb_first(&rq->tasks_timeline);
    if (left) {
        next = rb_entry(left, struct process, sched_node);
        rb_erase(&next->sched_node, &rq->tasks_timeline);
        next->on_rq = false;
        rq->nr_running--;
    } else {
        /* Local empty - attempt stealing without holding local lock to simplify */
        spin_unlock(&rq->lock);
        next = sched_steal_task(cpu->cpu_id);
        spin_lock(&rq->lock);
        
        if (!next) next = cpu->idle_proc;
    }

    if (next != prev) {
        next->last_run_time = arch_timer_ticks() * TICK_NS;
        rq->curr = next;
        next->state = PROC_RUNNING;
        next->on_cpu = true; /* Mark next as running to prevent stealing */
        cpu->curr_proc = next;
        proc_set_current(next);

        if (next->mm) arch_mmu_switch(next->mm->pgdir);
        
        /* Update the CPU ID in the next task's context (for tp restoration) */
        if (next->context) arch_context_set_cpu(next->context, cpu->cpu_id);

        /* Store prev for cleanup by next task */
        cpu->prev_task = prev;

        spin_unlock(&rq->lock);
        if (prev && prev->context) arch_context_switch(prev->context, next->context);
        
        /* 
         * Back from switch (as 'next' - now current).
         * Cleanup the task that switched to us (which is cpu->prev_task).
         */
        sched_post_switch_cleanup();
        
        arch_irq_restore(state);
    } else {
        next->state = PROC_RUNNING;
        next->on_cpu = true;
        rq->curr = next;
        if (cpu->prev_task) sched_post_switch_cleanup(); /* Just in case */
        spin_unlock(&rq->lock);
        arch_irq_restore(state);
    }
}

void sched_tick(void) {
    struct percpu_data *cpu = arch_get_percpu();
    struct cfs_rq *rq = &cpu->runqueue;
    struct process *curr = proc_current();

    cpu->ticks++;
    /* We don't necessarily need the lock for simple status check, but safety first */
    if (spin_trylock(&rq->lock)) {
        if (curr && curr != cpu->idle_proc) {
            rq->curr = curr;
            update_curr(rq);
        }
        /* Preemption logic placeholder */
        spin_unlock(&rq->lock);
    }
}

int sched_setnice(struct process *p, int nice) {
    if (!p) return -1;
    nice = (nice < NICE_MIN) ? NICE_MIN : (nice > NICE_MAX) ? NICE_MAX : nice;

    struct cfs_rq *rq = &cpu_data[p->cpu].runqueue;
    bool state = arch_irq_save();
    spin_lock(&rq->lock);
    bool on_rq = p->on_rq;
    if (on_rq) rb_erase(&p->sched_node, &rq->tasks_timeline);
    p->nice = nice;
    if (on_rq) __enqueue_entity(rq, p);
    spin_unlock(&rq->lock);
    arch_irq_restore(state);
    return 0;
}

int sched_getnice(struct process *p) { return p ? p->nice : 0; }
int sched_cpu_id(void) { return arch_cpu_id(); }
struct cfs_rq *sched_cpu_rq(void) { return this_rq; }
bool sched_need_resched(void) { return arch_get_percpu()->resched_needed; }
void sched_set_idle(struct process *p) {
    struct percpu_data *cpu = arch_get_percpu();
    cpu->idle_proc = p;
    cpu->runqueue.idle = p;
}
int sched_cpu_count(void) { return nr_cpus_online; }
void sched_cpu_online(int cpu) {
    if (cpu >= 0 && cpu < CONFIG_MAX_CPUS && cpu >= nr_cpus_online)
        nr_cpus_online = cpu + 1;
}
struct percpu_data *sched_cpu_data(int cpu) {
    return (cpu < 0 || cpu >= CONFIG_MAX_CPUS) ? NULL : &cpu_data[cpu];
}
