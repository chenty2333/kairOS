/**
 * sched.c - CFS (Completely Fair Scheduler) Implementation
 *
 * Phase 4: Implements the Completely Fair Scheduler using a red-black
 * tree to maintain runnable processes sorted by vruntime.
 *
 * Phase 4.3: SMP support with per-CPU run queues.
 */

#include <kairos/sched.h>
#include <kairos/process.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/config.h>
#include <kairos/rbtree.h>

/*
 * CFS Scheduler Tunables
 */
#define SCHED_LATENCY_NS        6000000UL       /* 6ms - target latency */
#define SCHED_MIN_GRANULARITY   750000UL        /* 0.75ms - min timeslice */
#define SCHED_WAKEUP_GRANULARITY 1000000UL      /* 1ms - wakeup preemption */

/* Convert ticks to nanoseconds (assuming CONFIG_HZ = 100) */
#define TICK_NS                 (1000000000UL / CONFIG_HZ)

/*
 * Nice to weight table (from Linux kernel)
 */
const int sched_nice_to_weight[40] = {
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */  9548,  7620,  6100,  4904,  3906,
    /*  -5 */  3121,  2501,  1991,  1586,  1277,
    /*   0 */  1024,   820,   655,   526,   423,
    /*   5 */   335,   272,   215,   172,   137,
    /*  10 */   110,    87,    70,    56,    45,
    /*  15 */    36,    29,    23,    18,    15,
};

/*
 * Per-CPU data array
 */
static struct percpu_data cpu_data[CONFIG_MAX_CPUS];
static int nr_cpus_online = 1;  /* Number of online CPUs */

/*
 * Global scheduler lock (protects cross-CPU operations)
 */
static spinlock_t sched_lock = SPINLOCK_INIT;

/*
 * Helper: get current CPU's per-CPU data
 */
static inline struct percpu_data *this_cpu_data(void)
{
    return &cpu_data[arch_cpu_id()];
}

/*
 * Helper: get current CPU's run queue
 */
static inline struct cfs_rq *this_rq_local(void)
{
    return &cpu_data[arch_cpu_id()].runqueue;
}

/**
 * __sched_weight - Get weight for a nice value
 */
static inline int __sched_weight(int nice)
{
    int index = nice - NICE_MIN;
    if (index < 0) {
        index = 0;
    }
    if (index > 39) {
        index = 39;
    }
    return sched_nice_to_weight[index];
}

/**
 * calc_delta_fair - Calculate weighted vruntime delta
 */
static uint64_t calc_delta_fair(uint64_t delta, int weight)
{
    if (weight <= 0) {
        weight = NICE_0_WEIGHT;
    }
    return (delta * NICE_0_WEIGHT) / weight;
}

/**
 * update_min_vruntime - Update the minimum vruntime baseline
 */
static void update_min_vruntime(struct cfs_rq *rq)
{
    uint64_t vruntime = rq->min_vruntime;
    struct rb_node *leftmost;

    if (rq->curr) {
        if (rq->curr->vruntime > vruntime) {
            vruntime = rq->curr->vruntime;
        }
    }

    leftmost = rb_first(&rq->tasks_timeline);
    if (leftmost) {
        struct process *p = rb_entry(leftmost, struct process, sched_node);
        if (p->vruntime < vruntime) {
            vruntime = p->vruntime;
        }
    }

    if (vruntime > rq->min_vruntime) {
        rq->min_vruntime = vruntime;
    }
}

/**
 * __enqueue_entity - Insert a process into the RB tree
 */
static void __enqueue_entity(struct cfs_rq *rq, struct process *p)
{
    struct rb_node **link = &rq->tasks_timeline.rb_node;
    struct rb_node *parent = NULL;
    struct process *entry;
    
    pr_debug("__enqueue_entity: starting for pid %d\n", p->pid);

    while (*link) {
        parent = *link;
        entry = rb_entry(parent, struct process, sched_node);

        if (p->vruntime < entry->vruntime) {
            link = &parent->rb_left;
        } else {
            link = &parent->rb_right;
        }
    }
    
    pr_debug("__enqueue_entity: linking node\n");

    rb_link_node(&p->sched_node, parent, link);
    rb_insert_color(&p->sched_node, &rq->tasks_timeline);
    
    pr_debug("__enqueue_entity: done\n");
}

/**
 * __dequeue_entity - Remove a process from the RB tree
 */
static void __dequeue_entity(struct cfs_rq *rq, struct process *p)
{
    rb_erase(&p->sched_node, &rq->tasks_timeline);
}

/**
 * __pick_first_entity - Get the leftmost (smallest vruntime) process
 */
static struct process *__pick_first_entity(struct cfs_rq *rq)
{
    struct rb_node *left = rb_first(&rq->tasks_timeline);
    if (!left) {
        return NULL;
    }
    return rb_entry(left, struct process, sched_node);
}

/**
 * update_curr - Update the current process's vruntime
 */
static void update_curr(struct cfs_rq *rq)
{
    struct process *curr = rq->curr;
    uint64_t now, delta_exec;

    if (!curr || curr == rq->idle) {
        return;
    }

    now = arch_timer_ticks() * TICK_NS;
    delta_exec = now - curr->last_run_time;

    if ((int64_t)delta_exec <= 0) {
        return;
    }

    curr->vruntime += calc_delta_fair(delta_exec, __sched_weight(curr->nice));
    curr->last_run_time = now;
    curr->stime++;

    update_min_vruntime(rq);
}

/**
 * place_entity - Set initial vruntime for a new/woken task
 */
static void place_entity(struct cfs_rq *rq, struct process *p, bool initial)
{
    uint64_t vruntime = rq->min_vruntime;

    if (initial) {
        vruntime += calc_delta_fair(SCHED_LATENCY_NS, __sched_weight(p->nice));
    }

    if (p->vruntime < vruntime) {
        p->vruntime = vruntime;
    }
}

/**
 * check_preempt_tick - Check if current task should be preempted
 */
static bool check_preempt_tick(struct cfs_rq *rq)
{
    struct process *curr = rq->curr;
    struct process *next;
    uint64_t ideal_runtime, delta_exec;

    if (!curr || curr == rq->idle) {
        return rq->nr_running > 0;
    }

    if (rq->nr_running > 0) {
        ideal_runtime = SCHED_LATENCY_NS / rq->nr_running;
        if (ideal_runtime < SCHED_MIN_GRANULARITY) {
            ideal_runtime = SCHED_MIN_GRANULARITY;
        }
    } else {
        ideal_runtime = SCHED_LATENCY_NS;
    }

    delta_exec = (arch_timer_ticks() * TICK_NS) - curr->last_run_time;
    if (delta_exec > ideal_runtime) {
        return true;
    }

    next = __pick_first_entity(rq);
    if (next && (int64_t)(curr->vruntime - next->vruntime) > (int64_t)SCHED_WAKEUP_GRANULARITY) {
        return true;
    }

    return false;
}

/**
 * sched_cpu_data - Get per-CPU data for a specific CPU
 */
struct percpu_data *sched_cpu_data(int cpu)
{
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS) {
        return NULL;
    }
    return &cpu_data[cpu];
}

/**
 * sched_init_cpu - Initialize scheduler for a specific CPU
 */
void sched_init_cpu(int cpu)
{
    struct percpu_data *data = &cpu_data[cpu];

    data->cpu_id = cpu;
    data->runqueue.tasks_timeline = RB_ROOT;
    data->runqueue.min_vruntime = 0;
    data->runqueue.nr_running = 0;
    data->runqueue.curr = NULL;
    data->runqueue.idle = NULL;
    spin_init(&data->runqueue.lock);
    data->curr_proc = NULL;
    data->idle_proc = NULL;
    data->ticks = 0;
    data->resched_needed = false;

    pr_info("CPU %d: scheduler initialized\n", cpu);
}

/**
 * sched_init - Initialize the CFS scheduler (called on boot CPU)
 */
void sched_init(void)
{
    int boot_cpu = arch_cpu_id();

    spin_init(&sched_lock);

    /* Initialize boot CPU */
    sched_init_cpu(boot_cpu);
    sched_cpu_online(boot_cpu);

    pr_info("Scheduler: initialized (CFS, boot CPU %d, max %d CPUs)\n",
            boot_cpu, CONFIG_MAX_CPUS);
}

/**
 * arch_get_percpu - Get per-CPU data for current CPU
 */
struct percpu_data *arch_get_percpu(void)
{
    return this_cpu_data();
}

/**
 * sched_enqueue - Add a process to the run queue
 */
void sched_enqueue(struct process *p)
{
    struct cfs_rq *rq;
    bool irq_state;
    int cpu;

    if (!p || p->on_rq) {
        return;
    }

    irq_state = arch_irq_save();
    spin_lock(&sched_lock);
    
    pr_debug("sched_enqueue: enqueuing pid %d\n", p->pid);

    /* Use process's preferred CPU, or current CPU */
    cpu = (p->cpu >= 0 && p->cpu < nr_cpus_online) ? p->cpu : arch_cpu_id();
    rq = &cpu_data[cpu].runqueue;

    if (p->vruntime == 0) {
        place_entity(rq, p, true);
    } else {
        place_entity(rq, p, false);
    }

    __enqueue_entity(rq, p);
    p->on_rq = true;
    p->cpu = cpu;
    rq->nr_running++;

    update_min_vruntime(rq);

    /* If enqueued on a different CPU, send an IPI to trigger rescheduling */
    if (cpu != arch_cpu_id()) {
        arch_send_ipi(cpu, IPI_RESCHEDULE);
    }

    spin_unlock(&sched_lock);
    arch_irq_restore(irq_state);
}

/**
 * sched_dequeue - Remove a process from the run queue
 */
void sched_dequeue(struct process *p)
{
    struct cfs_rq *rq;
    bool irq_state;

    if (!p || !p->on_rq) {
        return;
    }

    irq_state = arch_irq_save();
    spin_lock(&sched_lock);

    rq = &cpu_data[p->cpu].runqueue;

    __dequeue_entity(rq, p);
    p->on_rq = false;
    rq->nr_running--;

    update_min_vruntime(rq);

    spin_unlock(&sched_lock);
    arch_irq_restore(irq_state);
}

/**
 * pick_next_task - Select the next process to run on current CPU
 */
static struct process *pick_next_task(void)
{
    struct cfs_rq *rq = this_rq_local();
    struct process *next;

    next = __pick_first_entity(rq);
    if (!next) {
        return this_cpu_data()->idle_proc;
    }

    return next;
}

/**
 * put_prev_task - Called when switching away from a task
 */
static void put_prev_task(struct process *p)
{
    struct cfs_rq *rq = this_rq_local();

    if (!p || p == this_cpu_data()->idle_proc) {
        return;
    }

    update_curr(rq);

    if (p->state == PROC_RUNNING) {
        p->state = PROC_RUNNABLE;
        if (!p->on_rq) {
            __enqueue_entity(rq, p);
            p->on_rq = true;
            rq->nr_running++;
        }
    } else if (p->state == PROC_SLEEPING || p->state == PROC_ZOMBIE) {
        /* Process is sleeping or exiting - must be removed from runqueue */
        if (p->on_rq) {
            __dequeue_entity(rq, p);
            p->on_rq = false;
            rq->nr_running--;
        }
    }
}

/**
 * set_next_task - Called when switching to a task
 */
static void set_next_task(struct process *p)
{
    struct cfs_rq *rq = this_rq_local();

    if (!p || p == this_cpu_data()->idle_proc) {
        return;
    }

    if (p->on_rq) {
        __dequeue_entity(rq, p);
        p->on_rq = false;
        rq->nr_running--;
    }

    p->last_run_time = arch_timer_ticks() * TICK_NS;
    rq->curr = p;
}

/**
 * schedule - Main scheduler entry point
 */
void schedule(void)
{
    struct percpu_data *cpu = this_cpu_data();
    struct process *prev = proc_current();
    struct process *next;
    bool irq_state;

    irq_state = arch_irq_save();
    spin_lock(&sched_lock);

    cpu->resched_needed = false;

    put_prev_task(prev);
    next = pick_next_task();

    /* No task to run (no idle process on this CPU) - just return */
    if (!next) {
        spin_unlock(&sched_lock);
        arch_irq_restore(irq_state);
        return;
    }

    if (next != prev) {
        set_next_task(next);
        next->state = PROC_RUNNING;
        cpu->curr_proc = next;
        proc_set_current(next);

        /* Switch address space if needed */
        if (next->mm) {
            arch_mmu_switch(next->mm->pgdir);
        }

        spin_unlock(&sched_lock);

        if (prev && prev->context && next->context) {
            arch_context_switch(prev->context, next->context);
        }

        spin_lock(&sched_lock);
    }

    spin_unlock(&sched_lock);
    arch_irq_restore(irq_state);
}

/**
 * sched_tick - Called on each timer tick
 */
void sched_tick(void)
{
    struct percpu_data *cpu = this_cpu_data();
    struct cfs_rq *rq = &cpu->runqueue;
    struct process *curr = proc_current();

    cpu->ticks++;

    spin_lock(&sched_lock);

    if (curr && curr != cpu->idle_proc) {
        rq->curr = curr;
        update_curr(rq);
    }

    if (check_preempt_tick(rq)) {
        cpu->resched_needed = true;
    }

    spin_unlock(&sched_lock);
}

/**
 * sched_setnice - Set process nice value
 */
int sched_setnice(struct process *p, int nice)
{
    bool irq_state;
    struct cfs_rq *rq;
    bool on_rq;

    if (!p) {
        return -1;
    }

    if (nice < NICE_MIN) {
        nice = NICE_MIN;
    }
    if (nice > NICE_MAX) {
        nice = NICE_MAX;
    }

    irq_state = arch_irq_save();
    spin_lock(&sched_lock);

    rq = &cpu_data[p->cpu >= 0 ? p->cpu : 0].runqueue;
    on_rq = p->on_rq;

    if (on_rq) {
        __dequeue_entity(rq, p);
        rq->nr_running--;
    }

    p->nice = nice;

    if (on_rq) {
        __enqueue_entity(rq, p);
        rq->nr_running++;
    }

    spin_unlock(&sched_lock);
    arch_irq_restore(irq_state);

    return 0;
}

/**
 * sched_getnice - Get process nice value
 */
int sched_getnice(struct process *p)
{
    if (!p) {
        return 0;
    }
    return p->nice;
}

/**
 * sched_cpu_id - Get current CPU ID
 */
int sched_cpu_id(void)
{
    return arch_cpu_id();
}

/**
 * sched_cpu_rq - Get current CPU's run queue
 */
struct cfs_rq *sched_cpu_rq(void)
{
    return this_rq_local();
}

/**
 * sched_rq - Get run queue for specific CPU
 */
struct cfs_rq *sched_rq(int cpu)
{
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS) {
        cpu = 0;
    }
    return &cpu_data[cpu].runqueue;
}

/**
 * sched_need_resched - Check if rescheduling is needed
 */
bool sched_need_resched(void)
{
    return this_cpu_data()->resched_needed;
}

/**
 * sched_set_idle - Set the idle process for current CPU
 */
void sched_set_idle(struct process *p)
{
    struct percpu_data *cpu = this_cpu_data();
    cpu->idle_proc = p;
    cpu->runqueue.idle = p;
}

/**
 * sched_cpu_count - Get number of online CPUs
 */
int sched_cpu_count(void)
{
    return nr_cpus_online;
}

/**
 * sched_cpu_online - Mark a CPU as online
 */
void sched_cpu_online(int cpu)
{
    if (cpu >= 0 && cpu < CONFIG_MAX_CPUS) {
        if (cpu >= nr_cpus_online) {
            nr_cpus_online = cpu + 1;
        }
    }
}
