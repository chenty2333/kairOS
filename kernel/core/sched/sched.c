/**
 * sched.c - CFS (Completely Fair Scheduler) Implementation
 *
 * Phase 4: Implements the Completely Fair Scheduler using a red-black
 * tree to maintain runnable processes sorted by vruntime.
 *
 * Key concepts:
 * - vruntime: Virtual runtime, increases slower for high-priority tasks
 * - min_vruntime: Baseline for new tasks to prevent starvation
 * - RB tree: Processes ordered by vruntime, leftmost = next to run
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
 * Higher weight = more CPU time
 * nice -20 → weight 88761 (highest priority)
 * nice   0 → weight  1024 (default)
 * nice +19 → weight    15 (lowest priority)
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
 * Per-CPU data (single CPU for now, will be extended in Phase 4.3)
 */
static struct percpu_data cpu0_data;

/*
 * Global scheduler lock (for single CPU; per-CPU locks in SMP)
 */
static spinlock_t sched_lock = SPINLOCK_INIT;

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
 * @delta: Actual execution time in nanoseconds
 * @weight: Process weight
 *
 * vruntime = delta * NICE_0_WEIGHT / weight
 * Higher weight processes accumulate vruntime slower.
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
 * @rq: The run queue
 *
 * min_vruntime is monotonically increasing and serves as the baseline
 * for new tasks. It's the maximum of:
 * - Current min_vruntime
 * - Current task's vruntime
 * - Leftmost task's vruntime
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

    /* min_vruntime only increases */
    if (vruntime > rq->min_vruntime) {
        rq->min_vruntime = vruntime;
    }
}

/**
 * __enqueue_entity - Insert a process into the RB tree
 * @rq: The run queue
 * @p: The process to insert
 */
static void __enqueue_entity(struct cfs_rq *rq, struct process *p)
{
    struct rb_node **link = &rq->tasks_timeline.rb_node;
    struct rb_node *parent = NULL;
    struct process *entry;
    bool leftmost = true;

    /* Find the right place in the tree */
    while (*link) {
        parent = *link;
        entry = rb_entry(parent, struct process, sched_node);

        if (p->vruntime < entry->vruntime) {
            link = &parent->rb_left;
        } else {
            link = &parent->rb_right;
            leftmost = false;
        }
    }

    /* Add new node and rebalance */
    rb_link_node(&p->sched_node, parent, link);
    rb_insert_color(&p->sched_node, &rq->tasks_timeline);

    (void)leftmost;  /* Could cache leftmost for O(1) access */
}

/**
 * __dequeue_entity - Remove a process from the RB tree
 * @rq: The run queue
 * @p: The process to remove
 */
static void __dequeue_entity(struct cfs_rq *rq, struct process *p)
{
    rb_erase(&p->sched_node, &rq->tasks_timeline);
}

/**
 * __pick_first_entity - Get the leftmost (smallest vruntime) process
 * @rq: The run queue
 *
 * Returns NULL if the tree is empty.
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
 * @rq: The run queue
 *
 * Called on timer tick to account for execution time.
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

    /* Update vruntime */
    curr->vruntime += calc_delta_fair(delta_exec, __sched_weight(curr->nice));
    curr->last_run_time = now;

    /* Update statistics */
    curr->stime++;

    /* Update min_vruntime */
    update_min_vruntime(rq);
}

/**
 * place_entity - Set initial vruntime for a new/woken task
 * @rq: The run queue
 * @p: The process
 * @initial: True if this is a new process
 */
static void place_entity(struct cfs_rq *rq, struct process *p, bool initial)
{
    uint64_t vruntime = rq->min_vruntime;

    if (initial) {
        /* New tasks start slightly behind to avoid immediate preemption */
        vruntime += calc_delta_fair(SCHED_LATENCY_NS, __sched_weight(p->nice));
    }

    /* Don't let vruntime go backward */
    if (p->vruntime < vruntime) {
        p->vruntime = vruntime;
    }
}

/**
 * check_preempt_tick - Check if current task should be preempted
 * @rq: The run queue
 *
 * Returns true if preemption is needed.
 */
static bool check_preempt_tick(struct cfs_rq *rq)
{
    struct process *curr = rq->curr;
    struct process *next;
    uint64_t ideal_runtime, delta_exec;

    if (!curr || curr == rq->idle) {
        return rq->nr_running > 0;
    }

    /* Calculate ideal runtime based on number of tasks */
    if (rq->nr_running > 0) {
        ideal_runtime = SCHED_LATENCY_NS / rq->nr_running;
        if (ideal_runtime < SCHED_MIN_GRANULARITY) {
            ideal_runtime = SCHED_MIN_GRANULARITY;
        }
    } else {
        ideal_runtime = SCHED_LATENCY_NS;
    }

    /* Check if current has run long enough */
    delta_exec = (arch_timer_ticks() * TICK_NS) - curr->last_run_time;
    if (delta_exec > ideal_runtime) {
        return true;
    }

    /* Check if there's a task with significantly smaller vruntime */
    next = __pick_first_entity(rq);
    if (next && (int64_t)(curr->vruntime - next->vruntime) > (int64_t)SCHED_WAKEUP_GRANULARITY) {
        return true;
    }

    return false;
}

/**
 * sched_init - Initialize the CFS scheduler
 */
void sched_init(void)
{
    spin_init(&sched_lock);

    /* Initialize CPU 0 run queue */
    cpu0_data.cpu_id = 0;
    cpu0_data.runqueue.tasks_timeline = RB_ROOT;
    cpu0_data.runqueue.min_vruntime = 0;
    cpu0_data.runqueue.nr_running = 0;
    cpu0_data.runqueue.curr = NULL;
    cpu0_data.runqueue.idle = NULL;
    spin_init(&cpu0_data.runqueue.lock);
    cpu0_data.curr_proc = NULL;
    cpu0_data.idle_proc = NULL;
    cpu0_data.ticks = 0;
    cpu0_data.resched_needed = false;

    pr_info("Scheduler: initialized (CFS)\n");
}

/**
 * arch_get_percpu - Get per-CPU data for current CPU
 */
struct percpu_data *arch_get_percpu(void)
{
    return &cpu0_data;
}

/**
 * sched_enqueue - Add a process to the run queue
 * @p: The process to enqueue
 */
void sched_enqueue(struct process *p)
{
    struct cfs_rq *rq;
    bool irq_state;

    if (!p || p->on_rq) {
        return;
    }

    irq_state = arch_irq_save();
    spin_lock(&sched_lock);

    rq = &cpu0_data.runqueue;

    /* Set initial vruntime for new tasks */
    if (p->vruntime == 0) {
        place_entity(rq, p, true);
    } else {
        place_entity(rq, p, false);
    }

    /* Insert into RB tree */
    __enqueue_entity(rq, p);
    p->on_rq = true;
    rq->nr_running++;

    /* Update baseline */
    update_min_vruntime(rq);

    spin_unlock(&sched_lock);
    arch_irq_restore(irq_state);
}

/**
 * sched_dequeue - Remove a process from the run queue
 * @p: The process to dequeue
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

    rq = &cpu0_data.runqueue;

    /* Remove from RB tree */
    __dequeue_entity(rq, p);
    p->on_rq = false;
    rq->nr_running--;

    /* Update baseline */
    update_min_vruntime(rq);

    spin_unlock(&sched_lock);
    arch_irq_restore(irq_state);
}

/**
 * pick_next_task - Select the next process to run
 *
 * Returns the process with the smallest vruntime (leftmost in RB tree),
 * or the idle process if the queue is empty.
 */
static struct process *pick_next_task(void)
{
    struct cfs_rq *rq = &cpu0_data.runqueue;
    struct process *next;

    next = __pick_first_entity(rq);
    if (!next) {
        return proc_idle();
    }

    return next;
}

/**
 * put_prev_task - Called when switching away from a task
 * @p: The previous task
 */
static void put_prev_task(struct process *p)
{
    struct cfs_rq *rq = &cpu0_data.runqueue;

    if (!p || p == proc_idle()) {
        return;
    }

    /* Update vruntime before putting back */
    update_curr(rq);

    /* If still runnable, put back in the tree */
    if (p->state == PROC_RUNNING) {
        p->state = PROC_RUNNABLE;
        if (!p->on_rq) {
            __enqueue_entity(rq, p);
            p->on_rq = true;
            rq->nr_running++;
        }
    }
}

/**
 * set_next_task - Called when switching to a task
 * @p: The next task
 */
static void set_next_task(struct process *p)
{
    struct cfs_rq *rq = &cpu0_data.runqueue;

    if (!p || p == proc_idle()) {
        return;
    }

    /* Remove from tree while running */
    if (p->on_rq) {
        __dequeue_entity(rq, p);
        p->on_rq = false;
        rq->nr_running--;
    }

    /* Record start time */
    p->last_run_time = arch_timer_ticks() * TICK_NS;
    rq->curr = p;
}

/**
 * schedule - Main scheduler entry point
 *
 * Called to potentially switch to a different process.
 */
void schedule(void)
{
    struct process *prev = proc_current();
    struct process *next;
    bool irq_state;

    irq_state = arch_irq_save();
    spin_lock(&sched_lock);

    /* Clear reschedule flag */
    cpu0_data.resched_needed = false;

    /* Update current task's vruntime and put it back */
    put_prev_task(prev);

    /* Pick next task to run */
    next = pick_next_task();

    /* Switch if different */
    if (next != prev) {
        set_next_task(next);
        next->state = PROC_RUNNING;
        cpu0_data.curr_proc = next;
        proc_set_current(next);

        spin_unlock(&sched_lock);

        if (prev && prev->context && next->context) {
            arch_context_switch(prev->context, next->context);
        }

        /* After context switch, we're back - re-acquire lock for restore */
        spin_lock(&sched_lock);
    }

    spin_unlock(&sched_lock);
    arch_irq_restore(irq_state);
}

/**
 * sched_tick - Called on each timer tick
 *
 * Updates current task's vruntime and checks for preemption.
 * Note: Called from timer interrupt handler, interrupts already disabled.
 */
void sched_tick(void)
{
    struct cfs_rq *rq = &cpu0_data.runqueue;
    struct process *curr = proc_current();

    cpu0_data.ticks++;

    spin_lock(&sched_lock);

    /* Update current task's runtime */
    if (curr && curr != proc_idle()) {
        rq->curr = curr;
        update_curr(rq);
    }

    /* Check if preemption is needed */
    if (check_preempt_tick(rq)) {
        cpu0_data.resched_needed = true;
    }

    spin_unlock(&sched_lock);
}

/**
 * sched_setnice - Set process nice value
 * @p: The process
 * @nice: New nice value (-20 to +19)
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

    rq = &cpu0_data.runqueue;
    on_rq = p->on_rq;

    /* If on run queue, dequeue first */
    if (on_rq) {
        __dequeue_entity(rq, p);
        rq->nr_running--;
    }

    /* Update nice value */
    p->nice = nice;

    /* Re-enqueue with updated priority */
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
    return 0;  /* Single CPU for now */
}

/**
 * sched_cpu_rq - Get current CPU's run queue
 */
struct cfs_rq *sched_cpu_rq(void)
{
    return &cpu0_data.runqueue;
}

/**
 * sched_rq - Get run queue for specific CPU
 */
struct cfs_rq *sched_rq(int cpu)
{
    (void)cpu;
    return &cpu0_data.runqueue;
}

/**
 * sched_need_resched - Check if rescheduling is needed
 */
bool sched_need_resched(void)
{
    return cpu0_data.resched_needed;
}

/**
 * sched_set_idle - Set the idle process for this CPU
 * @p: The idle process
 */
void sched_set_idle(struct process *p)
{
    cpu0_data.idle_proc = p;
    cpu0_data.runqueue.idle = p;
}
