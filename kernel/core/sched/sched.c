/**
 * sched.c - Simple Round-Robin Scheduler
 *
 * Phase 3 uses a simple round-robin scheduler.
 * CFS (Completely Fair Scheduler) will be implemented in Phase 4.
 */

#include <kairos/types.h>
#include <kairos/sched.h>
#include <kairos/process.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/config.h>

/* Run queue - simple linked list for round-robin */
static struct list_head runqueue = LIST_HEAD_INIT(runqueue);
static spinlock_t runqueue_lock = SPINLOCK_INIT;
static uint32_t nr_running = 0;

/* Per-CPU data (single CPU for now) */
static struct percpu_data cpu0_data;

/* Nice to weight table (for future CFS) */
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

/**
 * sched_init - Initialize scheduler
 */
void sched_init(void)
{
    INIT_LIST_HEAD(&runqueue);
    spin_init(&runqueue_lock);
    nr_running = 0;

    /* Initialize CPU 0 data */
    cpu0_data.cpu_id = 0;
    cpu0_data.curr_proc = NULL;
    cpu0_data.idle_proc = NULL;
    cpu0_data.ticks = 0;
    cpu0_data.resched_needed = false;

    pr_info("Scheduler: initialized (round-robin)\n");
}

/**
 * arch_get_percpu - Get per-CPU data
 */
struct percpu_data *arch_get_percpu(void)
{
    return &cpu0_data;
}

/**
 * sched_enqueue - Add process to run queue
 */
void sched_enqueue(struct process *p)
{
    if (!p || p->on_rq) {
        return;
    }

    spin_lock(&runqueue_lock);

    list_add_tail(&p->sched_list, &runqueue);
    p->on_rq = true;
    nr_running++;

    spin_unlock(&runqueue_lock);
}

/**
 * sched_dequeue - Remove process from run queue
 */
void sched_dequeue(struct process *p)
{
    if (!p || !p->on_rq) {
        return;
    }

    spin_lock(&runqueue_lock);

    list_del(&p->sched_list);
    INIT_LIST_HEAD(&p->sched_list);
    p->on_rq = false;
    nr_running--;

    spin_unlock(&runqueue_lock);
}

/**
 * pick_next_task - Select next process to run
 *
 * Simple round-robin: pick first from queue.
 */
static struct process *pick_next_task(void)
{
    struct process *next = NULL;

    if (list_empty(&runqueue)) {
        return proc_idle();
    }

    /* Get first runnable process */
    next = list_first_entry(&runqueue, struct process, sched_list);

    /* Move to end of queue (round-robin) */
    list_del(&next->sched_list);
    list_add_tail(&next->sched_list, &runqueue);

    return next;
}

/**
 * schedule - Main scheduler entry point
 *
 * Picks next process and switches to it.
 */
void schedule(void)
{
    struct process *prev = proc_current();
    struct process *next;
    bool irq_state;

    /* Disable interrupts during scheduling */
    irq_state = arch_irq_save();

    spin_lock(&runqueue_lock);

    /* If current process is still runnable and not the idle process,
     * keep it in the run queue */
    if (prev && prev->state == PROC_RUNNING && prev != proc_idle()) {
        prev->state = PROC_RUNNABLE;
        /* Already in queue from round-robin rotation */
    }

    /* Pick next process */
    next = pick_next_task();

    spin_unlock(&runqueue_lock);

    /* Switch if different process */
    if (next != prev) {
        next->state = PROC_RUNNING;
        cpu0_data.curr_proc = next;
        proc_set_current(next);

        if (prev && prev->context && next->context) {
            arch_context_switch(prev->context, next->context);
        }
    }

    arch_irq_restore(irq_state);
}

/**
 * sched_tick - Called on each timer tick
 */
void sched_tick(void)
{
    struct process *p = proc_current();

    cpu0_data.ticks++;

    if (!p || p == proc_idle()) {
        cpu0_data.resched_needed = true;
        return;
    }

    /* Update runtime */
    p->stime++;

    /* Simple time slice: reschedule every TIMESLICE_MS */
    if (cpu0_data.ticks % (CONFIG_HZ * CONFIG_TIMESLICE_MS / 1000) == 0) {
        cpu0_data.resched_needed = true;
    }
}

/**
 * sched_setnice - Set process nice value
 */
int sched_setnice(struct process *p, int nice)
{
    if (nice < NICE_MIN) {
        nice = NICE_MIN;
    }
    if (nice > NICE_MAX) {
        nice = NICE_MAX;
    }

    p->nice = nice;
    return 0;
}

/**
 * sched_getnice - Get process nice value
 */
int sched_getnice(struct process *p)
{
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
