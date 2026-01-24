/**
 * kairos/sched.h - CFS Scheduler
 */

#ifndef _KAIROS_SCHED_H
#define _KAIROS_SCHED_H

#include <kairos/types.h>
#include <kairos/config.h>
#include <kairos/spinlock.h>
#include <kairos/rbtree.h>
#include <kairos/list.h>
#include <kairos/arch.h>

struct process;

/*
 * Nice value to weight mapping
 * Higher weight = more CPU time
 * nice -20 → weight 88761 (highest priority)
 * nice   0 → weight  1024 (default)
 * nice +19 → weight    15 (lowest priority)
 */
#define NICE_0_WEIGHT   1024
#define NICE_MIN        (-20)
#define NICE_MAX        19

extern const int sched_nice_to_weight[40];

/*
 * Per-CPU Run Queue
 */
struct cfs_rq {
    struct rb_root tasks_timeline;      /* RB tree of runnable tasks */
    uint64_t min_vruntime;              /* Minimum vruntime (baseline) */
    uint32_t nr_running;                /* Number of runnable tasks */
    struct process *curr;               /* Currently running task */
    struct process *idle;               /* Idle task for this CPU */
    spinlock_t lock;
};

/*
 * Scheduler API
 */

/* Initialize scheduler */
void sched_init(void);

/* Initialize per-CPU run queue */
void sched_init_cpu(int cpu);

/* Add process to run queue */
void sched_enqueue(struct process *p);

/* Remove process from run queue */
void sched_dequeue(struct process *p);

/* Pick next process to run and switch to it */
void schedule(void);

/* Called on timer tick */
void sched_tick(void);

/* Set process nice value */
int sched_setnice(struct process *p, int nice);

/* Get process nice value */
int sched_getnice(struct process *p);

/*
 * Scheduler Helpers
 */

/* Get weight for nice value */
static inline int sched_weight(int nice)
{
    return sched_nice_to_weight[nice - NICE_MIN];
}

/* Calculate vruntime delta */
static inline uint64_t calc_delta_vruntime(uint64_t delta_exec, int weight)
{
    /* vruntime = exec_time * NICE_0_WEIGHT / weight */
    return (delta_exec * NICE_0_WEIGHT) / weight;
}

/*
 * Current CPU helpers (implemented in arch)
 */
int sched_cpu_id(void);
struct cfs_rq *sched_cpu_rq(void);
struct cfs_rq *sched_rq(int cpu);

/* Get per-CPU data for specific CPU */
struct percpu_data *sched_cpu_data(int cpu);

/*
 * Flags for schedule()
 */
#define SCHED_PREEMPT   (1 << 0)        /* Preempted by higher priority */
#define SCHED_YIELD     (1 << 1)        /* Voluntary yield */
#define SCHED_BLOCK     (1 << 2)        /* Blocking on I/O or lock */

/*
 * Per-CPU data
 */
struct trap_frame;

struct percpu_data {
    int cpu_id;
    struct cfs_rq runqueue;
    struct process *curr_proc;          /* Currently running process */
    struct process *idle_proc;          /* Idle process for this CPU */
    struct trap_frame *current_tf;      /* Current trap frame (for fork) */

    /* IPI State */
    volatile int ipi_pending_mask;      /* Pending IPIs (bitmask) */
    
    /* IPI_CALL data */
    spinlock_t ipi_call_lock;           /* Protects call data */
    void (*ipi_call_func)(void *);      /* Function to call */
    void *ipi_call_arg;                 /* Argument */

    /* Stats */
    uint64_t ticks;
    bool resched_needed;
};

/* Defined in core/sched/sched.c */
extern struct percpu_data cpu_data[];

/**
 * arch_get_percpu - Get per-CPU data for current CPU
 * 
 * Optimized to be inline and use direct array access (or register read).
 */
static inline struct percpu_data *arch_get_percpu(void)
{
    return &cpu_data[arch_cpu_id()];
}

#define this_cpu        (arch_get_percpu()->cpu_id)
#define this_rq         (&arch_get_percpu()->runqueue)
#define need_resched    (arch_get_percpu()->resched_needed)

/*
 * Additional scheduler functions
 */

/* Check if rescheduling is needed */
bool sched_need_resched(void);

/* Set the idle process for this CPU */
void sched_set_idle(struct process *p);

/*
 * SMP Support (Phase 4.3)
 */

/* Get number of online CPUs */
int sched_cpu_count(void);

/* Mark a CPU as online */
void sched_cpu_online(int cpu);

#endif /* _KAIROS_SCHED_H */
