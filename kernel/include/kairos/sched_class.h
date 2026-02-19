/**
 * kernel/include/kairos/sched_class.h - Pluggable scheduler class interface
 *
 * Each scheduling policy (EEVDF, RT, deadline, ...) implements this
 * interface.  The core scheduler dispatches through function pointers,
 * iterating classes by priority (lower number = higher priority).
 */

#ifndef _KAIROS_SCHED_CLASS_H
#define _KAIROS_SCHED_CLASS_H

#include <kairos/types.h>

struct rq;
struct process;

struct sched_class {
    /* Enqueue a task onto this class's sub-runqueue */
    void (*enqueue_task)(struct rq *rq, struct process *p, int flags);

    /* Dequeue a task from this class's sub-runqueue */
    void (*dequeue_task)(struct rq *rq, struct process *p, int flags);

    /* Pick the next task to run; returns NULL if class has no runnable tasks */
    struct process *(*pick_next_task)(struct rq *rq, struct process *prev);

    /* Called when prev is being switched away from */
    void (*put_prev_task)(struct rq *rq, struct process *prev);

    /* Periodic tick processing */
    void (*task_tick)(struct rq *rq, struct process *p);

    /* Initialize child's scheduling entity at fork time */
    void (*task_fork)(struct process *child, struct process *parent);

    /* Change nice value; returns 0 on success */
    int (*set_nice)(struct rq *rq, struct process *p, int nice);

    /* Check whether p should preempt the current task */
    void (*check_preempt_curr)(struct rq *rq, struct process *p);

    /* Try to steal a task from this class's sub-runqueue on a remote CPU.
     * Returns stolen process or NULL. Called with rq->lock held. */
    struct process *(*steal_task)(struct rq *rq, int dst_cpu);

    /* Priority: lower number = higher priority class */
    int priority;
};

/* Enqueue flags */
#define ENQUEUE_WAKEUP  0x01
#define ENQUEUE_FORK    0x02

/* Dequeue flags */
#define DEQUEUE_SLEEP   0x01

/* The fair (EEVDF) scheduling class — defined in sched.c */
extern const struct sched_class fair_sched_class;

#endif /* _KAIROS_SCHED_CLASS_H */
