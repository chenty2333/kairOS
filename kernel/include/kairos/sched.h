/**
 * kernel/include/kairos/sched.h - CFS Scheduler
 */

#ifndef _KAIROS_SCHED_H
#define _KAIROS_SCHED_H

#include <kairos/arch.h>
#include <kairos/list.h>
#include <kairos/rbtree.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>

#define NICE_0_WEIGHT 1024
#define NICE_MIN (-20)
#define NICE_MAX 19

struct process;
extern const int sched_nice_to_weight[40];

struct cfs_rq {
    struct rb_root tasks_timeline;
    uint64_t min_vruntime;
    uint32_t nr_running;
    struct process *curr, *idle;
    spinlock_t lock;
};

void sched_init(void);
void sched_init_cpu(int cpu);
void sched_enqueue(struct process *p);
void sched_dequeue(struct process *p);
void schedule(void);
void sched_tick(void);
int sched_setnice(struct process *p, int nice);

struct percpu_data {
    int cpu_id;
    struct cfs_rq runqueue;
    struct process *curr_proc, *idle_proc;
    struct trap_frame *current_tf;
    volatile int ipi_pending_mask;
    spinlock_t ipi_call_lock;
    void (*ipi_call_func)(void *);
    void *ipi_call_arg;
    uint64_t ticks;
    bool resched_needed;
};

extern struct percpu_data cpu_data[];
static inline struct percpu_data *arch_get_percpu(void) {
    return &cpu_data[arch_cpu_id()];
}

#define this_rq (&arch_get_percpu()->runqueue)
bool sched_need_resched(void);
void sched_set_idle(struct process *p);
int sched_cpu_count(void);
void sched_cpu_online(int cpu);
struct percpu_data *sched_cpu_data(int cpu);

#endif