/**
 * kernel/include/kairos/sched.h - CFS Scheduler
 */

#ifndef _KAIROS_SCHED_H
#define _KAIROS_SCHED_H

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/list.h>
#include <kairos/rbtree.h>
#include <kairos/sched_types.h>
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
    struct sched_entity *curr_se;
    struct process *idle;
    spinlock_t lock;
};

void sched_init(void);
void sched_init_cpu(int cpu);
void sched_enqueue(struct process *p);
void sched_dequeue(struct process *p);
void schedule(void);
void sched_tick(void);
void sched_fork(struct process *child, struct process *parent);
void sched_post_switch_cleanup(void);
int sched_setnice(struct process *p, int nice);
int sched_getnice(struct process *p);

struct sched_cpu_stats {
    uint64_t enqueue_count;
    uint64_t dequeue_count;
    uint64_t pick_count;
    uint64_t switch_count;
    uint64_t idle_pick_count;
    uint64_t steal_attempt_count;
    uint64_t steal_success_count;
    uint64_t state_violation_count;
};

struct sched_stats {
    uint32_t cpu_count;
    bool steal_enabled;
    struct sched_cpu_stats cpu[CONFIG_MAX_CPUS];
};

enum sched_trace_event_type {
    SCHED_TRACE_ENQUEUE = 1,
    SCHED_TRACE_DEQUEUE = 2,
    SCHED_TRACE_PICK = 3,
    SCHED_TRACE_SWITCH = 4,
    SCHED_TRACE_IDLE = 5,
    SCHED_TRACE_STEAL = 6,
    SCHED_TRACE_SLEEP = 7,
    SCHED_TRACE_WAKEUP = 8,
    SCHED_TRACE_TRAP = 9,
    SCHED_TRACE_MIGRATE = 10,
};

#define SCHED_TRACE_PER_CPU 64
#define SCHED_TRACE_PER_CPU_MASK (SCHED_TRACE_PER_CPU - 1)

struct sched_trace_entry {
    uint64_t seq;
    uint64_t ticks;
    uint32_t cpu;
    uint16_t type;
    int32_t pid;
    int32_t proc_state;
    int32_t se_cpu;
    uint32_t se_state;
    uint8_t on_rq;
    uint8_t on_cpu;
    uint64_t arg0;
    uint64_t arg1;
};

struct percpu_data {
    int cpu_id;
    struct cfs_rq runqueue;
    struct process *curr_proc, *idle_proc;
    struct process *prev_task; /* Task that just switched out */
    struct trap_frame *current_tf;
    volatile int ipi_pending_mask;
    spinlock_t ipi_call_lock;
    void (*ipi_call_func)(void *);
    void *ipi_call_arg;
    uint64_t ticks;
    bool resched_needed;
    struct sched_cpu_stats stats;
    /* Per-CPU trace buffer — only written by local CPU with IRQs off */
    struct sched_trace_entry trace_buf[SCHED_TRACE_PER_CPU];
    uint32_t trace_head;
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
void sched_set_steal_enabled(bool enabled);
void sched_get_stats(struct sched_stats *out);
void sched_debug_dump_cpu(int cpu_id);
void sched_trace_event(enum sched_trace_event_type type,
                       const struct process *p,
                       uint64_t arg0, uint64_t arg1);
void sched_trace_dump_recent(int max_events);

#endif
