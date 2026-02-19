/**
 * kernel/include/kairos/sched_types.h - Scheduler entity types (EEVDF)
 *
 * Defines struct sched_entity, which encapsulates all per-process scheduling
 * state.  The scheduler operates on sched_entity pointers internally;
 * public APIs still accept struct process *.
 *
 * on_rq / on_cpu are derived from run_state — no redundant bools.
 */

#ifndef _KAIROS_SCHED_TYPES_H
#define _KAIROS_SCHED_TYPES_H

#include <kairos/rbtree.h>
#include <kairos/types.h>

enum sched_entity_state {
    SE_STATE_BLOCKED  = 0,
    SE_STATE_RUNNABLE = 1,
    SE_STATE_QUEUED   = 2,
    SE_STATE_RUNNING  = 3,
};

struct sched_class;

struct sched_entity {
    /*
     * Scheduling state machine:
     * BLOCKED  -> not runnable (sleeping/zombie/etc.)
     * RUNNABLE -> runnable but not currently queued (transition state)
     * QUEUED   -> present on a runqueue RB tree
     * RUNNING  -> currently executing on a CPU
     */
    uint32_t run_state;

    /* EEVDF core fields */
    uint64_t vruntime;       /* virtual runtime (key for RB-tree ordering) */
    uint64_t deadline;       /* virtual deadline = vruntime + vslice */
    int64_t  vlag;           /* lag = V - vruntime at dequeue (positive = owed CPU) */
    uint64_t slice;          /* requested time slice in ns */

    uint64_t last_run_time;  /* wall-clock timestamp of last pick (ns) */
    int nice;
    int cpu;
    struct rb_node sched_node;
    const struct sched_class *sched_class;
};

/* Derive on_rq / on_cpu from the authoritative run_state */
static inline bool se_is_on_rq(const struct sched_entity *se) {
    return __atomic_load_n(&se->run_state, __ATOMIC_ACQUIRE) == SE_STATE_QUEUED;
}

static inline bool se_is_on_cpu(const struct sched_entity *se) {
    return __atomic_load_n(&se->run_state, __ATOMIC_ACQUIRE) == SE_STATE_RUNNING;
}

static inline void sched_entity_init(struct sched_entity *se) {
    se->run_state = SE_STATE_BLOCKED;
    se->vruntime = 0;
    se->deadline = 0;
    se->vlag = 0;
    se->slice = 0;  /* will be set to SCHED_SLICE_NS at enqueue */
    se->last_run_time = 0;
    se->nice = 0;
    se->cpu = -1;
    se->sched_class = NULL;
}

#endif
