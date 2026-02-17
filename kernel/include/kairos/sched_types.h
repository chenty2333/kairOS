/**
 * kernel/include/kairos/sched_types.h - Scheduler entity types
 *
 * Defines struct sched_entity, which encapsulates all per-process scheduling
 * state.  The scheduler operates on sched_entity pointers internally;
 * public APIs still accept struct process *.
 */

#ifndef _KAIROS_SCHED_TYPES_H
#define _KAIROS_SCHED_TYPES_H

#include <kairos/rbtree.h>
#include <kairos/types.h>

struct sched_entity {
    uint64_t vruntime;
    uint64_t last_run_time;
    int nice;
    int cpu;
    struct rb_node sched_node;
    bool on_rq;
    bool on_cpu;
};

static inline void sched_entity_init(struct sched_entity *se) {
    se->vruntime = 0;
    se->last_run_time = 0;
    se->nice = 0;
    se->cpu = -1;
    se->on_rq = false;
    se->on_cpu = false;
}

#endif
