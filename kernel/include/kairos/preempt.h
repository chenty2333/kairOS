/**
 * kernel/include/kairos/preempt.h - Kernel preemption control
 *
 * preempt_count tracks nesting depth of preemption-disabled regions.
 * When it drops to zero and resched_needed is set, we call schedule().
 */

#ifndef _KAIROS_PREEMPT_H
#define _KAIROS_PREEMPT_H

#include <kairos/sched.h>

static inline void preempt_disable(void) {
    struct percpu_data *cpu = arch_get_percpu();
    cpu->preempt_count++;
    /* Compiler barrier: ensure the increment is visible before
     * any subsequent memory accesses in the critical section. */
    __asm__ volatile("" ::: "memory");
}

static inline void preempt_enable_no_resched(void) {
    __asm__ volatile("" ::: "memory");
    arch_get_percpu()->preempt_count--;
}

static inline void preempt_enable(void) {
    __asm__ volatile("" ::: "memory");
    struct percpu_data *cpu = arch_get_percpu();
    if (--cpu->preempt_count == 0 && cpu->resched_needed) {
        schedule();
    }
}

static inline bool in_atomic(void) {
    return arch_get_percpu()->preempt_count > 0;
}

static inline int preempt_count(void) {
    return arch_get_percpu()->preempt_count;
}

#endif
