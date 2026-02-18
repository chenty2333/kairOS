/**
 * kernel/include/kairos/preempt.h - Preemption count for debug assertions
 *
 * Not used for actual kernel preemption — only provides in_atomic() so that
 * sleeping-lock debug checks can detect "sleeping while holding a spinlock".
 */

#ifndef _KAIROS_PREEMPT_H
#define _KAIROS_PREEMPT_H

#include <kairos/sched.h>

static inline void preempt_disable(void) {
    arch_get_percpu()->preempt_count++;
    __asm__ __volatile__("" ::: "memory");
}

static inline void preempt_enable(void) {
    __asm__ __volatile__("" ::: "memory");
    arch_get_percpu()->preempt_count--;
}

static inline bool in_atomic(void) {
    return arch_get_percpu()->preempt_count > 0;
}

#endif /* _KAIROS_PREEMPT_H */
