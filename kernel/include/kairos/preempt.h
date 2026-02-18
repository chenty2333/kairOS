/**
 * kernel/include/kairos/preempt.h - Preemption count query
 */

#ifndef _KAIROS_PREEMPT_H
#define _KAIROS_PREEMPT_H

#include <kairos/sched.h>

static inline bool in_atomic(void) {
    return arch_get_percpu()->preempt_count > 0;
}

#endif
