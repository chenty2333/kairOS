/**
 * kernel/include/kairos/lock_debug.h - Lock debugging annotations
 *
 * When CONFIG_DEBUG_LOCKS=1, adds runtime checks to detect common locking bugs:
 *   - spinlock: same-CPU recursive acquisition, preempt count tracking
 *   - mutex/sem/rwlock: sleeping with IRQs disabled or in atomic context
 *   - rwlock: holding write lock while attempting read lock (self-deadlock)
 */

#ifndef _KAIROS_LOCK_DEBUG_H
#define _KAIROS_LOCK_DEBUG_H

#include <kairos/config.h>

#if CONFIG_DEBUG_LOCKS

#include <kairos/printk.h>
#include <kairos/arch.h>

/* Extra fields embedded in spinlock_t */
#define SPIN_DEBUG_FIELDS  int held_cpu;

#define SPIN_DEBUG_INIT    .held_cpu = -1,

#define SPIN_DEBUG_ON_LOCK(lock) do { \
    WARN_ON((lock)->held_cpu == arch_cpu_id()); \
    (lock)->held_cpu = arch_cpu_id(); \
} while (0)

#define SPIN_DEBUG_ON_UNLOCK(lock) do { \
    (lock)->held_cpu = -1; \
} while (0)

/*
 * Check: sleeping locks must not be acquired with IRQs disabled.
 * The in_atomic() check (sleeping while holding spinlock) is done via
 * preempt_count — but that requires sched.h which creates a circular
 * dependency from spinlock.h.  So we provide it as an extern function
 * implemented in sync.c where the full header set is available.
 */
void __lock_debug_sleep_check(const char *file, int line, const char *func);
#define SLEEP_LOCK_DEBUG_CHECK() \
    __lock_debug_sleep_check(__FILE__, __LINE__, __func__)

#else /* !CONFIG_DEBUG_LOCKS */

#define SPIN_DEBUG_FIELDS
#define SPIN_DEBUG_INIT
#define SPIN_DEBUG_ON_LOCK(lock)    ((void)0)
#define SPIN_DEBUG_ON_UNLOCK(lock)  ((void)0)
#define SLEEP_LOCK_DEBUG_CHECK()    ((void)0)

#endif /* CONFIG_DEBUG_LOCKS */

#endif /* _KAIROS_LOCK_DEBUG_H */
