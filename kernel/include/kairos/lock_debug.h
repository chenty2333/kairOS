/**
 * kernel/include/kairos/lock_debug.h - Lock debugging annotations
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

/* Extern — implemented in sync.c to avoid circular deps with sched.h */
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
