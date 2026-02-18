/**
 * kernel/include/kairos/spinlock.h - Ticket spinlock primitives
 */

#ifndef _KAIROS_SPINLOCK_H
#define _KAIROS_SPINLOCK_H

#include <kairos/types.h>
#include <kairos/arch.h>
#include <kairos/lock_debug.h>
#include <kairos/lockdep.h>

typedef struct {
    uint32_t next;
    uint32_t serving;
    SPIN_DEBUG_FIELDS
    LOCKDEP_KEY_FIELD
} spinlock_t;
#if CONFIG_DEBUG_LOCKS || CONFIG_LOCKDEP
#define SPINLOCK_INIT {.next = 0, .serving = 0, SPIN_DEBUG_INIT LOCKDEP_KEY_INIT}
#else
#define SPINLOCK_INIT {0, 0}
#endif

static inline void spin_init(spinlock_t *lock) {
    lock->next = 0;
    lock->serving = 0;
    SPIN_DEBUG_ON_UNLOCK(lock);
}

#if CONFIG_DEBUG_LOCKS
void __spin_preempt_disable(void);
void __spin_preempt_enable(void);
#else
#define __spin_preempt_disable() ((void)0)
#define __spin_preempt_enable()  ((void)0)
#endif

static inline void spin_lock(spinlock_t *lock) {
    __spin_preempt_disable();
    uint32_t ticket = __atomic_fetch_add(&lock->next, 1, __ATOMIC_RELAXED);
    while (__atomic_load_n(&lock->serving, __ATOMIC_ACQUIRE) != ticket)
        arch_cpu_relax();
    SPIN_DEBUG_ON_LOCK(lock);
    LOCKDEP_ACQUIRE(lock);
}

static inline void spin_unlock(spinlock_t *lock) {
    LOCKDEP_RELEASE(lock);
    SPIN_DEBUG_ON_UNLOCK(lock);
    __atomic_fetch_add(&lock->serving, 1, __ATOMIC_RELEASE);
    __spin_preempt_enable();
}

static inline bool spin_trylock(spinlock_t *lock) {
    __spin_preempt_disable();
    uint32_t cur = __atomic_load_n(&lock->serving, __ATOMIC_RELAXED);
    bool acquired = __atomic_compare_exchange_n(
        &lock->next, &cur, cur + 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
    if (acquired) {
        SPIN_DEBUG_ON_LOCK(lock);
        LOCKDEP_ACQUIRE(lock);
    } else {
        __spin_preempt_enable();
    }
    return acquired;
}

static inline void spin_lock_irqsave(spinlock_t *lock, bool *flags) {
    *flags = arch_irq_save();
    spin_lock(lock);
}

static inline void spin_unlock_irqrestore(spinlock_t *lock, bool flags) {
    spin_unlock(lock);
    arch_irq_restore(flags);
}

#endif
