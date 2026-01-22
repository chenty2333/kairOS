/**
 * kairos/spinlock.h - Spinlock primitives
 */

#ifndef _KAIROS_SPINLOCK_H
#define _KAIROS_SPINLOCK_H

#include <kairos/types.h>

typedef struct {
    volatile uint32_t lock;
} spinlock_t;

#define SPINLOCK_INIT { 0 }
#define DEFINE_SPINLOCK(name) spinlock_t name = SPINLOCK_INIT

static inline void spin_init(spinlock_t *lock)
{
    lock->lock = 0;
}

static inline void spin_lock(spinlock_t *lock)
{
    while (__atomic_test_and_set(&lock->lock, __ATOMIC_ACQUIRE)) {
        /* Spin */
        while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED)) {
            __builtin_ia32_pause();  /* CPU hint: we're spinning */
        }
    }
}

static inline void spin_unlock(spinlock_t *lock)
{
    __atomic_clear(&lock->lock, __ATOMIC_RELEASE);
}

static inline bool spin_trylock(spinlock_t *lock)
{
    return !__atomic_test_and_set(&lock->lock, __ATOMIC_ACQUIRE);
}

/*
 * Spinlock with interrupt disable
 * Use these when the lock might be acquired in interrupt context
 */

/* Defined in arch code */
extern bool arch_irq_save(void);
extern void arch_irq_restore(bool state);

typedef struct {
    spinlock_t lock;
    bool irq_state;
} spinlock_irq_t;

#define SPINLOCK_IRQ_INIT { SPINLOCK_INIT, false }

static inline void spin_lock_irqsave(spinlock_irq_t *lock)
{
    lock->irq_state = arch_irq_save();
    spin_lock(&lock->lock);
}

static inline void spin_unlock_irqrestore(spinlock_irq_t *lock)
{
    spin_unlock(&lock->lock);
    arch_irq_restore(lock->irq_state);
}

#endif /* _KAIROS_SPINLOCK_H */
