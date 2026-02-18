/**
 * kernel/include/kairos/atomic.h - Atomic operations
 */

#ifndef _KAIROS_ATOMIC_H
#define _KAIROS_ATOMIC_H

#include <kairos/types.h>

typedef struct {
    volatile uint32_t counter;
} atomic_t;

#define ATOMIC_INIT(val) { .counter = (val) }

static inline void atomic_init(atomic_t *a, uint32_t val)
{
    __atomic_store_n(&a->counter, val, __ATOMIC_RELAXED);
}

static inline uint32_t atomic_read(const atomic_t *a)
{
    return __atomic_load_n(&a->counter, __ATOMIC_ACQUIRE);
}

static inline void atomic_set(atomic_t *a, uint32_t val)
{
    __atomic_store_n(&a->counter, val, __ATOMIC_RELEASE);
}

static inline void atomic_inc(atomic_t *a)
{
    __atomic_fetch_add(&a->counter, 1, __ATOMIC_RELAXED);
}

static inline uint32_t atomic_inc_return(atomic_t *a)
{
    return __atomic_add_fetch(&a->counter, 1, __ATOMIC_ACQ_REL);
}

static inline uint32_t atomic_dec_return(atomic_t *a)
{
    return __atomic_sub_fetch(&a->counter, 1, __ATOMIC_ACQ_REL);
}

static inline uint32_t atomic_add_return(atomic_t *a, uint32_t val)
{
    return __atomic_add_fetch(&a->counter, val, __ATOMIC_ACQ_REL);
}

static inline uint32_t atomic_sub_return(atomic_t *a, uint32_t val)
{
    return __atomic_sub_fetch(&a->counter, val, __ATOMIC_ACQ_REL);
}

static inline uint32_t atomic_fetch_add(atomic_t *a, uint32_t val)
{
    return __atomic_fetch_add(&a->counter, val, __ATOMIC_ACQ_REL);
}

static inline uint32_t atomic_fetch_sub(atomic_t *a, uint32_t val)
{
    return __atomic_fetch_sub(&a->counter, val, __ATOMIC_ACQ_REL);
}

static inline bool atomic_cmpxchg(atomic_t *a, uint32_t *expected,
                                   uint32_t desired)
{
    return __atomic_compare_exchange_n(&a->counter, expected, desired,
                                       false, __ATOMIC_ACQ_REL,
                                       __ATOMIC_ACQUIRE);
}

#endif /* _KAIROS_ATOMIC_H */
