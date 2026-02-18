/**
 * kernel/include/kairos/lockdep.h - Lightweight lock dependency checker
 *
 * When CONFIG_LOCKDEP=1, tracks lock acquisition order and warns on
 * potential deadlocks (AB-BA inversions).
 *
 * Each lock instance gets a static lock_class via __FILE__:__LINE__.
 * Per-thread held-lock stack (max depth 8).
 * NxN dependency bit-matrix (N<=64, 512 bytes).
 */

#ifndef _KAIROS_LOCKDEP_H
#define _KAIROS_LOCKDEP_H

#include <kairos/config.h>

#if CONFIG_LOCKDEP

#define LOCKDEP_MAX_CLASSES 64
#define LOCKDEP_HELD_MAX   8

struct lock_class_key {
    int id;   /* assigned lazily on first use; 0 = unassigned */
};

void lockdep_acquire(struct lock_class_key *key, const char *name);
void lockdep_release(struct lock_class_key *key);

/*
 * Usage: place LOCK_CLASS_KEY_DECL at each lock init/acquire site.
 * The static variable ensures one class per source location.
 */
#define LOCKDEP_ACQUIRE(name) do { \
    static struct lock_class_key __lock_key; \
    lockdep_acquire(&__lock_key, name); \
} while (0)

#define LOCKDEP_RELEASE(name) do { \
    static struct lock_class_key __lock_key; \
    lockdep_release(&__lock_key); \
} while (0)

#else /* !CONFIG_LOCKDEP */

#define LOCKDEP_ACQUIRE(name) ((void)0)
#define LOCKDEP_RELEASE(name) ((void)0)

#endif /* CONFIG_LOCKDEP */

#endif /* _KAIROS_LOCKDEP_H */
