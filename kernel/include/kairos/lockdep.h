/**
 * kernel/include/kairos/lockdep.h - Lightweight lock dependency checker
 */

#ifndef _KAIROS_LOCKDEP_H
#define _KAIROS_LOCKDEP_H

#include <kairos/config.h>

#if CONFIG_LOCKDEP

#define LOCKDEP_MAX_CLASSES 64
#define LOCKDEP_HELD_MAX   8

struct lock_class_key {
    int id;
};

void lockdep_acquire(struct lock_class_key *key, const char *name);
void lockdep_release(struct lock_class_key *key);

/* Embed in lock structs for proper acquire/release pairing */
#define LOCKDEP_KEY_FIELD  struct lock_class_key dep_key;
#define LOCKDEP_KEY_INIT   .dep_key = {0},

#else

#define LOCKDEP_KEY_FIELD
#define LOCKDEP_KEY_INIT
static inline void lockdep_acquire(void *k, const char *n) { (void)k; (void)n; }
static inline void lockdep_release(void *k) { (void)k; }

#endif

#endif
