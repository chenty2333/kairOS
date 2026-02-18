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

#define LOCKDEP_KEY_FIELD       struct lock_class_key dep_key;
#define LOCKDEP_KEY_INIT        .dep_key = {0},
#define LOCKDEP_ACQUIRE(lock)   lockdep_acquire(&(lock)->dep_key, NULL)
#define LOCKDEP_RELEASE(lock)   lockdep_release(&(lock)->dep_key)
#define LOCKDEP_ACQUIRE_NAME(lock, name) lockdep_acquire(&(lock)->dep_key, name)

#else

#define LOCKDEP_KEY_FIELD
#define LOCKDEP_KEY_INIT
#define LOCKDEP_ACQUIRE(lock)            ((void)0)
#define LOCKDEP_RELEASE(lock)            ((void)0)
#define LOCKDEP_ACQUIRE_NAME(lock, name) ((void)0)

#endif

#endif
