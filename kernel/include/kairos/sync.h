/**
 * kernel/include/kairos/sync.h - Mutex and Semaphore implementation
 */

#ifndef _KAIROS_SYNC_H
#define _KAIROS_SYNC_H

#include <kairos/spinlock.h>
#include <kairos/types.h>
#include <kairos/wait.h>

struct process;

/**
 * Mutex - Mutual Exclusion Lock (Sleep-lock)
 */
struct mutex {
    spinlock_t lock;    /* Spinlock to protect mutex state */
    bool locked;        /* Is the mutex held? */
    struct wait_queue wq;
    struct process *holder;
    const char *name;
};

void mutex_init(struct mutex *m, const char *name);
void mutex_lock(struct mutex *m);
void mutex_unlock(struct mutex *m);
bool mutex_trylock(struct mutex *m);

/**
 * Semaphore - Counting Semaphore
 */
struct semaphore {
    spinlock_t lock;
    int count;
    struct wait_queue wq;
    const char *name;
};

void sem_init(struct semaphore *s, int count, const char *name);
void sem_wait(struct semaphore *s);
void sem_post(struct semaphore *s);
bool sem_trywait(struct semaphore *s);

#endif
