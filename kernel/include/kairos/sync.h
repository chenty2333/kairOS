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
int mutex_lock_interruptible(struct mutex *m); /* Returns -EINTR if interrupted */
int mutex_lock_timeout(struct mutex *m, uint64_t timeout_ticks); /* Returns -ETIMEDOUT */
void mutex_unlock(struct mutex *m);
bool mutex_trylock(struct mutex *m);

/**
 * RWLock - Reader/Writer Lock (Sleep-lock)
 *
 * Writer-priority: when a writer is waiting, new readers queue behind it.
 * Recursive write-lock panics (same as mutex).
 * Falls back to spinning when no process context (same as mutex).
 */
struct rwlock {
    spinlock_t lock;           /* Protects rwlock state */
    int readers;               /* Number of active readers (0 when write-held) */
    bool write_locked;         /* Is a writer holding the lock? */
    uint32_t writers_waiting;  /* Number of writers queued */
    struct wait_queue rd_wq;   /* Reader wait queue */
    struct wait_queue wr_wq;   /* Writer wait queue */
    struct process *writer;    /* Current write-lock holder */
    const char *name;
};

void rwlock_init(struct rwlock *rw, const char *name);
void rwlock_read_lock(struct rwlock *rw);
int rwlock_read_lock_interruptible(struct rwlock *rw);
void rwlock_read_unlock(struct rwlock *rw);
void rwlock_write_lock(struct rwlock *rw);
int rwlock_write_lock_interruptible(struct rwlock *rw);
void rwlock_write_unlock(struct rwlock *rw);
bool rwlock_write_trylock(struct rwlock *rw);
bool rwlock_read_trylock(struct rwlock *rw);

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
int sem_wait_interruptible(struct semaphore *s);
void sem_post(struct semaphore *s);
bool sem_trywait(struct semaphore *s);

#endif
