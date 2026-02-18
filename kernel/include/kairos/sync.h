/**
 * kernel/include/kairos/sync.h - Mutex, RWLock, and Semaphore
 */

#ifndef _KAIROS_SYNC_H
#define _KAIROS_SYNC_H

#include <kairos/spinlock.h>
#include <kairos/types.h>
#include <kairos/wait.h>

struct process;

struct mutex {
    spinlock_t lock;
    bool locked;
    struct wait_queue wq;
    struct process *holder;
    const char *name;
};

void mutex_init(struct mutex *m, const char *name);
void mutex_lock(struct mutex *m);
int  mutex_lock_interruptible(struct mutex *m);
int  mutex_lock_timeout(struct mutex *m, uint64_t timeout_ticks);
void mutex_unlock(struct mutex *m);
bool mutex_trylock(struct mutex *m);

/* Writer-priority rwlock. Falls back to spinning without process context. */
struct rwlock {
    spinlock_t lock;
    int readers;
    bool write_locked;
    uint32_t writers_waiting;
    struct wait_queue rd_wq;
    struct wait_queue wr_wq;
    struct process *writer;
    const char *name;
};

void rwlock_init(struct rwlock *rw, const char *name);
void rwlock_read_lock(struct rwlock *rw);
int  rwlock_read_lock_interruptible(struct rwlock *rw);
void rwlock_read_unlock(struct rwlock *rw);
void rwlock_write_lock(struct rwlock *rw);
int  rwlock_write_lock_interruptible(struct rwlock *rw);
void rwlock_write_unlock(struct rwlock *rw);
bool rwlock_write_trylock(struct rwlock *rw);
bool rwlock_read_trylock(struct rwlock *rw);

struct semaphore {
    spinlock_t lock;
    int count;
    struct wait_queue wq;
    const char *name;
};

void sem_init(struct semaphore *s, int count, const char *name);
void sem_wait(struct semaphore *s);
int  sem_wait_interruptible(struct semaphore *s);
void sem_post(struct semaphore *s);
bool sem_trywait(struct semaphore *s);

#endif
