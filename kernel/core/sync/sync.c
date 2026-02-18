/**
 * kernel/core/sync/sync.c - Mutex, Semaphore, and RWLock implementation
 */

#include <kairos/sync.h>
#include <kairos/arch.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/printk.h>
#include <kairos/lock_debug.h>
#include <kairos/preempt.h>
#include <kairos/mm.h>
#include <kairos/string.h>

/* --- Lock debug (needs sched.h for in_atomic) --- */

#if CONFIG_DEBUG_LOCKS
void __lock_debug_sleep_check(const char *file, int line, const char *func) {
    if (!arch_irq_enabled())
        printk("[WARN] sleeping lock with IRQs disabled at %s:%d in %s()\n",
               file, line, func);
    if (in_atomic())
        printk("[WARN] sleeping lock in atomic context at %s:%d in %s()\n",
               file, line, func);
}

void __spin_preempt_disable(void) {
    arch_get_percpu()->preempt_count++;
    __asm__ __volatile__("" ::: "memory");
}

void __spin_preempt_enable(void) {
    __asm__ __volatile__("" ::: "memory");
    arch_get_percpu()->preempt_count--;
}
#endif

/* --- User-space Semaphore Management --- */

#define MAX_USER_SEMS 128
static struct semaphore user_sems[MAX_USER_SEMS];
static bool user_sem_used[MAX_USER_SEMS];
static spinlock_t user_sem_lock = SPINLOCK_INIT;

int do_sem_init(int count) {
    if (count < 0) return -EINVAL;
    spin_lock(&user_sem_lock);
    for (int i = 0; i < MAX_USER_SEMS; i++) {
        if (!user_sem_used[i]) {
            user_sem_used[i] = true;
            sem_init(&user_sems[i], count, "user_sem");
            spin_unlock(&user_sem_lock);
            return i;
        }
    }
    spin_unlock(&user_sem_lock);
    return -ENOSPC;
}

int do_sem_wait(int sem_id) {
    if (sem_id < 0 || sem_id >= MAX_USER_SEMS || !user_sem_used[sem_id])
        return -EINVAL;
    sem_wait(&user_sems[sem_id]);
    return 0;
}

int do_sem_post(int sem_id) {
    if (sem_id < 0 || sem_id >= MAX_USER_SEMS || !user_sem_used[sem_id])
        return -EINVAL;
    sem_post(&user_sems[sem_id]);
    return 0;
}

/* --- Mutex Implementation --- */

void mutex_init(struct mutex *m, const char *name) {
    spin_init(&m->lock);
    m->locked = false;
    m->holder = NULL;
    m->name = name;
    wait_queue_init(&m->wq);
}

void mutex_lock(struct mutex *m) {
    SLEEP_LOCK_DEBUG_CHECK();
    struct process *curr = proc_current();
    if (curr && m->holder == curr)
        panic("mutex_lock: recursive deadlock on mutex '%s'", m->name ? m->name : "unnamed");

    if (!curr) {
        spin_lock(&m->lock);
        while (m->locked) {
            spin_unlock(&m->lock);
            arch_cpu_relax();
            spin_lock(&m->lock);
        }
        m->locked = true;
        m->holder = NULL;
        spin_unlock(&m->lock);
        LOCKDEP_ACQUIRE_NAME(m, m->name);
        return;
    }

    spin_lock(&m->lock);
    while (m->locked) {
        spin_unlock(&m->lock);
        proc_sleep_on(&m->wq, m, true);
        spin_lock(&m->lock);
    }
    m->locked = true;
    m->holder = curr;
    spin_unlock(&m->lock);
    LOCKDEP_ACQUIRE_NAME(m, m->name);
}

int mutex_lock_interruptible(struct mutex *m) {
    SLEEP_LOCK_DEBUG_CHECK();
    struct process *curr = proc_current();
    if (curr && m->holder == curr)
        panic("mutex_lock: recursive deadlock on mutex '%s'", m->name ? m->name : "unnamed");

    if (!curr) {
        spin_lock(&m->lock);
        while (m->locked) {
            spin_unlock(&m->lock);
            arch_cpu_relax();
            spin_lock(&m->lock);
        }
        m->locked = true;
        m->holder = NULL;
        spin_unlock(&m->lock);
        LOCKDEP_ACQUIRE_NAME(m, m->name);
        return 0;
    }

    spin_lock(&m->lock);
    while (m->locked) {
        if (curr->mm && curr->sig_pending) {
            spin_unlock(&m->lock);
            return -EINTR;
        }
        spin_unlock(&m->lock);
        int rc = proc_sleep_on(&m->wq, m, true);
        if (rc < 0)
            return rc;
        spin_lock(&m->lock);
    }
    m->locked = true;
    m->holder = curr;
    spin_unlock(&m->lock);
    LOCKDEP_ACQUIRE_NAME(m, m->name);
    return 0;
}

void mutex_unlock(struct mutex *m) {
    LOCKDEP_RELEASE(m);
    struct process *curr = proc_current();
    if (curr && m->holder != curr)
        WARN_ON(1);
    spin_lock(&m->lock);
    m->locked = false;
    m->holder = NULL;
    spin_unlock(&m->lock);
    wait_queue_wakeup_one(&m->wq);
}

bool mutex_trylock(struct mutex *m) {
    bool success = false;
    spin_lock(&m->lock);
    if (!m->locked) {
        m->locked = true;
        m->holder = proc_current();
        success = true;
    }
    spin_unlock(&m->lock);
    if (success)
        LOCKDEP_ACQUIRE_NAME(m, m->name);
    return success;
}

/* --- Semaphore Implementation --- */

void sem_init(struct semaphore *s, int count, const char *name) {
    spin_init(&s->lock);
    s->count = count;
    s->name = name;
    wait_queue_init(&s->wq);
}

void sem_wait(struct semaphore *s) {
    SLEEP_LOCK_DEBUG_CHECK();
    struct process *curr = proc_current();

    if (!curr) {
        spin_lock(&s->lock);
        while (s->count <= 0) {
            spin_unlock(&s->lock);
            arch_cpu_relax();
            spin_lock(&s->lock);
        }
        s->count--;
        spin_unlock(&s->lock);
        LOCKDEP_ACQUIRE_NAME(s, s->name);
        return;
    }

    spin_lock(&s->lock);
    while (s->count <= 0) {
        spin_unlock(&s->lock);
        proc_sleep_on(&s->wq, s, true);
        spin_lock(&s->lock);
    }
    s->count--;
    spin_unlock(&s->lock);
    LOCKDEP_ACQUIRE_NAME(s, s->name);
}

int sem_wait_interruptible(struct semaphore *s) {
    SLEEP_LOCK_DEBUG_CHECK();
    struct process *curr = proc_current();
    if (!curr) {
        spin_lock(&s->lock);
        while (s->count <= 0) {
            spin_unlock(&s->lock);
            arch_cpu_relax();
            spin_lock(&s->lock);
        }
        s->count--;
        spin_unlock(&s->lock);
        LOCKDEP_ACQUIRE_NAME(s, s->name);
        return 0;
    }

    spin_lock(&s->lock);
    while (s->count <= 0) {
        if (curr->mm && curr->sig_pending) {
            spin_unlock(&s->lock);
            return -EINTR;
        }

        spin_unlock(&s->lock);
        int rc = proc_sleep_on(&s->wq, s, true);
        if (rc < 0)
            return rc;
        spin_lock(&s->lock);
    }
    s->count--;
    spin_unlock(&s->lock);
    LOCKDEP_ACQUIRE_NAME(s, s->name);
    return 0;
}

void sem_post(struct semaphore *s) {
    LOCKDEP_RELEASE(s);
    spin_lock(&s->lock);
    s->count++;
    spin_unlock(&s->lock);
    wait_queue_wakeup_one(&s->wq);
}

bool sem_trywait(struct semaphore *s) {
    bool success = false;
    spin_lock(&s->lock);
    if (s->count > 0) {
        s->count--;
        success = true;
    }
    spin_unlock(&s->lock);
    if (success)
        LOCKDEP_ACQUIRE_NAME(s, s->name);
    return success;
}

/* --- RWLock Implementation --- */

void rwlock_init(struct rwlock *rw, const char *name) {
    spin_init(&rw->lock);
    rw->readers = 0;
    rw->write_locked = false;
    rw->writers_waiting = 0;
    wait_queue_init(&rw->rd_wq);
    wait_queue_init(&rw->wr_wq);
    rw->writer = NULL;
    rw->name = name;
}

void rwlock_read_lock(struct rwlock *rw) {
    SLEEP_LOCK_DEBUG_CHECK();
    struct process *curr = proc_current();

    if (!curr) {
        spin_lock(&rw->lock);
        while (rw->write_locked || rw->writers_waiting) {
            spin_unlock(&rw->lock);
            arch_cpu_relax();
            spin_lock(&rw->lock);
        }
        rw->readers++;
        spin_unlock(&rw->lock);
        LOCKDEP_ACQUIRE_NAME(rw, rw->name);
        return;
    }

    spin_lock(&rw->lock);
    while (rw->write_locked || rw->writers_waiting) {
        spin_unlock(&rw->lock);
        proc_sleep_on(&rw->rd_wq, rw, true);
        spin_lock(&rw->lock);
    }
    rw->readers++;
    spin_unlock(&rw->lock);
    LOCKDEP_ACQUIRE_NAME(rw, rw->name);
}

int rwlock_read_lock_interruptible(struct rwlock *rw) {
    struct process *curr = proc_current();

    if (!curr) {
        spin_lock(&rw->lock);
        while (rw->write_locked || rw->writers_waiting) {
            spin_unlock(&rw->lock);
            arch_cpu_relax();
            spin_lock(&rw->lock);
        }
        rw->readers++;
        spin_unlock(&rw->lock);
        LOCKDEP_ACQUIRE_NAME(rw, rw->name);
        return 0;
    }

    spin_lock(&rw->lock);
    while (rw->write_locked || rw->writers_waiting) {
        if (curr->mm && curr->sig_pending) {
            spin_unlock(&rw->lock);
            return -EINTR;
        }
        spin_unlock(&rw->lock);
        int rc = proc_sleep_on(&rw->rd_wq, rw, true);
        if (rc < 0)
            return rc;
        spin_lock(&rw->lock);
    }
    rw->readers++;
    spin_unlock(&rw->lock);
    LOCKDEP_ACQUIRE_NAME(rw, rw->name);
    return 0;
}

void rwlock_read_unlock(struct rwlock *rw) {
    LOCKDEP_RELEASE(rw);
    spin_lock(&rw->lock);
    rw->readers--;
    WARN_ON(rw->readers < 0);
    if (rw->readers == 0 && rw->writers_waiting > 0) {
        spin_unlock(&rw->lock);
        wait_queue_wakeup_one(&rw->wr_wq);
        return;
    }
    spin_unlock(&rw->lock);
}

void rwlock_write_lock(struct rwlock *rw) {
    SLEEP_LOCK_DEBUG_CHECK();
    struct process *curr = proc_current();

    if (curr && rw->writer == curr) {
        panic("rwlock_write_lock: recursive deadlock on rwlock '%s'",
              rw->name ? rw->name : "unnamed");
    }

    if (!curr) {
        spin_lock(&rw->lock);
        rw->writers_waiting++;
        while (rw->write_locked || rw->readers > 0) {
            spin_unlock(&rw->lock);
            arch_cpu_relax();
            spin_lock(&rw->lock);
        }
        rw->writers_waiting--;
        rw->write_locked = true;
        rw->writer = NULL;
        spin_unlock(&rw->lock);
        LOCKDEP_ACQUIRE_NAME(rw, rw->name);
        return;
    }

    spin_lock(&rw->lock);
    rw->writers_waiting++;
    while (rw->write_locked || rw->readers > 0) {
        spin_unlock(&rw->lock);
        proc_sleep_on(&rw->wr_wq, rw, true);
        spin_lock(&rw->lock);
    }
    rw->writers_waiting--;
    rw->write_locked = true;
    rw->writer = curr;
    spin_unlock(&rw->lock);
    LOCKDEP_ACQUIRE_NAME(rw, rw->name);
}

int rwlock_write_lock_interruptible(struct rwlock *rw) {
    struct process *curr = proc_current();

    if (curr && rw->writer == curr) {
        panic("rwlock_write_lock: recursive deadlock on rwlock '%s'",
              rw->name ? rw->name : "unnamed");
    }

    if (!curr) {
        spin_lock(&rw->lock);
        rw->writers_waiting++;
        while (rw->write_locked || rw->readers > 0) {
            spin_unlock(&rw->lock);
            arch_cpu_relax();
            spin_lock(&rw->lock);
        }
        rw->writers_waiting--;
        rw->write_locked = true;
        rw->writer = NULL;
        spin_unlock(&rw->lock);
        LOCKDEP_ACQUIRE_NAME(rw, rw->name);
        return 0;
    }

    spin_lock(&rw->lock);
    rw->writers_waiting++;
    while (rw->write_locked || rw->readers > 0) {
        if (curr->mm && curr->sig_pending) {
            rw->writers_waiting--;
            spin_unlock(&rw->lock);
            return -EINTR;
        }
        spin_unlock(&rw->lock);
        int rc = proc_sleep_on(&rw->wr_wq, rw, true);
        if (rc < 0) {
            spin_lock(&rw->lock);
            rw->writers_waiting--;
            spin_unlock(&rw->lock);
            return rc;
        }
        spin_lock(&rw->lock);
    }
    rw->writers_waiting--;
    rw->write_locked = true;
    rw->writer = curr;
    spin_unlock(&rw->lock);
    LOCKDEP_ACQUIRE_NAME(rw, rw->name);
    return 0;
}

void rwlock_write_unlock(struct rwlock *rw) {
    LOCKDEP_RELEASE(rw);
    spin_lock(&rw->lock);
    rw->write_locked = false;
    rw->writer = NULL;
    bool has_writers = rw->writers_waiting > 0;
    spin_unlock(&rw->lock);

    if (has_writers) {
        wait_queue_wakeup_one(&rw->wr_wq);
    } else {
        wait_queue_wakeup_all(&rw->rd_wq);
    }
}

bool rwlock_write_trylock(struct rwlock *rw) {
    bool success = false;
    spin_lock(&rw->lock);
    if (!rw->write_locked && rw->readers == 0) {
        rw->write_locked = true;
        rw->writer = proc_current();
        success = true;
    }
    spin_unlock(&rw->lock);
    if (success)
        LOCKDEP_ACQUIRE_NAME(rw, rw->name);
    return success;
}

bool rwlock_read_trylock(struct rwlock *rw) {
    spin_lock(&rw->lock);
    if (rw->write_locked || rw->writers_waiting > 0) {
        spin_unlock(&rw->lock);
        return false;
    }
    rw->readers++;
    spin_unlock(&rw->lock);
    LOCKDEP_ACQUIRE_NAME(rw, rw->name);
    return true;
}

int mutex_lock_timeout(struct mutex *m, uint64_t timeout_ticks) {
    SLEEP_LOCK_DEBUG_CHECK();
    struct process *curr = proc_current();
    if (curr && m->holder == curr)
        panic("mutex_lock_timeout: recursive deadlock on mutex '%s'",
              m->name ? m->name : "unnamed");

    if (!curr) {
        uint64_t deadline = arch_timer_get_ticks() + timeout_ticks;
        spin_lock(&m->lock);
        while (m->locked) {
            spin_unlock(&m->lock);
            if (arch_timer_get_ticks() >= deadline)
                return -ETIMEDOUT;
            arch_cpu_relax();
            spin_lock(&m->lock);
        }
        m->locked = true;
        m->holder = NULL;
        spin_unlock(&m->lock);
        LOCKDEP_ACQUIRE_NAME(m, m->name);
        return 0;
    }

    uint64_t deadline = arch_timer_get_ticks() + timeout_ticks;
    spin_lock(&m->lock);
    while (m->locked) {
        spin_unlock(&m->lock);
        int rc = proc_sleep_on_mutex_timeout(&m->wq, m, NULL, false, deadline);
        if (rc == -ETIMEDOUT)
            return -ETIMEDOUT;
        spin_lock(&m->lock);
    }
    m->locked = true;
    m->holder = curr;
    spin_unlock(&m->lock);
    LOCKDEP_ACQUIRE_NAME(m, m->name);
    return 0;
}
