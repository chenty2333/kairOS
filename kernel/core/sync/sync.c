/**
 * kernel/core/sync/sync.c - Advanced Robust Mutex and Semaphore implementation
 */

#include <kairos/sync.h>
#include <kairos/arch.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/printk.h>
#include <kairos/mm.h>
#include <kairos/string.h>

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
    (void)mutex_lock_interruptible(m);
}

int mutex_lock_interruptible(struct mutex *m) {
    struct process *curr = proc_current();
    if (curr && m->holder == curr) {
        panic("mutex_lock: recursive deadlock on mutex '%s'", m->name ? m->name : "unnamed");
    }

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
        return 0;
    }

    spin_lock(&m->lock);
    while (m->locked) {
        /* Check for pending signals if we're in user context */
        if (curr->mm && curr->sig_pending) {
            spin_unlock(&m->lock);
            return -EINTR;
        }

        wait_queue_add(&m->wq, curr);
        curr->state = PROC_SLEEPING;
        curr->wait_channel = m;
        
        spin_unlock(&m->lock);
        schedule();
        spin_lock(&m->lock);
    }
    
    m->locked = true;
    m->holder = curr;
    spin_unlock(&m->lock);
    return 0;
}

void mutex_unlock(struct mutex *m) {
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
    (void)sem_wait_interruptible(s);
}

int sem_wait_interruptible(struct semaphore *s) {
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
        return 0;
    }

    spin_lock(&s->lock);
    while (s->count <= 0) {
        if (curr->mm && curr->sig_pending) {
            spin_unlock(&s->lock);
            return -EINTR;
        }

        wait_queue_add(&s->wq, curr);
        curr->state = PROC_SLEEPING;
        curr->wait_channel = s;
        
        spin_unlock(&s->lock);
        schedule();
        spin_lock(&s->lock);
    }
    s->count--;
    spin_unlock(&s->lock);
    return 0;
}

void sem_post(struct semaphore *s) {
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
    return success;
}
