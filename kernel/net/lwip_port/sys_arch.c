/**
 * sys_arch.c - lwIP OS abstraction layer for Kairos
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/wait.h>

#include "lwip/sys.h"
#include "lwip/opt.h"
#include "arch/sys_arch.h"

/* --- Semaphores --- */

err_t sys_sem_new(sys_sem_t *sem, u8_t count) {
    sem->count = count;
    mutex_init(&sem->lock, "lwip_sem");
    wait_queue_init(&sem->wq);
    sem->valid = true;
    return ERR_OK;
}

void sys_sem_free(sys_sem_t *sem) {
    sem->valid = false;
}

void sys_sem_signal(sys_sem_t *sem) {
    mutex_lock(&sem->lock);
    sem->count++;
    mutex_unlock(&sem->lock);
    wait_queue_wakeup_one(&sem->wq);
}

u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout) {
    uint64_t deadline = 0;
    if (timeout != 0) {
        uint64_t ticks = ((uint64_t)timeout * CONFIG_HZ + 999) / 1000;
        deadline = arch_timer_get_ticks() + ticks;
    }

    mutex_lock(&sem->lock);
    while (sem->count == 0) {
        if (timeout != 0 && arch_timer_get_ticks() >= deadline) {
            mutex_unlock(&sem->lock);
            return SYS_ARCH_TIMEOUT;
        }
        proc_sleep_on_mutex(&sem->wq, &sem->wq, &sem->lock, false);
    }
    sem->count--;
    mutex_unlock(&sem->lock);
    return 0;
}

int sys_sem_valid(sys_sem_t *sem) {
    return (sem && sem->valid) ? 1 : 0;
}

void sys_sem_set_invalid(sys_sem_t *sem) {
    sem->valid = false;
}

/* --- Mutexes --- */

err_t sys_mutex_new(sys_mutex_t *mutex) {
    mutex_init(&mutex->m, "lwip_mut");
    mutex->valid = true;
    return ERR_OK;
}

void sys_mutex_free(sys_mutex_t *mutex) {
    mutex->valid = false;
}

void sys_mutex_lock(sys_mutex_t *mutex) {
    mutex_lock(&mutex->m);
}

void sys_mutex_unlock(sys_mutex_t *mutex) {
    mutex_unlock(&mutex->m);
}

int sys_mutex_valid(sys_mutex_t *mutex) {
    return (mutex && mutex->valid) ? 1 : 0;
}

void sys_mutex_set_invalid(sys_mutex_t *mutex) {
    mutex->valid = false;
}

/* --- Mailboxes --- */

err_t sys_mbox_new(sys_mbox_t *mbox, int size) {
    (void)size; /* we use fixed SYS_MBOX_SIZE */
    mbox->head = 0;
    mbox->tail = 0;
    mbox->count = 0;
    mutex_init(&mbox->lock, "lwip_mbox");
    wait_queue_init(&mbox->not_empty);
    wait_queue_init(&mbox->not_full);
    mbox->valid = true;
    return ERR_OK;
}

void sys_mbox_free(sys_mbox_t *mbox) {
    mbox->valid = false;
}

void sys_mbox_post(sys_mbox_t *mbox, void *msg) {
    mutex_lock(&mbox->lock);
    while (mbox->count >= SYS_MBOX_SIZE) {
        proc_sleep_on_mutex(&mbox->not_full, &mbox->not_full,
                            &mbox->lock, false);
    }
    mbox->msgs[mbox->head] = msg;
    mbox->head = (mbox->head + 1) % SYS_MBOX_SIZE;
    mbox->count++;
    mutex_unlock(&mbox->lock);
    wait_queue_wakeup_one(&mbox->not_empty);
}

err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg) {
    mutex_lock(&mbox->lock);
    if (mbox->count >= SYS_MBOX_SIZE) {
        mutex_unlock(&mbox->lock);
        return ERR_MEM;
    }
    mbox->msgs[mbox->head] = msg;
    mbox->head = (mbox->head + 1) % SYS_MBOX_SIZE;
    mbox->count++;
    mutex_unlock(&mbox->lock);
    wait_queue_wakeup_one(&mbox->not_empty);
    return ERR_OK;
}

err_t sys_mbox_trypost_fromisr(sys_mbox_t *mbox, void *msg) {
    return sys_mbox_trypost(mbox, msg);
}

u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout) {
    uint64_t deadline = 0;
    if (timeout != 0) {
        uint64_t ticks = ((uint64_t)timeout * CONFIG_HZ + 999) / 1000;
        deadline = arch_timer_get_ticks() + ticks;
    }

    mutex_lock(&mbox->lock);
    while (mbox->count == 0) {
        if (timeout != 0 && arch_timer_get_ticks() >= deadline) {
            mutex_unlock(&mbox->lock);
            return SYS_ARCH_TIMEOUT;
        }
        proc_sleep_on_mutex(&mbox->not_empty, &mbox->not_empty,
                            &mbox->lock, false);
    }
    void *m = mbox->msgs[mbox->tail];
    mbox->tail = (mbox->tail + 1) % SYS_MBOX_SIZE;
    mbox->count--;
    mutex_unlock(&mbox->lock);
    wait_queue_wakeup_one(&mbox->not_full);

    if (msg) {
        *msg = m;
    }
    return 0;
}

u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg) {
    mutex_lock(&mbox->lock);
    if (mbox->count == 0) {
        mutex_unlock(&mbox->lock);
        return SYS_MBOX_EMPTY;
    }
    void *m = mbox->msgs[mbox->tail];
    mbox->tail = (mbox->tail + 1) % SYS_MBOX_SIZE;
    mbox->count--;
    mutex_unlock(&mbox->lock);
    wait_queue_wakeup_one(&mbox->not_full);

    if (msg) {
        *msg = m;
    }
    return 0;
}

int sys_mbox_valid(sys_mbox_t *mbox) {
    return (mbox && mbox->valid) ? 1 : 0;
}

void sys_mbox_set_invalid(sys_mbox_t *mbox) {
    mbox->valid = false;
}

/* --- Threads --- */

struct lwip_thread_arg {
    lwip_thread_fn fn;
    void *arg;
};

static int lwip_thread_wrapper(void *data) {
    struct lwip_thread_arg *ta = data;
    lwip_thread_fn fn = ta->fn;
    void *arg = ta->arg;
    kfree(ta);
    fn(arg);
    return 0;
}

sys_thread_t sys_thread_new(const char *name, lwip_thread_fn fn, void *arg,
                             int stacksize, int prio) {
    (void)stacksize; (void)prio;
    struct lwip_thread_arg *ta = kmalloc(sizeof(*ta));
    if (!ta) {
        return NULL;
    }
    ta->fn = fn;
    ta->arg = arg;

    struct process *p = kthread_create(lwip_thread_wrapper, ta, name);
    if (!p) {
        kfree(ta);
        return NULL;
    }
    sched_enqueue(p);
    return (sys_thread_t)p;
}

/* --- Init --- */

void sys_init(void) {
    /* Nothing to do */
}

/* --- Time --- */

u32_t sys_now(void) {
    /* Return milliseconds since boot */
    uint64_t ticks = arch_timer_ticks();
    return (u32_t)(ticks * 1000 / CONFIG_HZ);
}

/* --- Critical sections --- */

sys_prot_t sys_arch_protect(void) {
    return (sys_prot_t)arch_irq_save();
}

void sys_arch_unprotect(sys_prot_t pval) {
    arch_irq_restore((bool)pval);
}

/* --- Random --- */

u32_t lwip_kairos_rand(void) {
    static u32_t seed = 12345;
    seed = seed * 1103515245 + 12345;
    return seed;
}
