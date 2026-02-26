/**
 * arch/sys_arch.h - lwIP OS abstraction types for Kairos
 */

#ifndef LWIP_ARCH_SYS_ARCH_H
#define LWIP_ARCH_SYS_ARCH_H

#include <kairos/pollwait.h>
#include <kairos/sync.h>
#include <kairos/list.h>

/* Semaphore: counter + wait queue */
struct sys_sem {
    int count;
    struct mutex lock;
    struct poll_wait_source wait_src;
    bool valid;
};
typedef struct sys_sem sys_sem_t;

/* Mutex: direct mapping to Kairos mutex */
struct sys_mut {
    struct mutex m;
    bool valid;
};
typedef struct sys_mut sys_mutex_t;

/* Mailbox: fixed-size ring buffer + wait queues */
#define SYS_MBOX_SIZE 32

struct sys_mbox {
    void *msgs[SYS_MBOX_SIZE];
    int head;
    int tail;
    int count;
    struct mutex lock;
    struct poll_wait_source not_empty;
    struct poll_wait_source not_full;
    bool valid;
};
typedef struct sys_mbox sys_mbox_t;

/* Thread handle */
typedef void *sys_thread_t;

/* Protection (critical sections) */
typedef int sys_prot_t;

#define SYS_SEM_NULL   NULL
#define SYS_MUTEX_NULL NULL
#define SYS_MBOX_NULL  NULL

#endif /* LWIP_ARCH_SYS_ARCH_H */
