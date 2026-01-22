/**
 * kairos/process.h - Process management
 */

#ifndef _KAIROS_PROCESS_H
#define _KAIROS_PROCESS_H

#include <kairos/types.h>
#include <kairos/config.h>
#include <kairos/list.h>
#include <kairos/rbtree.h>
#include <kairos/mm.h>
#include <kairos/spinlock.h>

/* Forward declarations */
struct file;
struct arch_context;
struct sigaction;

/*
 * Process States
 */
enum proc_state {
    PROC_UNUSED = 0,        /* Slot not in use */
    PROC_EMBRYO,            /* Being created */
    PROC_RUNNABLE,          /* Ready to run */
    PROC_RUNNING,           /* Currently running */
    PROC_SLEEPING,          /* Waiting for event */
    PROC_ZOMBIE,            /* Exited, waiting for parent */
};

/*
 * Process Structure
 */
struct process {
    /* === Identity === */
    pid_t pid;
    pid_t ppid;                         /* Parent PID */
    char name[16];

    /* === Credentials (simple: all root initially) === */
    uid_t uid;
    gid_t gid;

    /* === State === */
    enum proc_state state;
    int exit_code;

    /* === Scheduling (CFS) === */
    uint64_t vruntime;                  /* Virtual runtime */
    int nice;                           /* Priority: -20 (high) to +19 (low) */
    uint64_t last_run_time;             /* Last time this process ran */
    struct rb_node sched_node;          /* Red-black tree node (CFS, Phase 4) */
    struct list_head sched_list;        /* Run queue linkage (round-robin) */
    bool on_rq;                         /* On run queue? */
    int cpu;                            /* CPU affinity (-1 = any) */

    /* === Memory === */
    struct mm_struct *mm;               /* Address space */

    /* === Files === */
    struct file *files[CONFIG_MAX_FILES_PER_PROC];
    char *cwd;                          /* Current working directory */

    /* === Signals === */
    uint64_t sig_pending;               /* Pending signals bitmap */
    uint64_t sig_blocked;               /* Blocked signals mask */
    struct sigaction *sigactions;       /* Signal handlers */
    void *sig_stack;                    /* Alternate signal stack */

    /* === Wait/Sleep === */
    void *wait_channel;                 /* What we're waiting for */
    int wait_status;                    /* Wait result */
    struct list_head wait_list;         /* Wait queue linkage */

    /* === Family === */
    struct process *parent;
    struct list_head children;          /* List of children */
    struct list_head sibling;           /* Sibling list linkage */

    /* === Architecture Context === */
    struct arch_context *context;       /* Saved registers, kernel stack */

    /* === Statistics === */
    uint64_t utime;                     /* User time (ticks) */
    uint64_t stime;                     /* System time (ticks) */
    uint64_t start_time;                /* Process start time */
};

/*
 * Process Management API
 */

/* Initialize process subsystem */
void proc_init(void);

/* Create a new process from ELF */
struct process *proc_create(const char *name, const void *elf, size_t size);

/* Fork current process */
struct process *proc_fork(void);

/* Execute new program in current process */
int proc_exec(const char *path, char *const argv[], char *const envp[]);

/* Exit current process */
noreturn void proc_exit(int status);

/* Wait for child process */
pid_t proc_wait(pid_t pid, int *status, int options);

/* Kill a process */
int proc_kill(pid_t pid, int sig);

/* Get process by PID */
struct process *proc_find(pid_t pid);

/* Get current process */
struct process *proc_current(void);

/* Set current process (called by scheduler) */
void proc_set_current(struct process *p);

/* Get idle process */
struct process *proc_idle(void);

/* Initialize idle process */
struct process *proc_idle_init(void);

/* Yield CPU */
void proc_yield(void);

/*
 * Process State Transitions
 */

/* Wake up a sleeping process */
void proc_wakeup(struct process *p);

/* Put current process to sleep */
void proc_sleep(void *channel);

/* Sleep with timeout (returns 0 on wakeup, -ETIMEDOUT on timeout) */
int proc_sleep_timeout(void *channel, uint64_t timeout_ms);

/* Wake up all processes waiting on channel */
void proc_wakeup_all(void *channel);

/*
 * Wait Queue
 */

struct wait_queue {
    spinlock_t lock;
    struct list_head head;
};

#define WAIT_QUEUE_INIT(name) { SPINLOCK_INIT, LIST_HEAD_INIT((name).head) }
#define DEFINE_WAIT_QUEUE(name) struct wait_queue name = WAIT_QUEUE_INIT(name)

void wait_queue_init(struct wait_queue *wq);
void wait_queue_add(struct wait_queue *wq, struct process *p);
void wait_queue_remove(struct wait_queue *wq, struct process *p);
void wait_queue_wakeup_one(struct wait_queue *wq);
void wait_queue_wakeup_all(struct wait_queue *wq);

/*
 * Kernel Threads
 */

/* Create kernel thread */
struct process *kthread_create(int (*fn)(void *), void *arg, const char *name);

/* Current process macros */
#define current     proc_current()

#endif /* _KAIROS_PROCESS_H */
