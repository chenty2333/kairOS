/**
 * process.c - Process Management
 *
 * Implements process creation, destruction, and management.
 * Provides the core process abstraction for Kairos.
 */

#include <kairos/types.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/mm.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/config.h>

/* Process table */
static struct process proc_table[CONFIG_MAX_PROCESSES];
static spinlock_t proc_table_lock = SPINLOCK_INIT;

/* PID allocation */
static pid_t next_pid = 1;

/* Current process (per-CPU, but we're single-CPU for now) */
static struct process *current_proc = NULL;

/* Idle process */
static struct process *idle_proc = NULL;

/**
 * proc_init - Initialize process subsystem
 */
void proc_init(void)
{
    /* Clear process table */
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        proc_table[i].state = PROC_UNUSED;
        proc_table[i].pid = 0;
        INIT_LIST_HEAD(&proc_table[i].children);
        INIT_LIST_HEAD(&proc_table[i].sibling);
        INIT_LIST_HEAD(&proc_table[i].wait_list);
        INIT_LIST_HEAD(&proc_table[i].sched_list);
    }

    pr_info("Process: initialized (max %d processes)\n", CONFIG_MAX_PROCESSES);
}

/**
 * proc_alloc - Allocate a new process structure
 */
static struct process *proc_alloc(void)
{
    struct process *p = NULL;

    spin_lock(&proc_table_lock);

    /* Find unused slot */
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        if (proc_table[i].state == PROC_UNUSED) {
            p = &proc_table[i];
            p->state = PROC_EMBRYO;
            p->pid = next_pid++;
            break;
        }
    }

    spin_unlock(&proc_table_lock);

    if (!p) {
        pr_err("proc_alloc: no free process slots\n");
        return NULL;
    }

    /* Initialize fields */
    p->ppid = 0;
    p->name[0] = '\0';
    p->uid = 0;
    p->gid = 0;
    p->exit_code = 0;

    /* Scheduling */
    p->vruntime = 0;
    p->nice = 0;
    p->last_run_time = 0;
    p->on_rq = false;
    p->cpu = -1;

    /* Memory - will be set up later */
    p->mm = NULL;

    /* Files */
    for (int i = 0; i < CONFIG_MAX_FILES_PER_PROC; i++) {
        p->files[i] = NULL;
    }
    p->cwd = NULL;

    /* Signals */
    p->sig_pending = 0;
    p->sig_blocked = 0;
    p->sigactions = NULL;
    p->sig_stack = NULL;

    /* Wait/sleep */
    p->wait_channel = NULL;
    p->wait_status = 0;

    /* Family */
    p->parent = NULL;
    INIT_LIST_HEAD(&p->children);
    INIT_LIST_HEAD(&p->sibling);
    INIT_LIST_HEAD(&p->wait_list);

    /* Context - allocate kernel stack */
    p->context = arch_context_alloc();
    if (!p->context) {
        pr_err("proc_alloc: failed to allocate context\n");
        p->state = PROC_UNUSED;
        return NULL;
    }

    /* Statistics */
    p->utime = 0;
    p->stime = 0;
    p->start_time = arch_timer_ticks();

    return p;
}

/**
 * proc_alloc_internal - Allocate process structure (internal use)
 *
 * This is exposed for the ELF loader.
 */
struct process *proc_alloc_internal(void)
{
    return proc_alloc();
}

/**
 * proc_free_internal - Free process structure (internal use)
 *
 * This is exposed for the ELF loader.
 */
void proc_free_internal(struct process *p)
{
    if (!p) {
        return;
    }

    /* Free context (kernel stack) */
    if (p->context) {
        arch_context_free(p->context);
        p->context = NULL;
    }

    /* Mark as unused */
    p->state = PROC_UNUSED;
    p->pid = 0;
}

/**
 * proc_free - Free a process structure
 */
static void proc_free(struct process *p)
{
    if (!p) {
        return;
    }

    /* Free context (kernel stack) */
    if (p->context) {
        arch_context_free(p->context);
        p->context = NULL;
    }

    /* Free address space */
    if (p->mm) {
        mm_destroy(p->mm);
        p->mm = NULL;
    }

    /* Remove from parent's children list */
    if (!list_empty(&p->sibling)) {
        list_del(&p->sibling);
    }

    /* Mark as unused */
    p->state = PROC_UNUSED;
    p->pid = 0;
}

/**
 * proc_current - Get current running process
 */
struct process *proc_current(void)
{
    return current_proc;
}

/**
 * proc_set_current - Set current process (called by scheduler)
 */
void proc_set_current(struct process *p)
{
    current_proc = p;
}

/**
 * proc_find - Find process by PID
 */
struct process *proc_find(pid_t pid)
{
    if (pid <= 0) {
        return NULL;
    }

    spin_lock(&proc_table_lock);

    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        if (proc_table[i].pid == pid && proc_table[i].state != PROC_UNUSED) {
            spin_unlock(&proc_table_lock);
            return &proc_table[i];
        }
    }

    spin_unlock(&proc_table_lock);
    return NULL;
}

/**
 * kthread_create - Create a kernel thread
 */
struct process *kthread_create(int (*fn)(void *), void *arg, const char *name)
{
    struct process *p = proc_alloc();
    if (!p) {
        return NULL;
    }

    /* Set name */
    int i;
    for (i = 0; i < 15 && name[i]; i++) {
        p->name[i] = name[i];
    }
    p->name[i] = '\0';

    /* Kernel threads don't have user address space */
    p->mm = NULL;

    /* Initialize context for kernel thread */
    arch_context_init(p->context, (vaddr_t)fn, (vaddr_t)arg, true);

    /* Ready to run */
    p->state = PROC_RUNNABLE;

    pr_debug("kthread_create: created '%s' (pid %d)\n", p->name, p->pid);

    return p;
}

/**
 * idle_thread - The idle thread function
 *
 * Runs when no other process is runnable.
 */
static int idle_thread(void *arg)
{
    (void)arg;

    while (1) {
        /* Enable interrupts and halt until next interrupt */
        arch_irq_enable();
        arch_cpu_halt();

        /* Check if we need to reschedule */
        schedule();
    }

    return 0;
}

/**
 * proc_idle_init - Create the idle process (PID 0)
 */
struct process *proc_idle_init(void)
{
    /* Use slot 0 for idle */
    struct process *p = &proc_table[0];

    p->state = PROC_EMBRYO;
    p->pid = 0;
    p->ppid = 0;

    const char *name = "idle";
    for (int i = 0; name[i] && i < 15; i++) {
        p->name[i] = name[i];
    }
    p->name[4] = '\0';

    p->uid = 0;
    p->gid = 0;
    p->nice = 19;  /* Lowest priority */
    p->vruntime = 0;
    p->mm = NULL;

    /* Allocate context */
    p->context = arch_context_alloc();
    if (!p->context) {
        panic("Failed to allocate idle process context");
    }

    /* Initialize as kernel thread */
    arch_context_init(p->context, (vaddr_t)idle_thread, 0, true);

    p->state = PROC_RUNNABLE;
    idle_proc = p;
    current_proc = p;

    /* Register with scheduler */
    sched_set_idle(p);

    pr_info("Process: idle process created (pid 0)\n");

    return p;
}

/**
 * proc_idle - Get idle process
 */
struct process *proc_idle(void)
{
    return idle_proc;
}

/**
 * proc_fork - Fork current process
 *
 * Creates a copy of the current process. The child process is identical
 * to the parent except:
 * - It has a new PID
 * - Its parent is the calling process
 * - fork() returns 0 in the child
 * - fork() returns child PID in the parent
 *
 * Returns the child process structure (in parent context).
 * The child will start running from the syscall return point.
 */
struct process *proc_fork(void)
{
    struct process *parent = current_proc;
    struct process *child;

    if (!parent || !parent->mm) {
        pr_err("proc_fork: cannot fork kernel thread\n");
        return NULL;
    }

    /* Allocate child process */
    child = proc_alloc();
    if (!child) {
        pr_err("proc_fork: failed to allocate child process\n");
        return NULL;
    }

    /* Copy name */
    for (int i = 0; i < 15; i++) {
        child->name[i] = parent->name[i];
    }
    child->name[15] = '\0';

    /* Copy credentials */
    child->uid = parent->uid;
    child->gid = parent->gid;

    /* Set parent-child relationship */
    child->parent = parent;
    child->ppid = parent->pid;

    /* Add child to parent's children list */
    spin_lock(&proc_table_lock);
    list_add(&child->sibling, &parent->children);
    spin_unlock(&proc_table_lock);

    /* Clone address space */
    child->mm = mm_clone(parent->mm);
    if (!child->mm) {
        pr_err("proc_fork: failed to clone address space\n");
        spin_lock(&proc_table_lock);
        list_del(&child->sibling);
        spin_unlock(&proc_table_lock);
        proc_free_internal(child);
        return NULL;
    }

    /* Set up child to return from fork with return value 0 */
    struct trap_frame *parent_tf = get_current_trapframe();
    if (parent_tf) {
        arch_setup_fork_child(child->context, parent_tf);
    } else {
        /* Fallback: clone context (for kernel threads) */
        arch_context_clone(child->context, parent->context);
    }

    /* Child inherits scheduling parameters */
    child->nice = parent->nice;
    child->vruntime = parent->vruntime;

    /* Child is ready to run */
    child->state = PROC_RUNNABLE;

    pr_debug("proc_fork: created child pid %d from parent pid %d\n",
             child->pid, parent->pid);

    return child;
}

/**
 * proc_exit - Exit current process
 */
noreturn void proc_exit(int status)
{
    struct process *p = current_proc;

    if (p == idle_proc) {
        panic("Idle process cannot exit!");
    }

    pr_info("Process %d (%s) exiting with status %d\n",
            p->pid, p->name, status);

    /* Remove from run queue first */
    sched_dequeue(p);

    /* Save exit status */
    p->exit_code = status;
    p->state = PROC_ZOMBIE;

    /* Reparent children to init (pid 1) */
    /* TODO: implement when we have init */

    /* Wake up parent if waiting */
    if (p->parent) {
        proc_wakeup(p->parent);
    }

    /* For user processes without a parent (test processes), halt when done */
    /* This prevents returning to invalid kernel code after user test exits */
    if (p->mm && !p->parent) {
        pr_info("Test process exited. System halted.\n");
        arch_irq_disable();
        while (1) {
            arch_cpu_halt();
        }
    }

    /* Schedule another process - this should never return */
    schedule();

    /* Should never reach here */
    panic("zombie process returned from schedule!");
}

/**
 * proc_yield - Voluntarily yield CPU
 */
void proc_yield(void)
{
    schedule();
}

/**
 * proc_wakeup - Wake up a sleeping process
 */
void proc_wakeup(struct process *p)
{
    if (!p) {
        return;
    }

    if (p->state == PROC_SLEEPING) {
        p->state = PROC_RUNNABLE;
        sched_enqueue(p);
    }
}

/**
 * proc_sleep - Put current process to sleep
 */
void proc_sleep(void *channel)
{
    struct process *p = current_proc;

    p->wait_channel = channel;
    p->state = PROC_SLEEPING;

    schedule();

    p->wait_channel = NULL;
}

/**
 * proc_wakeup_all - Wake up all processes waiting on channel
 */
void proc_wakeup_all(void *channel)
{
    spin_lock(&proc_table_lock);

    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        struct process *p = &proc_table[i];
        if (p->state == PROC_SLEEPING && p->wait_channel == channel) {
            p->state = PROC_RUNNABLE;
            p->wait_channel = NULL;
            sched_enqueue(p);
        }
    }

    spin_unlock(&proc_table_lock);
}

/**
 * proc_wait - Wait for child process
 */
pid_t proc_wait(pid_t pid, int *status, int options)
{
    struct process *p = current_proc;
    struct process *child, *tmp;
    (void)options;

    while (1) {
        /* Look for zombie children */
        bool found_child = false;

        spin_lock(&proc_table_lock);

        list_for_each_entry_safe(child, tmp, &p->children, sibling) {
            found_child = true;

            if (pid > 0 && child->pid != pid) {
                continue;
            }

            if (child->state == PROC_ZOMBIE) {
                /* Found a zombie child */
                pid_t child_pid = child->pid;
                if (status) {
                    *status = child->exit_code;
                }

                /* Clean up the child */
                proc_free(child);

                spin_unlock(&proc_table_lock);
                return child_pid;
            }
        }

        spin_unlock(&proc_table_lock);

        if (!found_child) {
            return -ECHILD;
        }

        /* No zombie yet, sleep and wait */
        proc_sleep(p);
    }
}

/* proc_create is now implemented in elf.c */

/**
 * Wait queue implementation
 */

void wait_queue_init(struct wait_queue *wq)
{
    spin_init(&wq->lock);
    INIT_LIST_HEAD(&wq->head);
}

void wait_queue_add(struct wait_queue *wq, struct process *p)
{
    spin_lock(&wq->lock);
    list_add_tail(&p->wait_list, &wq->head);
    spin_unlock(&wq->lock);
}

void wait_queue_remove(struct wait_queue *wq, struct process *p)
{
    spin_lock(&wq->lock);
    list_del(&p->wait_list);
    INIT_LIST_HEAD(&p->wait_list);
    spin_unlock(&wq->lock);
}

void wait_queue_wakeup_one(struct wait_queue *wq)
{
    spin_lock(&wq->lock);

    if (!list_empty(&wq->head)) {
        struct process *p = list_first_entry(&wq->head, struct process, wait_list);
        list_del(&p->wait_list);
        INIT_LIST_HEAD(&p->wait_list);
        proc_wakeup(p);
    }

    spin_unlock(&wq->lock);
}

void wait_queue_wakeup_all(struct wait_queue *wq)
{
    spin_lock(&wq->lock);

    while (!list_empty(&wq->head)) {
        struct process *p = list_first_entry(&wq->head, struct process, wait_list);
        list_del(&p->wait_list);
        INIT_LIST_HEAD(&p->wait_list);
        proc_wakeup(p);
    }

    spin_unlock(&wq->lock);
}
