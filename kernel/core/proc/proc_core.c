/**
 * kernel/core/proc/proc_core.c - Core process management
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

#include "proc_internal.h"

struct process proc_table[CONFIG_MAX_PROCESSES];
spinlock_t proc_table_lock = SPINLOCK_INIT;
pid_t next_pid = 1;
struct process *reaper_proc = NULL;

void proc_init(void) {
    memset(proc_table, 0, sizeof(proc_table));
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        proc_table[i].state = PROC_UNUSED;
        INIT_LIST_HEAD(&proc_table[i].children);
        INIT_LIST_HEAD(&proc_table[i].sibling);
        INIT_LIST_HEAD(&proc_table[i].thread_group);
        wait_queue_entry_init(&proc_table[i].wait_entry, &proc_table[i]);
        wait_queue_init(&proc_table[i].exit_wait);
        wait_queue_init(&proc_table[i].vfork_wait);
        spin_init(&proc_table[i].lock);
    }
    pr_info("Process: initialized\n");
}

static void proc_set_name(struct process *p, const char *name) {
    strncpy(p->name, name, sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';
}

static void proc_attach_console(struct process *p) {
    struct file *f = NULL;
    if (!p) {
        return;
    }
    int ret = vfs_open_at("/", "/dev/console", O_RDWR, 0, &f);
    if ((ret < 0 || !f) &&
        vfs_open_at("/", "/console", O_RDWR, 0, &f) == 0 && f) {
        ret = 0;
    }
    if (ret < 0 || !f) {
        pr_warn("stdio: failed to open /dev/console (ret=%d)\n", ret);
        vfs_dump_mounts();
        return;
    }

    int fd0 = fd_alloc(p, f);
    if (fd0 < 0) {
        vfs_close(f);
        return;
    }
    fd_dup2(p, fd0, 1);
    fd_dup2(p, fd0, 2);
}

void proc_setup_stdio(struct process *p) {
    if (!p) {
        return;
    }
    if (!p->fdtable)
        return;
    if (p->fdtable->files[0] || p->fdtable->files[1] || p->fdtable->files[2]) {
        return;
    }
    proc_attach_console(p);
}

struct process *proc_alloc(void) {
    struct process *p = NULL;
    spin_lock(&proc_table_lock);
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
        return NULL;
    }

    p->ppid = p->uid = p->gid = 0;
    p->pgid = p->pid;
    p->sid = p->pid;
    p->umask = 022;
    p->syscall_abi = SYSCALL_ABI_LINUX;
    p->name[0] = '\0';
    p->mm = NULL;
    p->parent = NULL;
    sched_entity_init(&p->se);
    p->exit_code = p->sig_pending = p->sig_blocked = 0;
    p->wait_channel = NULL;
    p->sleep_deadline = 0;
    p->fdtable = fdtable_alloc();
    if (!p->fdtable) {
        p->state = PROC_UNUSED;
        return NULL;
    }
    strcpy(p->cwd, "/");
    p->cwd_vnode = NULL;
    p->cwd_dentry = NULL;
    struct dentry *root = vfs_root_dentry();
    if (root) {
        p->cwd_dentry = root;
        dentry_get(root);
        p->cwd_vnode = root->vnode;
        if (p->cwd_vnode)
            vnode_get(p->cwd_vnode);
    }
    p->mnt_ns = vfs_mount_ns_get();
    p->tid_address = 0;
    p->tid_set_address = 0;
    p->robust_list = 0;
    p->robust_len = 0;
    memset(&p->itimer_real, 0, sizeof(p->itimer_real));
    p->sigaltstack.ss_sp = NULL;
    p->sigaltstack.ss_flags = SS_DISABLE;
    p->sigaltstack.ss_size = 0;
    for (int i = 0; i < RLIM_NLIMITS; i++) {
        p->rlimits[i].rlim_cur = RLIM_INFINITY;
        p->rlimits[i].rlim_max = RLIM_INFINITY;
    }
    p->rlimits[RLIMIT_NOFILE].rlim_cur = CONFIG_MAX_FILES_PER_PROC;
    p->rlimits[RLIMIT_NOFILE].rlim_max = CONFIG_MAX_FILES_PER_PROC;
    p->rlimits[RLIMIT_STACK].rlim_cur = USER_STACK_SIZE;
    p->rlimits[RLIMIT_STACK].rlim_max = USER_STACK_SIZE;

    INIT_LIST_HEAD(&p->children);
    INIT_LIST_HEAD(&p->sibling);
    INIT_LIST_HEAD(&p->thread_group);
    wait_queue_entry_init(&p->wait_entry, p);
    wait_queue_init(&p->exit_wait);
    wait_queue_init(&p->vfork_wait);
    spin_init(&p->lock);

    p->tgid = p->pid;
    p->group_leader = p;

    if (!(p->context = arch_context_alloc())) {
        fdtable_put(p->fdtable);
        p->fdtable = NULL;
        p->state = PROC_UNUSED;
        return NULL;
    }
    signal_init_process(p);
    p->start_time = arch_timer_ticks();
    p->vfork_parent = NULL;
    p->vfork_done = true;
    return p;
}

struct process *proc_alloc_internal(void) {
    return proc_alloc();
}

void proc_adopt_child(struct process *parent, struct process *child) {
    if (!parent || !child) {
        return;
    }
    child->parent = parent;
    child->ppid = parent->pid;
    child->syscall_abi = parent->syscall_abi;
    child->umask = parent->umask;
    memcpy(child->rlimits, parent->rlimits, sizeof(child->rlimits));
    spin_lock(&proc_table_lock);
    list_add(&child->sibling, &parent->children);
    spin_unlock(&proc_table_lock);
    memcpy(child->cwd, parent->cwd, CONFIG_PATH_MAX);
    child->cwd_vnode = parent->cwd_vnode;
    if (child->cwd_vnode)
        vnode_get(child->cwd_vnode);
    child->cwd_dentry = parent->cwd_dentry;
    if (child->cwd_dentry)
        dentry_get(child->cwd_dentry);
    child->mnt_ns = parent->mnt_ns;
    if (child->mnt_ns)
        vfs_mount_ns_get_from(child->mnt_ns);
}

void proc_free_internal(struct process *p) {
    if (p && p->context) {
        arch_context_free(p->context);
        p->context = NULL;
    }
    if (p && p->sighand) {
        sighand_put(p->sighand);
        p->sighand = NULL;
    }
    if (p && p->fdtable) {
        fdtable_put(p->fdtable);
        p->fdtable = NULL;
    }
    if (p) {
        if (!list_empty(&p->thread_group)) {
            list_del(&p->thread_group);
            INIT_LIST_HEAD(&p->thread_group);
        }
        p->state = PROC_UNUSED;
        p->pid = 0;
    }
}

void proc_free(struct process *p) {
    if (!p) {
        return;
    }
    if (p->mm)
        mm_destroy(p->mm);
    if (p->cwd_vnode) {
        vnode_put(p->cwd_vnode);
        p->cwd_vnode = NULL;
    }
    if (p->cwd_dentry) {
        dentry_put(p->cwd_dentry);
        p->cwd_dentry = NULL;
    }
    if (p->mnt_ns) {
        vfs_mount_ns_put(p->mnt_ns);
        p->mnt_ns = NULL;
    }
    spin_lock(&proc_table_lock);
    if (!list_empty(&p->sibling)) {
        list_del(&p->sibling);
    }
    INIT_LIST_HEAD(&p->sibling);
    spin_unlock(&proc_table_lock);
    proc_free_internal(p);
}

struct process *proc_current(void) {
    return arch_get_percpu()->curr_proc;
}

void proc_set_current(struct process *p) {
    arch_get_percpu()->curr_proc = p;
}

struct process *proc_find(pid_t pid) {
    if (pid <= 0)
        return NULL;
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

struct process *kthread_create(int (*fn)(void *), void *arg, const char *name) {
    struct process *p = proc_alloc();
    if (!p)
        return NULL;
    proc_set_name(p, name);
    arch_context_init(p->context, (vaddr_t)fn, (vaddr_t)arg, true);
    p->state = PROC_RUNNABLE;
    return p;
}

static int idle_thread(void *arg __attribute__((unused))) {
    while (1) {
        arch_irq_enable();
        arch_cpu_halt();
        schedule();
    }
}

struct process *proc_idle_init(void) {
    struct process *p = proc_alloc();
    if (!p)
        panic("idle alloc fail");
    proc_set_name(p, "idle");
    p->se.nice = 19;
    if (!p->context)
        panic("idle ctx missing");
    arch_context_init(p->context, (vaddr_t)idle_thread, 0, true);
    /*
     * Bootstrap: idle is initialized before the scheduler is fully ready.
     * Direct writes to run_state/on_cpu/on_rq are intentional — the per-CPU
     * locks and state that se_mark_running() depends on are not yet established.
     * Do NOT "fix" these into helper calls.
     */
    p->state = PROC_RUNNING;
    p->se.run_state = SE_STATE_RUNNING;
    p->se.on_cpu = true;
    p->se.on_rq = false;
    struct percpu_data *cpu = arch_get_percpu();
    cpu->idle_proc = p;
    cpu->curr_proc = p;
    sched_set_idle(p);
    return p;
}

void proc_lock(struct process *p) {
    if (!p)
        return;
    spin_lock(&p->lock);
}

void proc_unlock(struct process *p) {
    if (!p)
        return;
    spin_unlock(&p->lock);
}

int proc_sleep_on(struct wait_queue *wq, void *channel, bool interruptible) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (interruptible && p->sig_pending)
        return -EINTR;

    if (wq)
        wait_queue_add(wq, p);

    proc_lock(p);
    /*
     * A wakeup can happen after wait_queue_add() but before we mark the task
     * sleeping. In that case wait_queue_wakeup() already removed wait_entry.
     */
    if (wq && !p->wait_entry.active) {
        p->wait_channel = NULL;
        p->sleep_deadline = 0;
        p->state = PROC_RUNNING;
        proc_unlock(p);
        if (interruptible && p->sig_pending)
            return -EINTR;
        return 0;
    }
    p->wait_channel = channel;
    p->sleep_deadline = 0;
    p->state = PROC_SLEEPING;
    sched_trace_event(SCHED_TRACE_SLEEP, p, (uint64_t)channel, 0);
    proc_unlock(p);

    schedule();

    proc_lock(p);
    if (p->wait_entry.active)
        wait_queue_remove_entry(&p->wait_entry);
    p->wait_channel = NULL;
    p->sleep_deadline = 0;
    if (p->state == PROC_SLEEPING)
        p->state = PROC_RUNNING;
    proc_unlock(p);

    if (interruptible && p->sig_pending)
        return -EINTR;
    return 0;
}

int proc_sleep_on_mutex(struct wait_queue *wq, void *channel,
                        struct mutex *mtx, bool interruptible) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (interruptible && p->sig_pending)
        return -EINTR;

    if (wq)
        wait_queue_add(wq, p);

    proc_lock(p);
    /*
     * Handle early wakeup racing between wait_queue_add() and sleep state set.
     */
    if (wq && !p->wait_entry.active) {
        p->wait_channel = NULL;
        p->sleep_deadline = 0;
        p->state = PROC_RUNNING;
        proc_unlock(p);
        if (interruptible && p->sig_pending)
            return -EINTR;
        return 0;
    }
    p->wait_channel = channel;
    p->sleep_deadline = 0;
    p->state = PROC_SLEEPING;
    sched_trace_event(SCHED_TRACE_SLEEP, p, (uint64_t)channel, 0);
    proc_unlock(p);

    if (mtx)
        mutex_unlock(mtx);

    schedule();

    if (mtx)
        mutex_lock(mtx);

    proc_lock(p);
    if (p->wait_entry.active)
        wait_queue_remove_entry(&p->wait_entry);
    p->wait_channel = NULL;
    p->sleep_deadline = 0;
    if (p->state == PROC_SLEEPING)
        p->state = PROC_RUNNING;
    proc_unlock(p);

    if (interruptible && p->sig_pending)
        return -EINTR;
    return 0;
}

int proc_sleep_on_mutex_timeout(struct wait_queue *wq, void *channel,
                                struct mutex *mtx, bool interruptible,
                                uint64_t deadline) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (interruptible && p->sig_pending)
        return -EINTR;

    if (wq)
        wait_queue_add(wq, p);

    proc_lock(p);
    /*
     * Handle early wakeup racing between wait_queue_add() and sleep state set.
     */
    if (wq && !p->wait_entry.active) {
        p->wait_channel = NULL;
        p->sleep_deadline = 0;
        p->state = PROC_RUNNING;
        proc_unlock(p);
        if (interruptible && p->sig_pending)
            return -EINTR;
        return 0;
    }
    p->wait_channel = channel;
    p->sleep_deadline = deadline;
    p->state = PROC_SLEEPING;
    sched_trace_event(SCHED_TRACE_SLEEP, p, (uint64_t)channel, deadline);
    proc_unlock(p);

    if (mtx)
        mutex_unlock(mtx);

    schedule();

    if (mtx)
        mutex_lock(mtx);

    proc_lock(p);
    if (p->wait_entry.active)
        wait_queue_remove_entry(&p->wait_entry);
    p->wait_channel = NULL;
    uint64_t dl = p->sleep_deadline;
    p->sleep_deadline = 0;
    if (p->state == PROC_SLEEPING)
        p->state = PROC_RUNNING;
    proc_unlock(p);

    if (interruptible && p->sig_pending)
        return -EINTR;
    if (dl != 0 && arch_timer_get_ticks() >= dl)
        return -ETIMEDOUT;
    return 0;
}
