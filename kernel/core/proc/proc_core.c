/**
 * kernel/core/proc/proc_core.c - Core process management
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/handle.h>
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
        completion_init(&proc_table[i].vfork_completion);
        complete_all(&proc_table[i].vfork_completion);
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
    bool flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        if (proc_table[i].state == PROC_UNUSED) {
            p = &proc_table[i];
            p->state = PROC_EMBRYO;
            p->pid = next_pid++;
            break;
        }
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);

    if (!p) {
        return NULL;
    }

    p->ppid = p->uid = p->gid = 0;
    p->pgid = p->pid;
    p->sid = p->pid;
    p->ctty = NULL;
    p->umask = 022;
    p->syscall_abi = SYSCALL_ABI_LINUX;
    p->name[0] = '\0';
    p->sched_flags = PROC_SCHEDF_STEALABLE;
    proc_sched_set_affinity_all(p);
    p->mm = NULL;
    p->active_tf = NULL;
    p->parent = NULL;
    p->kstack_top = 0;
    sched_entity_init(&p->se);
    p->exit_code = p->sig_pending = p->sig_blocked = 0;
    p->wait_channel = NULL;
    p->sleep_deadline = 0;
    p->fdtable = fdtable_alloc();
    if (!p->fdtable) {
        p->state = PROC_UNUSED;
        return NULL;
    }
    p->handletable = handletable_alloc();
    if (!p->handletable) {
        fdtable_put(p->fdtable);
        p->fdtable = NULL;
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
    completion_init(&p->vfork_completion);
    complete_all(&p->vfork_completion);
    spin_init(&p->lock);

    p->tgid = p->pid;
    p->group_leader = p;

    if (!(p->context = arch_context_alloc())) {
        handletable_put(p->handletable);
        p->handletable = NULL;
        fdtable_put(p->fdtable);
        p->fdtable = NULL;
        p->state = PROC_UNUSED;
        return NULL;
    }
    p->kstack_top = arch_context_kernel_stack(p->context);
    signal_init_process(p);
    p->start_time = arch_timer_ticks();
    p->vfork_parent = NULL;
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
    bool flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    list_add(&child->sibling, &parent->children);
    spin_unlock_irqrestore(&proc_table_lock, flags);
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
    if (p)
        p->active_tf = NULL;
    if (p && p->context) {
        p->kstack_top = 0;
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
    if (p && p->handletable) {
        handletable_put(p->handletable);
        p->handletable = NULL;
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
    bool flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    if (!list_empty(&p->sibling)) {
        list_del(&p->sibling);
    }
    INIT_LIST_HEAD(&p->sibling);
    spin_unlock_irqrestore(&proc_table_lock, flags);
    proc_free_internal(p);
}

#if defined(ARCH_riscv64) || defined(ARCH_aarch64)
static inline uint64_t proc_read_sp(void) {
    uint64_t sp;
#if defined(ARCH_riscv64)
    __asm__ __volatile__("mv %0, sp" : "=r"(sp));
#else
    __asm__ __volatile__("mov %0, sp" : "=r"(sp));
#endif
    return sp;
}

static bool proc_stack_contains_sp(const struct process *p, uint64_t sp) {
    if (!p || !p->kstack_top)
        return false;
    uint64_t bottom = p->kstack_top + 8 - (2ULL * CONFIG_PAGE_SIZE);
    return sp >= bottom && sp <= p->kstack_top;
}

static struct process *proc_current_from_sp(uint64_t sp) {
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        struct process *cand = &proc_table[i];
        if (cand->state == PROC_UNUSED || cand->state == PROC_EMBRYO)
            continue;
        if (proc_stack_contains_sp(cand, sp))
            return cand;
    }
    return NULL;
}
#endif

struct process *proc_current(void) {
    struct process *curr = arch_get_percpu()->curr_proc;
#if defined(ARCH_riscv64) || defined(ARCH_aarch64)
    uint64_t sp = proc_read_sp();
    if (proc_stack_contains_sp(curr, sp))
        return curr;
    struct process *fallback = proc_current_from_sp(sp);
    if (fallback) {
        if (curr && curr != fallback) {
            static int corrected_warn_count;
            int n = __atomic_fetch_add(&corrected_warn_count, 1,
                                       __ATOMIC_RELAXED);
            if (n < 8) {
                pr_warn("proc_current: corrected stale curr_proc cpu=%d curr=%d fallback=%d sp=%p\n",
                        arch_cpu_id(), curr->pid, fallback->pid, (void *)sp);
            }
        }
        return fallback;
    }
#endif
    return curr;
}

void proc_set_current(struct process *p) {
    arch_get_percpu()->curr_proc = p;
}

struct process *proc_find(pid_t pid) {
    if (pid <= 0)
        return NULL;
    bool flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        if (proc_table[i].pid == pid &&
            proc_table[i].state != PROC_UNUSED &&
            proc_table[i].state != PROC_EMBRYO) {
            spin_unlock_irqrestore(&proc_table_lock, flags);
            return &proc_table[i];
        }
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
    return NULL;
}

pid_t proc_get_nth_pid(int n) {
    int count = 0;
    pid_t pid = -1;
    bool flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        if (proc_table[i].state != PROC_UNUSED &&
            proc_table[i].state != PROC_EMBRYO) {
            if (count == n) {
                pid = proc_table[i].pid;
                break;
            }
            count++;
        }
    }
    spin_unlock_irqrestore(&proc_table_lock, flags);
    return pid;
}

struct process *kthread_create(int (*fn)(void *), void *arg, const char *name) {
    struct process *p = proc_alloc();
    if (!p)
        return NULL;
    proc_sched_mark_kthread(p);
    int cpu = arch_cpu_id();
    if (cpu >= 0 && cpu < CONFIG_MAX_CPUS) {
        p->se.cpu = cpu;
        unsigned long affinity[PROC_SCHED_AFFINITY_WORDS];
        proc_sched_affinity_zero(affinity);
        if (proc_sched_affinity_mask_set_cpu(affinity, cpu))
            proc_sched_set_affinity_mask_words(p, affinity,
                                               PROC_SCHED_AFFINITY_WORDS);
    }
    proc_set_name(p, name);
    arch_context_init(p->context, (vaddr_t)fn, (vaddr_t)arg, true);
    return p;
}

struct process *kthread_create_joinable(int (*fn)(void *), void *arg,
                                        const char *name) {
    struct process *p = kthread_create(fn, arg, name);
    if (!p)
        return NULL;

    struct process *parent = proc_current();
    if (!parent)
        return p;

    p->parent = parent;
    p->ppid = parent->pid;
    bool flags;
    spin_lock_irqsave(&proc_table_lock, &flags);
    list_add(&p->sibling, &parent->children);
    spin_unlock_irqrestore(&proc_table_lock, flags);
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
    proc_sched_mark_kthread(p);
    proc_set_name(p, "idle");
    if (!p->context)
        panic("idle ctx missing");
    arch_context_init(p->context, (vaddr_t)idle_thread, 0, true);
    /*
     * Bootstrap: idle is initialized before the scheduler is fully ready.
     * Use the accessor API to set up the sched_entity without depending
     * on per-CPU locks that aren't established yet.
     */
    p->state = PROC_RUNNING;
    sched_init_idle_entity(p, arch_cpu_id());
    struct percpu_data *cpu = arch_get_percpu();
    cpu->idle_proc = p;
    cpu->curr_proc = p;
    sched_set_idle(p);
    return p;
}

void proc_lock(struct process *p) {
    if (!p)
        return;
    bool flags = arch_irq_save();
    spin_lock(&p->lock);
    p->irq_flags = flags;
}

void proc_unlock(struct process *p) {
    if (!p)
        return;
    bool flags = p->irq_flags;
    spin_unlock(&p->lock);
    arch_irq_restore(flags);
}

int proc_sleep_on(struct wait_queue *wq, void *channel, bool interruptible) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (interruptible && proc_has_unblocked_signal(p))
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
        if (interruptible && proc_has_unblocked_signal(p))
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

    if (interruptible && proc_has_unblocked_signal(p))
        return -EINTR;
    return 0;
}

int proc_sleep_on_mutex(struct wait_queue *wq, void *channel,
                        struct mutex *mtx, bool interruptible) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (interruptible && proc_has_unblocked_signal(p))
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
        if (interruptible && proc_has_unblocked_signal(p))
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

    if (interruptible && proc_has_unblocked_signal(p))
        return -EINTR;
    return 0;
}

int proc_sleep_on_mutex_timeout(struct wait_queue *wq, void *channel,
                                struct mutex *mtx, bool interruptible,
                                uint64_t deadline) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (interruptible && proc_has_unblocked_signal(p))
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
        if (interruptible && proc_has_unblocked_signal(p))
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

    if (interruptible && proc_has_unblocked_signal(p))
        return -EINTR;
    if (dl != 0 && arch_timer_get_ticks() >= dl)
        return -ETIMEDOUT;
    return 0;
}
