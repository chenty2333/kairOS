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

static struct kmem_cache *proc_cache;
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
        wait_queue_entry_init(&proc_table[i].wait_entry, &proc_table[i]);
        mutex_init(&proc_table[i].files_lock, "files_lock");
        wait_queue_init(&proc_table[i].exit_wait);
        wait_queue_init(&proc_table[i].vfork_wait);
        spin_init(&proc_table[i].lock);
    }
    proc_cache = kmem_cache_create("process", sizeof(struct process), NULL);
    pr_info("Process: initialized (cache ready)\n");
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
    if (p->files[0] || p->files[1] || p->files[2]) {
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

    p->ppid = p->uid = p->gid = p->vruntime = p->nice = 0;
    p->pgid = p->pid;
    p->sid = p->pid;
    p->umask = 022;
    p->syscall_abi = SYSCALL_ABI_LINUX;
    p->name[0] = '\0';
    p->mm = NULL;
    p->parent = NULL;
    p->on_rq = false;
    p->on_cpu = false;
    p->cpu = -1;
    p->last_run_time = 0;
    p->exit_code = p->sig_pending = p->sig_blocked = 0;
    p->wait_channel = NULL;
    memset(p->files, 0, sizeof(p->files));
    memset(p->fd_flags, 0, sizeof(p->fd_flags));
    mutex_init(&p->files_lock, "files_lock");
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
    wait_queue_entry_init(&p->wait_entry, p);
    wait_queue_init(&p->exit_wait);
    wait_queue_init(&p->vfork_wait);
    spin_init(&p->lock);

    if (!(p->context = arch_context_alloc())) {
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
    child->tid_address = parent->tid_address;
    memcpy(child->rlimits, parent->rlimits, sizeof(child->rlimits));
    child->umask = parent->umask;
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
    if (p && p->sigactions) {
        kfree(p->sigactions);
        p->sigactions = NULL;
    }
    if (p) {
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
    if (!list_empty(&p->sibling)) {
        spin_lock(&proc_table_lock);
        if (!list_empty(&p->sibling))
            list_del(&p->sibling);
        spin_unlock(&proc_table_lock);
    }
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
    p->nice = 19;
    if (!p->context)
        panic("idle ctx missing");
    arch_context_init(p->context, (vaddr_t)idle_thread, 0, true);
    p->state = PROC_RUNNING;
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
    p->wait_channel = channel;
    p->state = PROC_SLEEPING;
    proc_unlock(p);

    schedule();

    proc_lock(p);
    if (p->wait_entry.active)
        wait_queue_remove_entry(&p->wait_entry);
    p->wait_channel = NULL;
    if (p->state == PROC_SLEEPING)
        p->state = PROC_RUNNING;
    proc_unlock(p);

    if (interruptible && p->sig_pending)
        return -EINTR;
    return 0;
}
