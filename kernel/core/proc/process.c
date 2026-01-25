/**
 * kernel/core/proc/process.c - Process Management
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

/* Process table and cache */
static struct kmem_cache *proc_cache;
static struct process proc_table[CONFIG_MAX_PROCESSES];
static spinlock_t proc_table_lock = SPINLOCK_INIT;

/* PID allocation */
static pid_t next_pid = 1;

/* Current process (per-CPU) */
static struct process *current_proc = NULL;
static struct process *idle_proc = NULL;

void proc_init(void) {
    memset(proc_table, 0, sizeof(proc_table));
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        proc_table[i].state = PROC_UNUSED;
        INIT_LIST_HEAD(&proc_table[i].children);
        INIT_LIST_HEAD(&proc_table[i].sibling);
        INIT_LIST_HEAD(&proc_table[i].wait_list);
        INIT_LIST_HEAD(&proc_table[i].sched_list);
    }
    proc_cache = kmem_cache_create("process", sizeof(struct process), NULL);
    pr_info("Process: initialized (cache ready)\n");
}

static void proc_set_name(struct process *p, const char *name) {
    strncpy(p->name, name, sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';
}

static struct process *proc_alloc(void) {
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

    if (!p)
        return NULL;

    /* Initialize essential fields */
    p->ppid = p->uid = p->gid = p->vruntime = p->nice = 0;
    p->name[0] = '\0';
    p->mm = NULL;
    p->parent = NULL;
    p->on_rq = false;
    p->exit_code = p->sig_pending = p->sig_blocked = 0;
    p->wait_channel = NULL;
    memset(p->files, 0, sizeof(p->files));
    strcpy(p->cwd, "/");

    INIT_LIST_HEAD(&p->children);
    INIT_LIST_HEAD(&p->sibling);
    INIT_LIST_HEAD(&p->wait_list);
    INIT_LIST_HEAD(&p->sched_list);

    if (!(p->context = arch_context_alloc())) {
        p->state = PROC_UNUSED;
        return NULL;
    }

    signal_init_process(p);
    p->start_time = arch_timer_ticks();
    return p;
}

struct process *proc_alloc_internal(void) {
    return proc_alloc();
}

void proc_free_internal(struct process *p) {
    if (p && p->context) {
        arch_context_free(p->context);
        p->context = NULL;
    }
    if (p) {
        p->state = PROC_UNUSED;
        p->pid = 0;
    }
}

static void proc_free(struct process *p) {
    if (!p)
        return;
    if (p->mm)
        mm_destroy(p->mm);
    if (!list_empty(&p->sibling))
        list_del(&p->sibling);
    proc_free_internal(p);
}

struct process *proc_current(void) {
    return current_proc;
}
void proc_set_current(struct process *p) {
    current_proc = p;
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
        panic("Failed to allocate idle process");

    p->pid = 0; /* Traditional PID for idle */
    proc_set_name(p, "idle");
    p->nice = 19; /* Lowest priority */
    
    if (!(p->context = arch_context_alloc()))
        panic("Idle context fail");
        
    arch_context_init(p->context, (vaddr_t)idle_thread, 0, true);
    p->state = PROC_RUNNING;
    
    struct percpu_data *cpu = arch_get_percpu();
    cpu->idle_proc = p;
    cpu->curr_proc = p;
    sched_set_idle(p);
    
    return p;
}

struct process *proc_idle(void) {
    return idle_proc;
}

struct process *proc_fork(void) {
    struct process *parent = current_proc, *child;
    if (!parent || !parent->mm || !(child = proc_alloc()))
        return NULL;

    strcpy(child->name, parent->name);
    child->uid = parent->uid;
    child->gid = parent->gid;
    child->parent = parent;
    child->ppid = parent->pid;
    child->nice = parent->nice;
    child->vruntime = parent->vruntime;

    spin_lock(&proc_table_lock);
    list_add(&child->sibling, &parent->children);
    spin_unlock(&proc_table_lock);

    if (!(child->mm = mm_clone(parent->mm))) {
        proc_free(child);
        return NULL;
    }

    memcpy(child->cwd, parent->cwd, CONFIG_PATH_MAX);
    for (int i = 0; i < CONFIG_MAX_FILES_PER_PROC; i++) {
        struct file *f = parent->files[i];
        if (f) {
            mutex_lock(&f->lock);
            f->refcount++;
            mutex_unlock(&f->lock);
            child->files[i] = f;
        }
    }

    struct trap_frame *tf = get_current_trapframe();
    if (tf)
        arch_setup_fork_child(child->context, tf);
    else
        arch_context_clone(child->context, parent->context);

    child->state = PROC_RUNNABLE;
    return child;
}

noreturn void proc_exit(int status) {
    struct process *p = current_proc;
    if (p == idle_proc)
        panic("Idle exit");
    pr_info("Process %d exiting: %d\n", p->pid, status);
    sched_dequeue(p);
    p->exit_code = status;
    p->state = PROC_ZOMBIE;
    if (p->parent)
        proc_wakeup(p->parent);
    if (p->mm && !p->parent) {
        arch_irq_disable();
        while (1)
            arch_cpu_halt();
    }
    schedule();
    panic("zombie ret");
}

int proc_exec(const char *path, char *const argv[]) {
    struct vnode *vn;
    struct mm_struct *old_mm, *new_mm;
    vaddr_t entry, sp;
    void *elf_data;
    size_t size;

    /* 1. Open the file */
    vn = vfs_lookup(path);
    if (!vn) return -ENOENT;
    
    if (vn->type != VNODE_FILE) {
        vnode_put(vn);
        return -EACCES;
    }

    size = vn->size;
    if (size > 2 * 1024 * 1024) { /* 2MB limit for now */
        vnode_put(vn);
        return -E2BIG;
    }

    /* 2. Read ELF data into kernel buffer */
    elf_data = kmalloc(size);
    if (!elf_data) {
        vnode_put(vn);
        return -ENOMEM;
    }

    struct file tmp_file = {.vnode = vn, .offset = 0};
    if (vfs_read(&tmp_file, elf_data, size) < (ssize_t)size) {
        kfree(elf_data);
        vnode_put(vn);
        return -EIO;
    }
    vnode_put(vn);

    /* 3. Create new address space */
    if (!(new_mm = mm_create())) {
        kfree(elf_data);
        return -ENOMEM;
    }

    /* 4. Load ELF and setup stack */
    extern int elf_load(struct mm_struct *mm, const void *elf, size_t size, vaddr_t *entry_out);
    extern int elf_setup_stack(struct mm_struct *mm, char *const argv[], char *const envp[], vaddr_t *sp_out);

    if (elf_load(new_mm, elf_data, size, &entry) < 0 ||
        elf_setup_stack(new_mm, argv, NULL, &sp) < 0) {
        mm_destroy(new_mm);
        kfree(elf_data);
        return -ENOEXEC;
    }
    kfree(elf_data);

    /* 5. Switch to new MM */
    struct process *curr = proc_current();
    old_mm = curr->mm;
    curr->mm = new_mm;
    arch_mmu_switch(new_mm->pgdir);
    
    if (old_mm) mm_destroy(old_mm);

    /* Update process name */
    const char *name = strrchr(path, '/');
    strncpy(curr->name, name ? name + 1 : path, sizeof(curr->name) - 1);

    /* 6. Update trap frame for return to user mode */
    struct trap_frame *tf = get_current_trapframe();
    if (tf) {
        tf->sepc = entry;
        tf->tf_sp = sp;
        /* Clear args for new program */
        tf->tf_a0 = 0; 
    }

    return 0;
}

void proc_yield(void) {
    schedule();
}
void proc_wakeup(struct process *p) {
    if (p && p->state == PROC_SLEEPING) {
        p->state = PROC_RUNNABLE;
        sched_enqueue(p);
    }
}

void proc_sleep(void *channel) {
    struct process *p = current_proc;
    p->wait_channel = channel;
    p->state = PROC_SLEEPING;
    schedule();
    p->wait_channel = NULL;
}

void proc_wakeup_all(void *channel) {
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

pid_t proc_wait(pid_t pid, int *status, int options __attribute__((unused))) {
    struct process *p = current_proc, *child, *tmp;
    while (1) {
        bool found = false;
        spin_lock(&proc_table_lock);
        list_for_each_entry_safe(child, tmp, &p->children, sibling) {
            found = true;
            if (pid > 0 && child->pid != pid)
                continue;
            if (child->state == PROC_ZOMBIE) {
                pid_t cpid = child->pid;
                if (status)
                    *status = child->exit_code;
                proc_free(child);
                spin_unlock(&proc_table_lock);
                return cpid;
            }
        }
        spin_unlock(&proc_table_lock);
        if (!found)
            return -ECHILD;
        proc_sleep(p);
    }
}

void wait_queue_init(struct wait_queue *wq) {
    spin_init(&wq->lock);
    INIT_LIST_HEAD(&wq->head);
}

void wait_queue_add(struct wait_queue *wq, struct process *p) {
    spin_lock(&wq->lock);
    list_add_tail(&p->wait_list, &wq->head);
    spin_unlock(&wq->lock);
}

void wait_queue_remove(struct wait_queue *wq, struct process *p) {
    spin_lock(&wq->lock);
    list_del(&p->wait_list);
    INIT_LIST_HEAD(&p->wait_list);
    spin_unlock(&wq->lock);
}

static void _wait_queue_wakeup(struct wait_queue *wq, bool all) {
    spin_lock(&wq->lock);
    while (!list_empty(&wq->head)) {
        struct process *p =
            list_first_entry(&wq->head, struct process, wait_list);
        list_del(&p->wait_list);
        INIT_LIST_HEAD(&p->wait_list);
        proc_wakeup(p);
        if (!all)
            break;
    }
    spin_unlock(&wq->lock);
}

void wait_queue_wakeup_one(struct wait_queue *wq) {
    _wait_queue_wakeup(wq, false);
}
void wait_queue_wakeup_all(struct wait_queue *wq) {
    _wait_queue_wakeup(wq, true);
}