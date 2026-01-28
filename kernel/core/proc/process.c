/**
 * kernel/core/proc/process.c - Process Management (Solid Foundation)
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/futex.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#ifdef ARCH_riscv64
#include "user_init_blob.h"
#endif

static struct kmem_cache *proc_cache;
static struct process proc_table[CONFIG_MAX_PROCESSES];
static spinlock_t proc_table_lock = SPINLOCK_INIT;
static pid_t next_pid = 1;
static struct process *reaper_proc = NULL;

static void proc_reparent_children(struct process *p);

void proc_init(void) {
    memset(proc_table, 0, sizeof(proc_table));
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        proc_table[i].state = PROC_UNUSED;
        INIT_LIST_HEAD(&proc_table[i].children);
        INIT_LIST_HEAD(&proc_table[i].sibling);
        INIT_LIST_HEAD(&proc_table[i].wait_list);
        mutex_init(&proc_table[i].files_lock, "files_lock");
        wait_queue_init(&proc_table[i].exit_wait);
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
    if (!p) return;
    int ret = vfs_open_at("/", "/dev/console", O_RDWR, 0, &f);
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
    if (!p) return;
    if (p->files[0] || p->files[1] || p->files[2]) return;
    proc_attach_console(p);
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

    if (!p) return NULL;

    p->ppid = p->uid = p->gid = p->vruntime = p->nice = 0;
    p->umask = 022;
    p->syscall_abi = SYSCALL_ABI_LINUX;
    p->name[0] = '\0'; p->mm = NULL; p->parent = NULL;
    p->on_rq = false; p->on_cpu = false; p->cpu = -1;
    p->last_run_time = 0;
    p->exit_code = p->sig_pending = p->sig_blocked = 0;
    p->wait_channel = NULL;
    memset(p->files, 0, sizeof(p->files));
    mutex_init(&p->files_lock, "files_lock");
    strcpy(p->cwd, "/");
    p->cwd_vnode = NULL;
    p->cwd_dentry = NULL;
    p->mnt_ns = vfs_mount_ns_get();
    p->tid_address = 0;
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
    INIT_LIST_HEAD(&p->wait_list);
    wait_queue_init(&p->exit_wait);

    if (!(p->context = arch_context_alloc())) { p->state = PROC_UNUSED; return NULL; }
    signal_init_process(p);
    p->start_time = arch_timer_ticks();
    return p;
}

static void proc_adopt_child(struct process *parent, struct process *child) {
    if (!parent || !child) return;
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

struct process *proc_alloc_internal(void) { return proc_alloc(); }

void proc_free_internal(struct process *p) {
    if (p && p->context) { arch_context_free(p->context); p->context = NULL; }
    if (p && p->sigactions) { kfree(p->sigactions); p->sigactions = NULL; }
    if (p) { p->state = PROC_UNUSED; p->pid = 0; }
}

static void proc_free(struct process *p) {
    if (!p) return;
    if (p->mm) mm_destroy(p->mm);
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

struct process *proc_current(void) { return arch_get_percpu()->curr_proc; }
void proc_set_current(struct process *p) { arch_get_percpu()->curr_proc = p; }

struct process *proc_find(pid_t pid) {
    if (pid <= 0) return NULL;
    spin_lock(&proc_table_lock);
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        if (proc_table[i].pid == pid && proc_table[i].state != PROC_UNUSED) {
            spin_unlock(&proc_table_lock); return &proc_table[i];
        }
    }
    spin_unlock(&proc_table_lock);
    return NULL;
}

struct process *kthread_create(int (*fn)(void *), void *arg, const char *name) {
    struct process *p = proc_alloc();
    if (!p) return NULL;
    proc_set_name(p, name);
    arch_context_init(p->context, (vaddr_t)fn, (vaddr_t)arg, true);
    p->state = PROC_RUNNABLE;
    return p;
}

static int idle_thread(void *arg __attribute__((unused))) {
    while (1) { arch_irq_enable(); arch_cpu_halt(); schedule(); }
}

struct process *proc_idle_init(void) {
    struct process *p = proc_alloc();
    if (!p) panic("idle alloc fail");
    proc_set_name(p, "idle");
    p->nice = 19;
    if (!p->context) panic("idle ctx missing");
    arch_context_init(p->context, (vaddr_t)idle_thread, 0, true);
    p->state = PROC_RUNNING;
    struct percpu_data *cpu = arch_get_percpu();
    cpu->idle_proc = p; cpu->curr_proc = p;
    sched_set_idle(p);
    return p;
}

struct process *proc_fork(void) {
    struct process *parent = proc_current(), *child;
    if (!parent || !parent->mm || !(child = proc_alloc())) return NULL;

    strcpy(child->name, parent->name);
    child->uid = parent->uid; child->gid = parent->gid;
    child->umask = parent->umask;
    child->tid_address = parent->tid_address;
    memcpy(child->rlimits, parent->rlimits, sizeof(child->rlimits));
    child->parent = parent; child->ppid = parent->pid;
    child->nice = parent->nice; child->vruntime = parent->vruntime;

    spin_lock(&proc_table_lock);
    list_add(&child->sibling, &parent->children);
    spin_unlock(&proc_table_lock);

    if (!(child->mm = mm_clone(parent->mm))) { proc_free(child); return NULL; }
    memcpy(child->cwd, parent->cwd, CONFIG_PATH_MAX);
    child->cwd_vnode = parent->cwd_vnode;
    if (child->cwd_vnode)
        vnode_get(child->cwd_vnode);
    child->cwd_dentry = parent->cwd_dentry;
    if (child->cwd_dentry)
        dentry_get(child->cwd_dentry);
    child->syscall_abi = parent->syscall_abi;
    mutex_lock(&parent->files_lock);
    for (int i = 0; i < CONFIG_MAX_FILES_PER_PROC; i++) {
        struct file *f = parent->files[i];
        if (f) {
            mutex_lock(&f->lock);
            f->refcount++;
            mutex_unlock(&f->lock);
            child->files[i] = f;
        }
    }
    mutex_unlock(&parent->files_lock);

    struct trap_frame *tf = get_current_trapframe();
    if (tf) arch_setup_fork_child(child->context, tf);
    else arch_context_clone(child->context, parent->context);

    child->state = PROC_RUNNABLE;
    sched_enqueue(child);
    return child;
}

noreturn void proc_exit(int status) {
    struct process *p = proc_current();
    pr_info("Process %d exiting: %d\n", p->pid, status);

    if (p->tid_address) {
        uint32_t zero = 0;
        copy_to_user((void *)p->tid_address, &zero, sizeof(zero));
        futex_wake(p->tid_address, 1);
        p->tid_address = 0;
    }

    fd_close_all(p);
    proc_reparent_children(p);

    sched_dequeue(p);
    p->exit_code = status;
    p->state = PROC_ZOMBIE;
    
    if (p->parent) {
        wait_queue_wakeup_all(&p->parent->exit_wait);
    }
    
    schedule();
    while(1) arch_cpu_halt();
}

int proc_exec(const char *path, char *const argv[]) {
    struct vnode *vn;
    struct mm_struct *old_mm, *new_mm;
    vaddr_t entry, sp;
    void *elf_data;
    size_t size;

    vn = vfs_lookup(path);
    if (!vn) return -ENOENT;
    if (vn->type != VNODE_FILE) { vnode_put(vn); return -EACCES; }

    size = vn->size;
    if (size > 2 * 1024 * 1024) { vnode_put(vn); return -E2BIG; }
    elf_data = kmalloc(size);
    if (!elf_data) { vnode_put(vn); return -ENOMEM; }

    struct file tmp_file = {.vnode = vn, .offset = 0};
    if (vfs_read(&tmp_file, elf_data, size) < (ssize_t)size) {
        kfree(elf_data); vnode_put(vn); return -EIO;
    }
    vnode_put(vn);

    if (!(new_mm = mm_create())) { kfree(elf_data); return -ENOMEM; }
    extern int elf_load(struct mm_struct *mm, const void *elf, size_t size, vaddr_t *entry_out);
    extern int elf_setup_stack(struct mm_struct *mm, char *const argv[], char *const envp[], vaddr_t *sp_out);

    if (elf_load(new_mm, elf_data, size, &entry) < 0 ||
        elf_setup_stack(new_mm, argv, NULL, &sp) < 0) {
        mm_destroy(new_mm); kfree(elf_data); return -ENOEXEC;
    }
    kfree(elf_data);

    struct process *curr = proc_current();
    old_mm = curr->mm; curr->mm = new_mm;
    arch_mmu_switch(new_mm->pgdir);
    if (old_mm) mm_destroy(old_mm);

    const char *name = strrchr(path, '/');
    strncpy(curr->name, name ? name + 1 : path, sizeof(curr->name) - 1);

    struct trap_frame *tf = get_current_trapframe();
    if (tf) { tf->sepc = entry; tf->tf_sp = sp; tf->tf_a0 = 0; }
    return 0;
}

static struct process *proc_spawn_from_vfs(const char *path, struct process *parent) {
    struct vnode *vn = vfs_lookup(path);
    if (!vn) return NULL;
    if (vn->type != VNODE_FILE) { vnode_put(vn); return NULL; }

    size_t size = vn->size;
    if (size == 0 || size > 2 * 1024 * 1024) { vnode_put(vn); return NULL; }

    void *elf_data = kmalloc(size);
    if (!elf_data) { vnode_put(vn); return NULL; }

    struct file tmp_file = {.vnode = vn, .offset = 0};
    if (vfs_read(&tmp_file, elf_data, size) < (ssize_t)size) {
        kfree(elf_data);
        vnode_put(vn);
        return NULL;
    }
    vnode_put(vn);

    const char *name = strrchr(path, '/');
    struct process *p = proc_create(name ? name + 1 : path, elf_data, size);
    kfree(elf_data);
    if (!p) return NULL;

    if (parent) proc_adopt_child(parent, p);
    else strcpy(p->cwd, "/");

    return p;
}

static int init_thread(void *arg __attribute__((unused))) {
    struct process *parent = proc_current();
    const char *init_paths[] = {"/init", "/sbin/init", "/bin/init"};
    struct process *child = NULL;

#ifdef ARCH_riscv64
    if (user_init_elf_size > 0) {
        child = proc_create("init", user_init_elf, user_init_elf_size);
        if (child) {
            proc_adopt_child(parent, child);
            pr_info("init: started embedded init (pid %d)\n", child->pid);
            sched_enqueue(child);
        }
    }
#endif

    if (!child) {
        for (size_t i = 0; i < ARRAY_SIZE(init_paths); i++) {
            child = proc_spawn_from_vfs(init_paths[i], parent);
            if (child) {
                pr_info("init: started %s (pid %d)\n", init_paths[i], child->pid);
                sched_enqueue(child);
                break;
            }
        }
    }

    if (!child) {
        pr_warn("init: no user init found, running built-in user test\n");
        run_user_test();
    }

    while (1) {
        int status;
        pid_t pid = proc_wait(-1, &status, 0);
        if (pid < 0) {
            proc_yield();
            continue;
        }
        pr_info("init: reaped pid %d (status %d)\n", pid, status);
    }
}

struct process *proc_start_init(void) {
    struct process *p = kthread_create(init_thread, NULL, "init");
    if (!p) return NULL;
    reaper_proc = p;
    sched_enqueue(p);
    return p;
}

static void proc_reparent_children(struct process *p) {
    struct process *reaper = reaper_proc;
    if (!reaper || reaper == p)
        return;

    bool wake_reaper = false;
    spin_lock(&proc_table_lock);
    struct process *child, *tmp;
    list_for_each_entry_safe(child, tmp, &p->children, sibling) {
        list_del(&child->sibling);
        child->parent = reaper;
        child->ppid = reaper->pid;
        list_add_tail(&child->sibling, &reaper->children);
        if (child->state == PROC_ZOMBIE)
            wake_reaper = true;
    }
    spin_unlock(&proc_table_lock);
    if (wake_reaper)
        wait_queue_wakeup_all(&reaper->exit_wait);
}

static bool is_process_active(struct process *p) {
    for (int i = 0; i < CONFIG_MAX_CPUS; i++) {
        struct percpu_data *cpu = sched_cpu_data(i);
        if (!cpu) continue;
        if (__atomic_load_n(&cpu->curr_proc, __ATOMIC_ACQUIRE) == p) return true;
        if (__atomic_load_n(&cpu->prev_task, __ATOMIC_ACQUIRE) == p) return true;
    }
    return false;
}

pid_t proc_wait(pid_t pid, int *status, int options __attribute__((unused))) {
    struct process *p = proc_current(), *child, *tmp;
    while (1) {
        bool found = false;
        bool busy_zombie = false;
        struct process *reap = NULL;
        spin_lock(&proc_table_lock);
        list_for_each_entry_safe(child, tmp, &p->children, sibling) {
            found = true;
            if (pid > 0 && child->pid != pid) continue;
            if (child->state == PROC_ZOMBIE) {
                if (__atomic_load_n(&child->on_cpu, __ATOMIC_ACQUIRE)) {
                    if (is_process_active(child)) {
                        busy_zombie = true;
                        continue;
                    }
                }
                child->state = PROC_REAPING;
                list_del(&child->sibling);
                reap = child;
                break;
            }
        }
        spin_unlock(&proc_table_lock);
        if (reap) {
            pid_t cpid = reap->pid;
            if (status) *status = reap->exit_code;
            proc_free(reap);
            return cpid;
        }
        if (!found) return -ECHILD;

        if (busy_zombie) {
            proc_yield();
            continue;
        }

        p->state = PROC_SLEEPING;
        p->wait_channel = &p->exit_wait;
        wait_queue_add(&p->exit_wait, p);
        
        schedule();
    }
}

void proc_yield(void) { schedule(); }
void proc_wakeup(struct process *p) {
    if (!p || p->state != PROC_SLEEPING)
        return;

    if (p->wait_channel && !list_empty(&p->wait_list))
        wait_queue_remove((struct wait_queue *)p->wait_channel, p);
    p->wait_channel = NULL;
    p->state = PROC_RUNNABLE;
    sched_enqueue(p);
}

void proc_sleep(void *channel) { 
    struct process *p = proc_current();
    p->wait_channel = channel; p->state = PROC_SLEEPING;
    schedule();
    p->wait_channel = NULL;
}

void proc_wakeup_all(void *channel) {
    spin_lock(&proc_table_lock);
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        struct process *p = &proc_table[i];
        if (p->state == PROC_SLEEPING && p->wait_channel == channel) {
            p->state = PROC_RUNNABLE; p->wait_channel = NULL; sched_enqueue(p);
        }
    }
    spin_unlock(&proc_table_lock);
}
