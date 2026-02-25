/**
 * kernel/include/kairos/process.h - Process management
 */

#ifndef _KAIROS_PROCESS_H
#define _KAIROS_PROCESS_H

#include <kairos/atomic.h>
#include <kairos/completion.h>
#include <kairos/config.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/rbtree.h>
#include <kairos/sched_types.h>
#include <kairos/spinlock.h>
#include <kairos/signal.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/wait.h>

struct vnode;
struct dentry;
struct mount_ns;
struct tty_struct;

/* Process exit callback */
typedef void (*proc_exit_callback_t)(struct process *p);

#define PROC_EXIT_CALLBACKS_MAX 8

void proc_register_exit_callback(proc_exit_callback_t callback);

/* Shared file descriptor table */
struct fdtable {
    struct file *files[CONFIG_MAX_FILES_PER_PROC];
    uint32_t fd_flags[CONFIG_MAX_FILES_PER_PROC];
    struct mutex lock;
    atomic_t refcount;
};

struct fdtable *fdtable_alloc(void);
struct fdtable *fdtable_copy(struct fdtable *src);
void fdtable_get(struct fdtable *fdt);
void fdtable_put(struct fdtable *fdt);

/* Shared signal handler table */
struct sighand_struct {
    struct sigaction actions[CONFIG_NSIG];
    atomic_t refcount;
    spinlock_t lock;
};

struct sighand_struct *sighand_alloc(void);
struct sighand_struct *sighand_copy(struct sighand_struct *src);
void sighand_get(struct sighand_struct *sh);
void sighand_put(struct sighand_struct *sh);

enum proc_state {
    PROC_UNUSED,
    PROC_EMBRYO,
    PROC_RUNNABLE,
    PROC_RUNNING,
    PROC_SLEEPING,
    PROC_ZOMBIE,
    PROC_REAPING
};

enum syscall_abi {
    SYSCALL_ABI_LINUX = 0,
    SYSCALL_ABI_LEGACY = 1,
};

enum proc_sched_flags {
    PROC_SCHEDF_STEALABLE = (1U << 0),
    PROC_SCHEDF_KTHREAD   = (1U << 1),
};

#define PROC_SCHED_AFFINITY_WORD_BITS 64U
#define PROC_SCHED_AFFINITY_WORDS \
    ((CONFIG_MAX_CPUS + PROC_SCHED_AFFINITY_WORD_BITS - 1U) / \
     PROC_SCHED_AFFINITY_WORD_BITS)
#define PROC_SCHED_AFFINITY_BYTES \
    (PROC_SCHED_AFFINITY_WORDS * sizeof(unsigned long))

#if (CONFIG_MAX_CPUS % PROC_SCHED_AFFINITY_WORD_BITS) == 0
#define PROC_SCHED_AFFINITY_LAST_WORD_MASK (~0UL)
#else
#define PROC_SCHED_AFFINITY_LAST_WORD_MASK \
    ((1UL << (CONFIG_MAX_CPUS % PROC_SCHED_AFFINITY_WORD_BITS)) - 1UL)
#endif

struct process {
    pid_t pid, ppid;
    pid_t pgid, sid;
    struct tty_struct *ctty;        /* controlling terminal */
    char name[16];
    uid_t uid;
    gid_t gid;
    mode_t umask;
    enum syscall_abi syscall_abi;
    enum proc_state state;
    uint32_t sched_flags;
    unsigned long sched_affinity[PROC_SCHED_AFFINITY_WORDS];
    int exit_code;
    spinlock_t lock;
    bool irq_flags;         /* saved IRQ state for proc_lock/proc_unlock */

    /* Scheduling */
    struct sched_entity se;

    struct mm_struct *mm;
    void *active_tf; /* trap frame while running in trap/syscall context */
    struct fdtable *fdtable;
    char cwd[CONFIG_PATH_MAX];
    struct vnode *cwd_vnode;
    struct dentry *cwd_dentry;
    struct mount_ns *mnt_ns;
    uint64_t tid_address;
    uint64_t tid_set_address;
    uint64_t robust_list;
    uint64_t robust_len;
    struct rlimit rlimits[RLIM_NLIMITS];
    struct itimerval itimer_real;
    stack_t sigaltstack;

    /* Thread group */
    pid_t tgid;
    struct process *group_leader;
    struct list_head thread_group;

    /* Signals & Waiting */
    uint64_t sig_pending, sig_blocked;
    struct sighand_struct *sighand;
    void *wait_channel;
    uint64_t sleep_deadline;  /* 0 = no timeout; >0 = tick deadline */
    struct wait_queue exit_wait;
    struct completion vfork_completion;
    struct wait_queue_entry wait_entry;
    struct list_head children, sibling;
    struct process *parent;
    struct process *vfork_parent;
    struct arch_context *context;
    uint64_t kstack_top;
    uint64_t utime, stime, start_time;
};

_Static_assert(sizeof(unsigned long) == 8,
               "proc affinity helpers assume 64-bit unsigned long");

static inline sigset_t proc_pending_unblocked_signals(const struct process *p) {
    if (!p)
        return 0;
    sigset_t pending = __atomic_load_n(&p->sig_pending, __ATOMIC_ACQUIRE);
    sigset_t blocked = __atomic_load_n(&p->sig_blocked, __ATOMIC_ACQUIRE);
    return pending & ~blocked;
}

static inline bool proc_has_unblocked_signal(const struct process *p) {
    return proc_pending_unblocked_signals(p) != 0;
}

/* Atomic state store — orders prior writes (e.g. exit_code) before state. */
static inline void proc_set_state_release(struct process *p,
                                          enum proc_state s) {
    _Static_assert(sizeof(p->state) == sizeof(int), "enum proc_state size");
    __atomic_store_n((int *)&p->state, (int)s, __ATOMIC_RELEASE);
}

static inline bool proc_sched_is_stealable(const struct process *p) {
    if (!p)
        return false;
    return (__atomic_load_n(&p->sched_flags, __ATOMIC_ACQUIRE) &
            PROC_SCHEDF_STEALABLE) != 0;
}

static inline size_t proc_sched_affinity_word_count(void) {
    return (size_t)PROC_SCHED_AFFINITY_WORDS;
}

static inline size_t proc_sched_affinity_bytes(void) {
    return (size_t)PROC_SCHED_AFFINITY_BYTES;
}

static inline void proc_sched_affinity_zero(unsigned long *mask) {
    if (!mask)
        return;
    for (size_t i = 0; i < PROC_SCHED_AFFINITY_WORDS; i++)
        mask[i] = 0;
}

static inline void proc_sched_affinity_fill_all(unsigned long *mask) {
    if (!mask)
        return;
    for (size_t i = 0; i < PROC_SCHED_AFFINITY_WORDS; i++)
        mask[i] = ~0UL;
    mask[PROC_SCHED_AFFINITY_WORDS - 1] &= PROC_SCHED_AFFINITY_LAST_WORD_MASK;
}

static inline bool proc_sched_affinity_is_zero(const unsigned long *mask) {
    if (!mask)
        return true;
    for (size_t i = 0; i < PROC_SCHED_AFFINITY_WORDS; i++) {
        if (mask[i] != 0)
            return false;
    }
    return true;
}

static inline void proc_sched_affinity_sanitize(unsigned long *mask) {
    if (!mask)
        return;
    mask[PROC_SCHED_AFFINITY_WORDS - 1] &= PROC_SCHED_AFFINITY_LAST_WORD_MASK;
    if (proc_sched_affinity_is_zero(mask))
        proc_sched_affinity_fill_all(mask);
}

static inline void proc_sched_affinity_copy(unsigned long *dst,
                                            const unsigned long *src) {
    if (!dst || !src)
        return;
    for (size_t i = 0; i < PROC_SCHED_AFFINITY_WORDS; i++)
        dst[i] = src[i];
}

static inline bool proc_sched_affinity_mask_test_cpu(const unsigned long *mask,
                                                     int cpu) {
    if (!mask || cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        return false;
    size_t word = (size_t)cpu / PROC_SCHED_AFFINITY_WORD_BITS;
    unsigned int bit = (unsigned int)cpu % PROC_SCHED_AFFINITY_WORD_BITS;
    return (mask[word] & (1UL << bit)) != 0;
}

static inline bool proc_sched_affinity_mask_set_cpu(unsigned long *mask, int cpu) {
    if (!mask || cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        return false;
    size_t word = (size_t)cpu / PROC_SCHED_AFFINITY_WORD_BITS;
    unsigned int bit = (unsigned int)cpu % PROC_SCHED_AFFINITY_WORD_BITS;
    mask[word] |= (1UL << bit);
    return true;
}

static inline uint64_t proc_sched_all_cpus_mask(void) {
    unsigned long word0 = ~0UL;
    if (PROC_SCHED_AFFINITY_WORDS == 1)
        word0 &= PROC_SCHED_AFFINITY_LAST_WORD_MASK;
    return (uint64_t)word0;
}

static inline uint64_t proc_sched_cpu_mask(int cpu) {
    if (cpu < 0 || cpu >= (int)PROC_SCHED_AFFINITY_WORD_BITS)
        return 0;
    return (1ULL << cpu);
}

static inline uint64_t proc_sched_sanitize_affinity_mask(uint64_t mask) {
    unsigned long word0 = (unsigned long)mask;
    if (PROC_SCHED_AFFINITY_WORDS == 1)
        word0 &= PROC_SCHED_AFFINITY_LAST_WORD_MASK;
    if (word0 == 0) {
        word0 = ~0UL;
        if (PROC_SCHED_AFFINITY_WORDS == 1)
            word0 &= PROC_SCHED_AFFINITY_LAST_WORD_MASK;
    }
    mask = (uint64_t)word0;
    return mask;
}

static inline void proc_sched_set_affinity_all(struct process *p) {
    if (!p)
        return;
    unsigned long mask[PROC_SCHED_AFFINITY_WORDS];
    proc_sched_affinity_fill_all(mask);
    for (size_t i = 0; i < PROC_SCHED_AFFINITY_WORDS; i++)
        __atomic_store_n(&p->sched_affinity[i], mask[i], __ATOMIC_RELEASE);
}

static inline void proc_sched_set_affinity_mask_words(struct process *p,
                                                      const unsigned long *mask,
                                                      size_t words) {
    if (!p || !mask || words == 0)
        return;
    unsigned long sanitized[PROC_SCHED_AFFINITY_WORDS];
    proc_sched_affinity_zero(sanitized);
    size_t n = words;
    if (n > PROC_SCHED_AFFINITY_WORDS)
        n = PROC_SCHED_AFFINITY_WORDS;
    for (size_t i = 0; i < n; i++)
        sanitized[i] = mask[i];
    proc_sched_affinity_sanitize(sanitized);
    for (size_t i = 0; i < PROC_SCHED_AFFINITY_WORDS; i++)
        __atomic_store_n(&p->sched_affinity[i], sanitized[i], __ATOMIC_RELEASE);
}

static inline void proc_sched_get_affinity_mask_words(const struct process *p,
                                                      unsigned long *mask,
                                                      size_t words) {
    if (!mask || words == 0)
        return;
    unsigned long current[PROC_SCHED_AFFINITY_WORDS];
    if (!p) {
        proc_sched_affinity_fill_all(current);
    } else {
        for (size_t i = 0; i < PROC_SCHED_AFFINITY_WORDS; i++)
            current[i] = __atomic_load_n(&p->sched_affinity[i], __ATOMIC_ACQUIRE);
        proc_sched_affinity_sanitize(current);
    }
    size_t n = words;
    if (n > PROC_SCHED_AFFINITY_WORDS)
        n = PROC_SCHED_AFFINITY_WORDS;
    for (size_t i = 0; i < n; i++)
        mask[i] = current[i];
    for (size_t i = n; i < words; i++)
        mask[i] = 0;
}

static inline uint64_t proc_sched_get_affinity_mask(const struct process *p) {
    unsigned long mask[PROC_SCHED_AFFINITY_WORDS];
    proc_sched_get_affinity_mask_words(p, mask, PROC_SCHED_AFFINITY_WORDS);
    return (uint64_t)mask[0];
}

static inline void proc_sched_set_affinity_mask(struct process *p,
                                                uint64_t mask) {
    unsigned long words[PROC_SCHED_AFFINITY_WORDS];
    proc_sched_affinity_zero(words);
    words[0] = (unsigned long)proc_sched_sanitize_affinity_mask(mask);
    proc_sched_set_affinity_mask_words(p, words, PROC_SCHED_AFFINITY_WORDS);
}

static inline bool proc_sched_cpu_allowed(const struct process *p, int cpu) {
    if (!p || cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        return false;
    unsigned long mask[PROC_SCHED_AFFINITY_WORDS];
    proc_sched_get_affinity_mask_words(p, mask, PROC_SCHED_AFFINITY_WORDS);
    return proc_sched_affinity_mask_test_cpu(mask, cpu);
}

static inline void proc_sched_set_stealable(struct process *p, bool enabled) {
    if (!p)
        return;
    uint32_t flags = __atomic_load_n(&p->sched_flags, __ATOMIC_RELAXED);
    if (enabled)
        flags |= PROC_SCHEDF_STEALABLE;
    else
        flags &= ~PROC_SCHEDF_STEALABLE;
    __atomic_store_n(&p->sched_flags, flags, __ATOMIC_RELEASE);
}

static inline void proc_sched_mark_kthread(struct process *p) {
    if (!p)
        return;
    uint32_t flags = __atomic_load_n(&p->sched_flags, __ATOMIC_RELAXED);
    flags |= PROC_SCHEDF_KTHREAD;
    flags &= ~PROC_SCHEDF_STEALABLE;
    __atomic_store_n(&p->sched_flags, flags, __ATOMIC_RELEASE);
}

void proc_init(void);
struct process *proc_create(const char *name, const void *elf, size_t size);
struct process *proc_fork(void);
struct proc_fork_opts {
    uint64_t child_stack;
    uint64_t tid_set_address;
    uint64_t tid_clear_address;
    struct process *vfork_parent;
    uint64_t clone_flags;
    uint64_t tls;
};
struct process *proc_fork_ex(const struct proc_fork_opts *opts);
noreturn void proc_exit(int status);
pid_t proc_wait(pid_t pid, int *status, int options);
struct process *proc_find(pid_t pid);
pid_t proc_get_nth_pid(int n);
struct process *proc_current(void);
void proc_set_current(struct process *p);
void proc_lock(struct process *p);
void proc_unlock(struct process *p);
int proc_sleep_on(struct wait_queue *wq, void *channel, bool interruptible);
int proc_sleep_on_mutex(struct wait_queue *wq, void *channel,
                        struct mutex *mtx, bool interruptible);
int proc_sleep_on_mutex_timeout(struct wait_queue *wq, void *channel,
                                struct mutex *mtx, bool interruptible,
                                uint64_t deadline);
struct process *proc_idle_init(void);
struct process *proc_start_init(void);
void proc_yield(void);
int proc_exec(const char *path, char *const argv[], char *const envp[]);
int proc_exec_resolve(const char *path, char *const argv[], char *const envp[],
                      int namei_flags);
void proc_wakeup(struct process *p);
void proc_wake_expired_sleepers(uint64_t now_ticks);
void signal_init_process(struct process *p);
void proc_setup_stdio(struct process *p);
void proc_fork_child_setup(void);

vaddr_t mm_brk(struct mm_struct *mm, vaddr_t newbrk);

void run_fork_test(void);
void run_user_test(void);
void run_crash_test(void);
void run_sync_test(void);
void run_vfork_test(void);

struct process *kthread_create(int (*fn)(void *), void *arg, const char *name);
struct process *kthread_create_joinable(int (*fn)(void *), void *arg,
                                        const char *name);
#define current proc_current()

/* FD management */
int fd_alloc(struct process *p, struct file *file);
int fd_alloc_flags(struct process *p, struct file *file, uint32_t fd_flags);
struct file *fd_get(struct process *p, int fd);
int fd_close(struct process *p, int fd);
int fd_dup(struct process *p, int oldfd);
int fd_dup2(struct process *p, int oldfd, int newfd);
int fd_dup2_flags(struct process *p, int oldfd, int newfd, uint32_t fd_flags);
int fd_dup_min_flags(struct process *p, int oldfd, int minfd,
                     uint32_t fd_flags);
void fd_close_all(struct process *p);
void fd_close_cloexec(struct process *p);

struct process *proc_alloc_internal(void);
void proc_free_internal(struct process *p);

#endif
