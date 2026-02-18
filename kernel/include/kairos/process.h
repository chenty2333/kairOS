/**
 * kernel/include/kairos/process.h - Process management
 */

#ifndef _KAIROS_PROCESS_H
#define _KAIROS_PROCESS_H

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

/* Shared file descriptor table */
struct fdtable {
    struct file *files[CONFIG_MAX_FILES_PER_PROC];
    uint32_t fd_flags[CONFIG_MAX_FILES_PER_PROC];
    struct mutex lock;
    uint32_t refcount;
};

struct fdtable *fdtable_alloc(void);
struct fdtable *fdtable_copy(struct fdtable *src);
void fdtable_get(struct fdtable *fdt);
void fdtable_put(struct fdtable *fdt);

/* Shared signal handler table */
struct sighand_struct {
    struct sigaction actions[CONFIG_NSIG];
    uint32_t refcount;
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

struct process {
    pid_t pid, ppid;
    pid_t pgid, sid;
    char name[16];
    uid_t uid;
    gid_t gid;
    mode_t umask;
    enum syscall_abi syscall_abi;
    enum proc_state state;
    int exit_code;
    spinlock_t lock;

    /* Scheduling */
    struct sched_entity se;

    struct mm_struct *mm;
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
    struct wait_queue vfork_wait;
    struct wait_queue_entry wait_entry;
    struct list_head children, sibling;
    struct process *parent;
    struct process *vfork_parent;
    bool vfork_done;
    struct arch_context *context;
    uint64_t utime, stime, start_time;
};

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
void proc_wakeup(struct process *p);
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
