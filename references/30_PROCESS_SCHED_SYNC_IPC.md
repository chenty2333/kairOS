# 30 — Process / Scheduler / Sync / IPC

## Process Model

Process table: global static array proc_table[CONFIG_MAX_PROCESSES] (default 256), protected by proc_table_lock.

Process states: PROC_UNUSED → PROC_EMBRYO → PROC_RUNNABLE → PROC_RUNNING → PROC_SLEEPING → PROC_ZOMBIE → PROC_REAPING

process struct (include/kairos/process.h) key fields:
- pid/ppid/pgid/sid/tgid, uid/gid/umask
- state, exit_code, syscall_abi (Linux or Legacy)
- se: scheduling entity (sched_entity)
- mm: address space (mm_struct)
- fdtable: file descriptor table (refcounted, supports CLONE_FILES sharing)
- sighand: signal handler table (refcounted, supports CLONE_SIGHAND sharing)
- context: architecture-specific context (arch_context)
- children/sibling: process tree
- thread_group: thread group list (CLONE_THREAD)
- wait_entry/exit_wait/vfork_completion: waiting and synchronization

Lifecycle (core/proc/):
- proc_alloc(): allocate free slot from proc_table, initialize fdtable, cwd, signals, context
- proc_fork() / proc_fork_ex(): fork/clone, supports CLONE_VM/CLONE_FILES/CLONE_SIGHAND/CLONE_THREAD/CLONE_SETTLS, COW address space copy
- proc_exec(): ELF loading (core/proc/elf.c), replaces address space and context
- proc_exit(): sets ZOMBIE, wakes parent, notifies reaper
- proc_wait(): reaps child processes

Other:
- kthread_create(): create detached kernel threads (not parent-linked, not reaped via proc_wait)
- kthread_create_joinable(): create kernel threads linked to current parent for proc_wait-based reaping
- proc_idle_init(): create idle process
- signal.c: signal delivery, sighand sharing/copying, sigaction, sigaltstack

## Scheduler (core/sched/sched.c)

EEVDF (Earliest Eligible Virtual Deadline First) scheduler, dispatched through sched_class interface:

sched_class interface: enqueue_task, dequeue_task, pick_next_task, put_prev_task, task_tick, task_fork, set_nice, check_preempt_curr, steal_task

fair_sched_class (EEVDF implementation):
- Red-black tree (tasks_timeline) ordered by vruntime
- sched_entity run_state machine: BLOCKED/RUNNABLE/QUEUED/RUNNING
- wakeup handoff uses wake_pending to close sleep/wakeup race when wake arrives before RUNNING task transitions to BLOCKED
- vruntime accumulates weighted by nice value (mapped through sched_nice_to_weight[])
- Time slices: SCHED_SLICE_NS=3ms, SCHED_LATENCY_NS=6ms, SCHED_MIN_GRANULARITY_NS=0.5ms
- vlag mechanism handles fairness compensation during task migration
- min_deadline augmentation recompute uses iterative post-order walk (non-recursive)
- sched_node is explicitly detached on entity init and rb_erase to prevent stale-link reuse

Per-CPU run queue (percpu_data.runqueue):
- nr_running count
- cfs_rq embedded CFS run queue (red-black tree + min_vruntime + rb_rightmost cache for O(1) steal)

SMP support:
- sched_steal_enabled flag, enabled after smp_init()
- Work stealing (pull): idle CPU steals task with largest vruntime (least owed) via cached rb_rightmost pointer
- Push migration: sched_enqueue redirects tasks to idle CPUs when preferred CPU is busy (randomized scan, lockless pre-check)
- sched_trace ring buffer for debugging (per-CPU, records enqueue/dequeue/pick/switch/steal/migrate events)

Core functions:
- schedule(): pick next task and context switch
- schedule() entry drains pending prev_task cleanup before next switch to avoid lost zombie cleanup events across fresh-task switches
- sched_tick(): driven by timer interrupt, updates vruntime, checks preemption
- sched_enqueue() / sched_dequeue(): enqueue/dequeue
- sched_wake(): wake BLOCKED tasks, or set wake_pending for RUNNING tasks and request resched
- sched_fork(): child inherits fair_sched_class

## Synchronization Primitives (core/sync/)

sync.c:
- mutex: sleeping lock based on spinlock + wait_queue, supports holder tracking, recursive deadlock detection, interruptible and timeout variants
- semaphore: counting semaphore, supports userspace semaphores (do_sem_init/wait/post, max 128)
- rwlock: read-write lock, writer-priority (writers_waiting blocks new readers)

wait.c:
- wait_queue: linked-list based wait queue, wait_queue_entry embedded in process struct
- wakeup_one / wakeup_all

completion.c:
- completion: one-shot/multi-shot synchronization based on wait_queue, supports interruptible and timeout
- complete_all() sets done=UINT32_MAX for permanent completion

futex.c:
- futex_wait / futex_wake: 128 hash buckets, multiplicative hash
- Supports timeout (via poll_sleep mechanism)
- Used for userspace fast locks (pthread mutex, etc.)

pollwait.c:
- poll_wait_head: unified poll wait infrastructure, supports waiters (process waiting) and watches (callback notification)
- poll_sleep: global timed sleep queue, tick interrupt drives expiry wakeups

lockdep.c (when CONFIG_LOCKDEP enabled):
- Lightweight lock dependency checker, bit matrix records lock acquisition order, detects potential deadlocks
- Per-CPU held_stack tracks currently held locks

Debug support (CONFIG_DEBUG_LOCKS):
- Warns when sleeping locks are used with IRQs disabled or in atomic context
- spinlock acquire/release manipulates preempt_count

## IPC

Current IPC mechanisms:
- Pipes: implemented in fs/ipc/pipe.c, accessed through VFS interface
- Unix domain sockets: kernel/net/af_unix.c
- Futex: userspace synchronization
- Signals: inter-process notification

Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE_TRAP_SYSCALL_TIME.md
- references/20_MEMORY.md
- references/40_VFS_BLOCK_FS.md
