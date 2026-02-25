# 30 — Process / Scheduler / Sync / IPC

## Process Model

Process table: global static array proc_table[CONFIG_MAX_PROCESSES] (default 256), protected by proc_table_lock.

Process states: PROC_UNUSED → PROC_EMBRYO → PROC_RUNNABLE → PROC_RUNNING → PROC_SLEEPING → PROC_ZOMBIE → PROC_REAPING

process struct (include/kairos/process.h) key fields:
- pid/ppid/pgid/sid/tgid, uid/gid/umask
- state, exit_code, syscall_abi (Linux or Legacy)
- sched_flags: scheduler migration policy bits (`PROC_SCHEDF_STEALABLE`, `PROC_SCHEDF_KTHREAD`)
- sched_affinity: CPU affinity bitmask used by enqueue/steal placement
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
- proc_exec() failure path preserves underlying `-errno` (instead of collapsing to `-ENOEXEC`) across main ELF load, interpreter resolve/load, and user stack setup
- proc_exec() failure diagnostics emit structured kernel log with `reason + stage + errno(number/name)` to classify missing interp, invalid ELF, permission, and resource faults
- exec path copy now reports `ENAMETOOLONG` on userspace path truncation (instead of `EFAULT`), and `execveat` relative-path join rejects truncated composed paths with `ENAMETOOLONG`
- proc_exit(): sets ZOMBIE, wakes parent, notifies reaper
- proc_wait(): reaps child processes

Other:
- kthread_create(): create detached kernel threads (not parent-linked, not reaped via proc_wait)
- kthread_create_joinable(): create kernel threads linked to current parent for proc_wait-based reaping
- kthread default placement policy: creator CPU affinity bit + non-stealable (can be relaxed explicitly)
- proc_idle_init(): create idle process
- userspace `/init` supervises the login shell in a restart loop, logs exit cause (exit code / signal), and uses bounded exponential backoff on repeated failures
- signal.c: signal delivery, sighand sharing/copying, sigaction, sigaltstack
- Linux ABI process compatibility: `wait`/`wait4`/`waitid` decode `options` as 32-bit `int`; `execveat` decodes `flags` and `dirfd` as 32-bit `int`; `setuid`/`setgid` and `setre*id`/`setres*id` decode uid/gid arguments as 32-bit values (`-1` sentinel is `0xffffffff`)
- Linux ABI process compatibility also normalizes `pid`/`signal`/`priority` scalar args to 32-bit ABI width for `tgkill`/`tkill`, `getpriority`/`setpriority`, `prlimit64`, `sched_{get,set}affinity`, `setpgid`, `getpgid`, and `getsid`

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
- sched_steal_enabled runtime flag controls pull-based work stealing
- Work stealing (pull) is enabled in normal boot path (`sched_set_steal_enabled(true)`)
- `fair_steal_task()` steals queued RUNNABLE entities from remote CFS runqueues (rightmost scan), with source/destination CPU state checks
- schedule() reinserts stolen entities after normalizing to RUNNABLE and force-detaching stale RB links before local enqueue, avoiding dropped runnable tasks on steal handoff
- Steal candidacy is explicit and requires both `proc_sched_is_stealable()` and destination-CPU affinity allowance
- Default policy: user processes are stealable with full affinity; kernel threads (`kthread_create*`, idle) are marked `PROC_SCHEDF_KTHREAD`, non-stealable, and affinity-pinned to creator CPU
- Failed steal attempts use per-CPU cooldown to reduce hot-loop lock pressure on empty/imbalanced systems
- Enqueue placement respects per-process affinity and falls back to the first online allowed CPU if the hinted CPU is not allowed
- Linux ABI exposes `sched_getaffinity` and `sched_setaffinity` with single-word (`unsigned long`) masks; `sched_setaffinity` accepts masks excluding the current CPU, migrates QUEUED tasks immediately, and actively kicks RUNNING tasks toward migration (self-targeted calls yield to converge promptly). For oversized `cpusetsize`, only the low word is consumed and all trailing bytes must be readable and zero, otherwise the syscall fails (`-EFAULT` or `-EINVAL`).
- sched_trace ring buffer for debugging (per-CPU, records enqueue/dequeue/pick/switch/steal/migrate events)

Core functions:
- schedule(): pick next task and context switch
- schedule() and sched_tick() use local per-CPU `curr_proc` as the scheduler truth source
- schedule() entry drains pending `prev_task` cleanup on the local CPU before new switches
- sched_tick(): driven by timer interrupt, updates vruntime, checks preemption
- Timer-IRQ-driven `schedule()` is limited to user return path or idle task; kernel-thread reschedule is deferred to explicit resched points to avoid trap-unwind context corruption
- sched_enqueue() / sched_dequeue(): enqueue/dequeue
- sched_wake(): wake BLOCKED tasks, or set wake_pending for RUNNING tasks and request resched
- sched_fork(): child inherits fair_sched_class

## Synchronization Primitives (core/sync/)

sync.c:
- mutex: sleeping lock based on spinlock + wait_queue, supports holder tracking, recursive deadlock detection, interruptible and timeout variants
- semaphore: counting semaphore, supports userspace semaphores (do_sem_init/wait/post, max 128); syscall `count`/`sem_id` are decoded as Linux ABI `int` (32-bit)
- rwlock: read-write lock, writer-priority (writers_waiting blocks new readers)

wait.c:
- wait_queue: linked-list based wait queue, wait_queue_entry embedded in process struct
- wakeup_one / wakeup_all

completion.c:
- completion: one-shot/multi-shot synchronization based on wait_queue, supports interruptible and timeout
- complete_all() sets done=UINT32_MAX for permanent completion

futex.c:
- futex_wait / futex_wake: 128 hash buckets, multiplicative hash
- futex_waitv: vectorized wait (`FUTEX_WAITV_MAX=128`), returns awakened waiter index
- futex opcode/wake count/clockid are decoded using Linux ABI `int`/`unsigned int` widths (32-bit), and futex_waitv decodes `flags` as 32-bit
- syslog syscall decodes `type`/`len` using Linux ABI `int` width (32-bit)
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
- Event FDs: `eventfd2` and `timerfd_*` are exposed as anon-vnode file descriptors (pollable, Linux ABI wiring)
- Signal FDs: `signalfd4` is wired; read consumes matching pending signals from the task signal bitmap
- Inotify: `inotify_init1/add_watch/rm_watch` is wired with vnode-based watches and pollable event queue delivery

Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE_TRAP_SYSCALL_TIME.md
- references/20_MEMORY.md
- references/40_VFS_BLOCK_FS.md
