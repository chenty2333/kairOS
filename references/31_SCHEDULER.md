# 31 — Scheduler

Part of the Process/Scheduler/Sync/IPC subsystem. See also:
- 30_PROCESS.md — Process model
- 32_SYNC.md — Synchronization primitives
- 33_IPC.md — Inter-process communication

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
- Linux ABI exposes `sched_getaffinity` and `sched_setaffinity` with kernel-sized cpumasks (`BITS_TO_LONGS(CONFIG_MAX_CPUS)` words); `sched_setaffinity` accepts masks excluding the current CPU, migrates QUEUED tasks immediately, and actively kicks RUNNING tasks toward migration (self-targeted calls yield to converge promptly). For oversized `cpusetsize`, bytes beyond the kernel cpumask are ignored; if the effective in-kernel mask has no online CPU bit, the syscall fails with `-EINVAL`.
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

Related references:
- references/00_REPO_MAP.md
- references/13_TIME.md — Timer interrupts and tick policy
- references/30_PROCESS.md — Process model
- references/32_SYNC.md — Synchronization primitives
