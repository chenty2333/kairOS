# 32 — Synchronization Primitives

Part of the Process/Scheduler/Sync/IPC subsystem. See also:
- 30_PROCESS.md — Process model
- 31_SCHEDULER.md — Scheduling
- 33_IPC.md — Inter-process communication

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
- futex waits now block through `poll_wait_source_block` (single-wait path holds futex bucket mutex across sleep handoff to avoid enqueue->sleep wake races)
- futex wakeups now route through waiter-bound `poll_wait_source_wake_one` instead of direct `proc_wakeup`, sharing the wait-core wake surface
- futex wake path removes/wakes matched waiters under bucket lock, avoiding waiter-lifetime races with timeout/signal dequeue paths
- futex_waitv sleep now uses a shared wait gate mutex across wake-index check + sleep handoff; futex_wake synchronizes on that gate for waitv waiters to close wake-index-vs-sleep lost-wake windows
- Used for userspace fast locks (pthread mutex, etc.)

pollwait.c:
- poll_wait_head: unified poll wait infrastructure, supports waiters (process waiting) and watches (callback notification)
- poll_wait_source: unified wait source object (`wait_queue` + optional pollable vnode), used to route block/wake through one kernel-internal interface
- `poll_wait_source` now carries a monotonic wake sequence (`seq`); wake paths bump `seq`, and block paths can use observed-seq precheck (`poll_wait_source_block_seq*`) to avoid sleeping across already-arrived events
- poll_sleep: global timed sleep queue, tick interrupt drives expiry wakeups
- Unified wait-core helpers: `poll_timeout_to_deadline_ms`, `poll_deadline_expired`, `poll_block_current_ex`, `poll_block_current`, `poll_block_current_mutex` (supports wait_queue + mutex sleep sites and interruptible policy)
- `poll_wait_source_block_ex` extends wait-source blocking with explicit interruptible policy; `poll_wait_source_block` remains the interruptible wrapper
- Unified ready wake bridge: `poll_ready_wake_one/all` wakes wait_queue waiters and poll watchers on one path
- `wait_queue_wakeup_one_hint()` adds a wait-core wake primitive with optional direct-switch hint; `poll_ready_wake_one` now uses it and enables single-waiter direct switch when no vnode fanout is involved
- `poll_wait_wake()` now also takes the same direct-switch fastpath when there is exactly one waiter and no watch callback fanout, so epoll-style waiter-only heads reuse the optimized wake handoff
- `eventfd`/`timerfd`/`inotify`/`signalfd`/`pidfd` block+wake paths now use `poll_wait_source_*` wrappers over wait-core helpers instead of direct `proc_sleep_on*` call sites
- pipe read/write blocking queues and close wakeups now route through `poll_wait_source` (pipe poll fanout remains on `poll_wait_head`)
- AF_UNIX and AF_INET stream/listen/datagram wait queues now route through `poll_wait_source` while socket poll readiness fanout remains on socket poll heads
- epoll internal detach wait (`epoll_item` teardown rendezvous) also routes through `poll_wait_source` instead of raw `wait_queue`
- lwIP `sys_arch` semaphore/mailbox waits now also route through `poll_wait_source` with non-interruptible policy
- `ppoll`/`pselect6` temporarily swap task signal mask via atomic exchange around the wait path and restore original mask on return (Linux-style per-call temporary mask window)
- Lightweight tracepoint emit points are attached on wait block/wake helpers (per-CPU ring buffer)
- wait-core epoll/fd-event paths now expose dedicated observability: `TRACE_WAIT_EPOLL` / `TRACE_WAIT_FD_EVENT`, plus unified wait-core counters (`poll_wait_stat_*`) for epoll wait cycles and fd-event block/wake hot paths
- wait-core counters also include `poll_wait_wake` head-level metrics (`poll_head_wake_calls`, `poll_head_direct_switch`) for single-waiter fastpath regression/telemetry
- wait-core counters include futex wait/waitv block/wake/timeout/interrupt telemetry and futex wake call/woken totals (`futex_wake_calls`, `futex_wake_woken`)
- `/sys/kernel/tracepoint/wait_core_events` exports wait-core traces (including epoll/fd-event), and `/sys/kernel/tracepoint/wait_core_stats` exports wait-core counters; `reset` clears both trace rings and wait-core counters
- `/sys/kernel/tracepoint/wait_events` keeps a legacy-compatible wait-only view (`TRACE_WAIT_BLOCK`/`TRACE_WAIT_WAKE`) for simpler tooling input
- `scripts/impl/tracepoint-wait-report.py` summarizes exported wait events (`total/by-event/by-cpu`, wake-one vs wake-all, timeout-vs-nontimeout waits)
- tracepoint ring snapshot uses release/acquire `seq` stabilization (double-sample verify) to avoid torn entries under concurrent writers

lockdep.c (when CONFIG_LOCKDEP enabled):
- Lightweight lock dependency checker, bit matrix records lock acquisition order, detects potential deadlocks
- Per-CPU held_stack tracks currently held locks

Debug support (CONFIG_DEBUG_LOCKS):
- Warns when sleeping locks are used with IRQs disabled or in atomic context
- spinlock acquire/release manipulates preempt_count

Related references:
- references/00_REPO_MAP.md
- references/30_PROCESS.md — Process model
- references/31_SCHEDULER.md — Scheduling
- references/33_IPC.md — Inter-process communication
- references/42_POLL_EPOLL.md — poll/epoll mechanisms
