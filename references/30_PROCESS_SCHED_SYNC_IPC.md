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
- default signal handling now treats `SIGSTOP` as suspend-until-`SIGCONT` (or `SIGKILL`) and consumes `SIGCONT` as a resume event
- procfs per-pid control endpoint: `/proc/<pid>/control` (mode `0600`) accepts `stop|cont|resume|kill|term|sig N|signal N`; write path emits signals via `signal_send_authorized`, and read path returns a structured snapshot (`schema`, `last.*`, `audit.*`) with per-action (`stop/cont/term/kill/signal`) attempt/ok/fail counters and error audit counters (`parse`, `too_long`, `perm`, `noent`, `other`)
- Linux ABI process compatibility: `wait`/`wait4`/`waitid` decode `options` as 32-bit `int`; `execveat` decodes `flags` and `dirfd` as 32-bit `int`; `setuid`/`setgid` and `setre*id`/`setres*id` decode uid/gid arguments as 32-bit values (`-1` sentinel is `0xffffffff`)
- Linux ABI process compatibility also normalizes `pid`/`signal`/`priority` scalar args to 32-bit ABI width for `tgkill`/`tkill`, `getpriority`/`setpriority`, `prlimit64`, `sched_{get,set}affinity`, `setpgid`, `getpgid`, and `getsid`
- Linux ABI pidfd baseline: `pidfd_open`, `pidfd_send_signal`, and `pidfd_getfd` are wired; pidfd is pollable (`POLLIN|POLLHUP` after target exit), `pidfd_open` enforces Linux-style `O_CLOEXEC` on returned fd, `pidfd_send_signal` supports `flags=0` plus optional `siginfo_t *info` user-pointer validation, `waitid(P_PIDFD, ...)` resolves pidfd targets through the fd table (including `WNOWAIT` no-reap path for exited children), and `pidfd_getfd` duplicates target fds with `FD_CLOEXEC`

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

## IPC

Current IPC mechanisms:
- Pipes: implemented in fs/ipc/pipe.c, accessed through VFS interface
- Unix domain sockets: kernel/net/af_unix.c
- Futex: userspace synchronization
- Signals: inter-process notification
- Event FDs: `eventfd2` and `timerfd_*` are exposed as anon-vnode file descriptors (pollable, Linux ABI wiring)
- Signal FDs: `signalfd4` is wired; read consumes matching pending signals from the task signal bitmap
- PID FDs: `pidfd_open` creates pollable process handles; `pidfd_send_signal` supports liveness probe (`sig=0`), signal delivery via pidfd, and `info!=NULL` pointer validation; `waitid(P_PIDFD, ...)` is wired for child wait/reap semantics and supports `WNOWAIT` for exited-child observation without immediate reap (`WSTOPPED/WCONTINUED` currently only accepted in nonblocking no-event polling path); `pidfd_getfd` duplicates a target fd into the caller with CLOEXEC
- Inotify: `inotify_init1/add_watch/rm_watch` is wired with vnode-based watches and pollable event queue delivery
- Capability handles: per-process `handletable` (refcounted; cloned with `CLONE_FILES` sharing or copied otherwise), rights-mask model (`READ/WRITE/TRANSFER/DUPLICATE/WAIT/MANAGE`), and generic `kobj` refcounted object lifetime
- Handle access checks now expose a unified op-based entry (`khandle_get_for_access` / `khandle_take_for_access`) so new fast paths reuse one rights-check surface instead of per-callsite bespoke masks
- Handletable entries now carry internal capability lineage id (`cap_id`), and the kernel tracks a parent/child delegation tree so derived capabilities can be revoked recursively
- Capability lineage nodes now track a sticky `revoked` state; subtree revoke marks descendants revoked first, then closes currently-live descendants, and revoked nodes cannot be rebound or used as delegation parents
- Handle close supports optional descendant revoke (`KHANDLE_CLOSE_F_REVOKE_DESCENDANTS`) via `khandle_close_with_flags()`, which marks the root lineage revoked before descendant/root close so in-flight transfer install cannot recreate descendants during close
- Hot IPC handle lookup path now has a per-CPU access cache keyed by `(current process handletable, handle, access-op)` and validated by handletable sequence/epoch; rights checks still route through the same access-rights predicate used by slow path
- Capability file bridge: Linux fd/file objects can be wrapped as `KOBJ_TYPE_FILE` handles and converted back to fd without changing Linux ABI syscalls; `fd_alloc_rights()` preserves rights attenuation when materializing fd from a handle
- Internal bridge helpers (`handle_bridge`) centralize fd-rights <-> handle-rights mapping plus fd<->`KOBJ_TYPE_FILE` conversion, so non-syscall kernel paths can reuse one capability conversion entrypoint
- fd core provides `fd_get_required_with_rights()` to pin `file*` and snapshot fd-rights in one lock pass; bridge paths now reuse this single pin/query entrypoint
- `handle_bridge` also provides cross-process fd duplication helper used by `pidfd_getfd`, so fd-rights-preserving duplication no longer reimplements per-call rights/copy glue
- FD capability rights: fdtable entries carry independent rights mask (`FD_RIGHT_READ/WRITE/IOCTL/DUP`); `read*`/`write*`/`copy_file_range`/`ioctl` enforce required rights, and `dup*`/`fcntl(F_DUPFD*)` require `FD_RIGHT_DUP`
- Socket message data paths now use fd-right checks internally: `send*` requires `FD_RIGHT_WRITE`, `recv*` requires `FD_RIGHT_READ`
- FD rights coverage also gates mutating descriptor/file operations: `ftruncate`/`fchmod`/`fchown` require `FD_RIGHT_WRITE`, `fcntl(F_SETFL)` requires `FD_RIGHT_IOCTL`, and file-backed `mmap` enforces `FD_RIGHT_READ` (+ `FD_RIGHT_WRITE` for `MAP_SHARED|PROT_WRITE`)
- Channel IPC (Kairos extension): message-oriented pair endpoints with bounded queue (`KCHANNEL_MAX_QUEUE`), blocking/nonblocking send/recv, and handle transfer (`KRIGHT_TRANSFER`) with move semantics
- Channel endpoint lifecycle is modeled as explicit state machine (`OPEN/CLOSING/CLOSED`); send/recv/poll/close paths share unified state predicates so close races consistently resolve to EOF/`-EPIPE` without stranded blockers
- Debug builds now assert channel endpoint transition legality (`OPEN->CLOSING->CLOSED`) so direct/invalid state rewrites are caught early
- Port wait queue (Kairos extension): channel endpoint can bind to a port key; events currently include `READABLE` and `PEER_CLOSED`, consumed through blocking/nonblocking `port_wait` with optional timeout
- Channel/port internal sleep+wake paths now share `poll_wait_source` for waiter blocking and wakeup; port fd poll fanout to multiple vnodes remains unchanged
- `poll_wait_source` wake paths now carry explicit wake reason (`data/hup/close/signal/timeout`); IPC channel/port call sites annotate close/data/signal wakeups so block-side diagnostics can distinguish timeout vs signal vs peer-close wake causes
- wait-core loose block helpers (`poll_wait_source_block*`) remain as compatibility wrappers; external sleep paths are migrated to seq-aware APIs (`poll_wait_source_block_seq*`)
- Channel/port poll fast paths now use lockless readiness hints when endpoint/port locks are contended, reducing false-positive `poll` readiness reports from lock-contention fallbacks
- Channel poll hint path now uses explicit acquire/release hint loads/stores and exports hint-vs-locked readiness mismatch telemetry for self-check
- `CONFIG_IPC_POLL_HINT_STRICT=1` enables fail-fast behavior on poll-hint mismatch (panic on mismatch) for test/debug environments
- `kobj` now carries a base `wait_queue`; channel/port expose unified `kobj_ops` dispatch for `read/write/poll/signal/wait` (`kobj_read`, `kobj_write`, `kobj_poll`, `kobj_signal`, `kobj_wait`)
- `kobj` lifecycle tracking now records bounded refcount history per object (init/get/put/last-put) with snapshot API (`kobj_refcount_history_snapshot`) for postmortem/debug inspection; base lifecycle state is explicit (`INIT/LIVE/DETACHED/DYING/FREED`) and key `kobj_ops` entrypoints emit ratelimited WARN on invalid-state access
- `port_wait` blocking now sleeps on object-level `kobj.waitq` (wake source remains channel/port enqueue/close paths), keeping fd-poll fanout unchanged
- Channel fd bridge: `kairos_fd_from_handle` supports `KOBJ_TYPE_CHANNEL`; resulting fd supports byte `read()`/`write()` on channel payload path (any transferred handles on `read()` are consumed and dropped), and `poll` readiness is rights-gated (`KRIGHT_READ` for `POLLIN`, `KRIGHT_WRITE` for `POLLOUT`, `POLLHUP` preserved)
- Channel endpoint liveness now tracks both handle slots and bridged channel fds; closing the last handle while a bridged fd remains no longer tears down the endpoint, and last-ref teardown wakes both local/peer waiters so blocked channel `send/recv` observe closure promptly
- Endpoint-liveness refs now also track owner classes (`handle`, `channel_fd`, `other`) under one API; ref underflow/accounting mismatch is detected and rate-limited warned
- Endpoint-liveness loose helpers (`kchannel_endpoint_ref_inc/dec`) remain as compatibility wrappers; external paths are migrated to owner-tagged refs (`*_ref_inc_owner/dec_owner`)
- Endpoint-liveness accounting now has unified audit hooks (`kchannel_endpoint_ref_audit_obj` / `kchannel_endpoint_ref_audit_registry`) wired at `channelfd_close`, `handletable_put`, and `proc_exit`; audits retry snapshots to filter transient concurrent updates and warn only on persistent owner-sum mismatch
- Port fd bridge: `kairos_fd_from_handle` supports `KOBJ_TYPE_PORT`; resulting fd rights now mirror handle attenuation (`KRIGHT_WAIT`->`FD_RIGHT_READ`, `KRIGHT_MANAGE`->`FD_RIGHT_IOCTL`, `KRIGHT_DUPLICATE`->`FD_RIGHT_DUP`), `read()` requires `KRIGHT_WAIT`, and `poll` readiness is rights-gated (`KRIGHT_WAIT` for `POLLIN`, `POLLHUP|POLLERR` preserved)
- `file_ops` adds optional `to_kobj` export hook for typed fd endpoints; channel/port bridge vnodes implement it so `kairos_handle_from_fd` no longer needs syscall-local special-fd branching
- Reverse bridge for channel/port fd: `kairos_handle_from_fd` recognizes bridge fds and recreates typed handles (`KOBJ_TYPE_CHANNEL` / `KOBJ_TYPE_PORT`) with rights derived from fd rights attenuation (`FD_RIGHT_READ`/`FD_RIGHT_IOCTL`/`FD_RIGHT_DUP` map to `KRIGHT_WAIT`/`KRIGHT_MANAGE`/`KRIGHT_DUPLICATE` on port handles; no implicit `KRIGHT_TRANSFER` escalation on port roundtrip)
- `kairos_fd_from_handle` accepts `O_NONBLOCK` for channel/port bridges (read path returns `-EAGAIN` when empty); `KOBJ_TYPE_FILE` bridge keeps existing semantics and rejects `O_NONBLOCK` at conversion time
- Channel `send/recv` options add `KCHANNEL_OPT_RENDEZVOUS`: when sender/receiver both opt in and a blocking receiver is armed, payload/control can bypass queue enqueue for a synchronous handoff fastpath
- Channel payload path adds small-message inline optimizations: each channel preallocates `KCHANNEL_MAX_QUEUE` queue slots (`inline bytes + handle array`) and small queued messages (`<= KCHANNEL_INLINE_MSG_BYTES`) run without per-message heap allocation; syscall send/recv staging also uses stack inline buffers for small payloads
- Rendezvous send path now attempts a direct armed-receiver handoff before queue-message allocation, reducing allocation overhead on synchronous transfer cases
- `kobj` now also records bounded transfer-history events (`TAKE/ENQUEUE/DELIVER/INSTALL/RESTORE/DROP`) with snapshot API (`kobj_transfer_history_snapshot`) for capability movement auditing
- transfer install/drop helpers (`khandle_install_transferred`, `khandle_transfer_drop_with_rights`) keep transfer lifecycle bookkeeping in one internal entrypoint without changing Linux fd syscall ABI
- transfer metadata now carries `cap_id`; transfer install/restore requires successful rebinding of that lineage node when `cap_id` is provided (no implicit fallback to a new root cap), and transfer drop paths prune detached lineage nodes
- transfer take paths that need lineage preservation must use `khandle_take_for_access_with_cap(..., KOBJ_ACCESS_TRANSFER, ...)`; `khandle_take_for_access` rejects `KOBJ_ACCESS_TRANSFER` to prevent cap-id loss
- transfer reserve/commit/abort handshake now also carries per-slot `slot_generation` (in addition to token) to harden against slot reuse ABA races during concurrent send rollback/commit windows
- reserved transfer now has timeout-based stale-sweep: timed-out reserved slots are opportunistically reclaimed and dropped (`khandle_transfer_drop_cap`) during handle-table operations, preventing long-lived slot pinning when exceptional paths miss commit/abort
- handletable and detached lineage-node frees are now deferred through retire queues with a grace delay (instead of immediate `kfree` on teardown), reducing concurrent lookup/detach paths observing recycled memory
- sysfs exports IPC observability at `/sys/ipc`: aggregated views are `/sys/ipc/{channels,ports,transfers,stats,hash_stats}`, and `/sys/ipc/objects/` exposes v2 paging controls (`page`, `cursor`, `page_size`) plus per-object dirs (`/sys/ipc/objects/<id>/{summary,transfers,transfers_v2,transfers_cursor,transfers_page_size}`); registry register/unregister paths now only mutate registry state and enqueue projection ops, while a dedicated `ipcsysfs` kthread performs single-writer sysfs create/remove after `ipc_registry_sysfs_bootstrap()` runs from `init_fs()`. Sysfs subtree removal now detaches nodes first and frees them on last vnode close, with explicit node lifecycle state machine (`INIT/LIVE/DETACHED/DYING/FREED`) and ratelimited illegal-transition warnings; object-scoped IPC attributes resolve live objects by `obj_id` under registry pinning (no direct dereference of transient registry entry pointers), and per-object summary/page rows include `kobj` lifecycle text
- kernel hash tables now share intrusive helpers (`khash_*`) in `kernel/include/kairos/hashtable.h` with common load/collision/depth stats collection (`khash_stats_collect`) and default rehash recommendation heuristics; current migrated call sites include proc/pidfd/ipc-id/kcap/iommu plus blkdev-name, ext2 inode-cache, bio buffer-cache key table, AF_UNIX bind table, and VFS dentry cache buckets
- `init_fs()` now performs a lightweight IPC hash-stats self-check by opening `/sys/ipc/hash_stats`, validating expected schema/fields, and warning on malformed output without aborting boot
- `/sys/ipc/stats` now includes channel correctness counters (`send_ePIPE`, `recv_eof`, close/wake reasons, poll-hint mismatch telemetry, endpoint-ref audit checks/mismatches), capability lineage/revoke counters (`cap_revoke_marked_total`, `cap_bind_rejected_revoked_total`, `cap_commit_eagain_total`, `cap_tryget_failed_total`), `khandle_cache_*` observability (`lookups`, `hits`, `misses`, `hit_per_mille`, `stores`, `slot_invalidate_calls`, `invalidated_slots`, `released_refs`, `ht_sweeps`, `active_refs`), `ipc_lock_probe_*` lock-order/deadlock-probe counters (`registry<->channel/port` order edges, contention, underflow, warn count), and `kobj_lifecycle_*` warning counters (`transition_warn_total`, `access_warn_total`, `warns`)
- `TRACE_IPC_CHANNEL` flags are now versioned (`version=1`) and use fixed bitfields: `op[7:0]`, `wake[11:8]`, `self_state[15:12]`, `peer_state[19:16]`, `version[31:28]`; `arg0` keeps `(self_id<<32)|peer_id`
- `/sys/kernel/tracepoint/ipc_events` now exports decoded schema rows (`trace_ipc_channel_v1`) with `op/wake/self_state/peer_state/self_id/peer_id` columns for stable parsing
- `TRACE_IPC_CAP` exposes capability lineage race/guard events (`revoke_marked`, `bind_rejected_revoked`, `commit_eagain`, `tryget_failed`) with versioned flags (`op[7:0]`, `version[31:28]`); `/sys/kernel/tracepoint/ipc_cap_events` exports decoded `trace_ipc_cap_v1` rows (`op/cap_id/arg1`)
- `scripts/impl/tracepoint-ipc-report.py` summarizes IPC trace exports (`op/wake/state/channel/pair` distributions), accepting both structured `ipc_events` output and legacy raw trace rows
- procfs exports per-process handle table view at `/proc/<pid>/handles` (`handle/cap_id/obj_id/type/rights/refcount`) and transfer-history correlation at `/proc/<pid>/handle_transfers` (`handle/cap_id/obj_id/type/rights` + transfer event stream)
- procfs handle transfer export also provides cursor-paged v2 view at `/proc/<pid>/handle_transfers_v2[.<cursor>[.<page_size>]]` with `token/next_token` plus `cursor/page_size/returned/next_cursor/end` metadata; procfs generated-read path now grows buffer on demand (up to 256 KiB) instead of fixed 4 KiB output staging
- procfs also exposes object-scoped, read-only transfer snapshots at `/proc/ipc/objects/<obj_id>/transfers_v2[.<cursor>[.<page_size>]]`, returning `token/next_token` cursor strings so pagination no longer depends on writable control files; v2 cursor-token lookups now reuse canonical procfs entries instead of allocating one persistent entry per tokenized filename
- procfs v2 token parameters (`cursor/page_size`) are now bound at `open` time into `file->private_data`; subsequent `read` uses this bound query state instead of reparsing `file->path`, keeping token semantics stable for the opened fd
- channel syscall send/recv (`sys_kairos_channel_send/recv`) now stage message payload in fixed stack buffers (`KCHANNEL_MAX_MSG_BYTES`) rather than temporary heap allocations; the remaining heap path is limited to channel queue payloads larger than `KCHANNEL_INLINE_MSG_BYTES`
- syscall-trap IPC/cap focused suite now includes channel close-vs-blocking (`recv`/`send`) races, fd-only endpoint-liveness longrun loops, channelfd `epoll(EPOLLET)` high-frequency send/recv checks, transfer reserve transaction guards (token + generation), and fault-inject regression coverage for `ipc_channel_send/recv/close` plus `pollwait_block/wake` (including send/recv non-consumption checks and pollwait reason-path checks), alongside reserved-transfer timeout sweep regression coverage
- Kairos extension syscalls (custom Linux ABI numbers): `kairos_handle_close`(4600), `kairos_handle_duplicate`(4601), `kairos_channel_create/send/recv`(4602-4604), `kairos_port_create/bind/wait`(4605-4607), `kairos_cap_rights_get`(4608), `kairos_cap_rights_limit`(4609), `kairos_handle_from_fd`(4610), `kairos_fd_from_handle`(4611)

Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE_TRAP_SYSCALL_TIME.md
- references/20_MEMORY.md
- references/40_VFS_BLOCK_FS.md
