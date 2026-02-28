# 33B — IPC Channel and Port Model

Part of the Process/Scheduler/Sync/IPC subsystem. See also:
- 33_IPC.md — IPC index
- 33_IPC__A_SURFACE_AND_FD_RIGHTS.md — IPC surface and rights model
- 33_IPC__C_TRANSFER_OBSERVABILITY.md — Transfer and observability

## Channel/Port Object Model and Lifecycle

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

Related references:
- references/00_REPO_MAP.md
- references/13_TIME.md
- references/30_PROCESS.md
- references/31_SCHEDULER.md
- references/32_SYNC.md
- references/33_IPC.md
- references/33_IPC__A_SURFACE_AND_FD_RIGHTS.md
- references/33_IPC__C_TRANSFER_OBSERVABILITY.md
- references/42_POLL_EPOLL.md
