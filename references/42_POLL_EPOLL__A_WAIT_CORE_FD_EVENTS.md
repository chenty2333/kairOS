# 42A — poll/epoll Wait Core and FD Events

Part of the VFS/Block/Filesystems subsystem. See also:
- 42_POLL_EPOLL.md — poll/epoll index
- 42_POLL_EPOLL__B_SOCKET_MESSAGE_ABI.md — socket message ABI
- 42_POLL_EPOLL__C_SELECT_PATH_ABI.md — poll/select/path/fd ABI details

## Wait Core and FD-Event Surfaces

- vfs_poll.c: VFS poll infrastructure, based on pollwait mechanism
- epoll.c: epoll implementation, epoll instances are VNODE_EPOLL type vnodes
- poll/epoll/futex/socket timeout waits share a common wait-core deadline/block path (`poll_timeout_to_deadline_ms` + `poll_block_current_ex` family / `poll_wait_source_block`)
- poll wait-core now provides `poll_wait_source` (`wait_queue` + optional vnode) so fd-event paths can share one internal block/wake surface
- poll wait-core `poll_wait_wake` now uses a single-waiter direct-switch fastpath when no poll-watch callback fanout is pending
- eventfd/timerfd/inotify/signalfd/pidfd wakeups now route through `poll_wait_source_wake_*` (built on `poll_ready_wake_all`) to keep wait_queue + poll watcher wake paths consistent
- eventfd/timerfd/inotify/signalfd blocking waits now go through `poll_wait_source_block` (wait-core wrapper) instead of direct `proc_sleep_on*`
- wait-core now tracks epoll/fd-event hot-path counters (`poll_wait_stat_*`) and emits dedicated tracepoint events (`TRACE_WAIT_EPOLL` / `TRACE_WAIT_FD_EVENT`) for block/wake/rescan observability
- wait-core counter snapshot also exposes `poll_wait_head` wake telemetry (`poll_head_wake_calls` / `poll_head_direct_switch`) used by fastpath regression checks
- `/sys/kernel/tracepoint` adds `wait_core_events` (extended wait-core trace stream) and `wait_core_stats` (counter snapshot); `reset` clears both trace ring and wait-core counters
- pipe read/write blocking and close-end waiter wakeups now also use `poll_wait_source`; pipe poll readiness fanout still uses `poll_wait_head`
- AF_UNIX/AF_INET stream/listen/datagram wait queues now also use `poll_wait_source`; socket readiness notifications still route through socket poll heads
- futex wakeups are now also routed via `poll_wait_source_wake_one` (per-waiter source) rather than direct process wake calls
- epoll internal detach waits are also routed through wait-core helper entry (`poll_block_current_ex`) with explicit non-interruptible policy
- Event modes: level-trigger default, plus `EPOLLET` and `EPOLLONESHOT` (oneshot requires `EPOLL_CTL_MOD` rearm)
- Linux ABI compatibility includes `epoll_pwait2` (timespec timeout + strict `sigsetsize == sizeof(sigset_t)` checks), `accept4` (`SOCK_NONBLOCK`/`SOCK_CLOEXEC`), and socket message syscalls (`sendmsg`/`recvmsg`/`sendmmsg`/`recvmmsg`)
- Linux ABI compatibility also includes `eventfd2`, `timerfd_create/settime/gettime`, and `signalfd4` via anon-vnode pollable file descriptors
- `epoll_create1`, `eventfd2`, `timerfd_create`, `timerfd_settime`, `signalfd4`, and `inotify_init1` decode `flags` using Linux ABI width (`int`/32-bit)
- `epoll_ctl`/`epoll_wait` decode `epfd` (and target `fd` in `epoll_ctl`) as Linux ABI `int` (32-bit)
- `timerfd_settime`/`timerfd_gettime`, `signalfd4`, and `inotify_add_watch`/`inotify_rm_watch` decode `fd` (and `wd` for `inotify_rm_watch`) as Linux ABI `int` (32-bit)
- `epoll_ctl` decodes `op` as Linux ABI `int` (32-bit), and `epoll_wait` decodes `maxevents`/`timeout` as Linux ABI `int` (32-bit)
- `timerfd_create` accepts `CLOCK_REALTIME`/`CLOCK_MONOTONIC` plus `CLOCK_BOOTTIME`/`*_ALARM` aliases (mapped to realtime/monotonic base clocks)
- `timerfd_settime` accepts `TFD_TIMER_CANCEL_ON_SET` for realtime absolute timers; after `clock_settime(CLOCK_REALTIME, ...)`, reads fail with `ECANCELED` until re-armed
- `inotify_init1`/`inotify_add_watch`/`inotify_rm_watch` are wired; VFS open/write/create/delete/rename/close paths emit inotify events to watched vnodes

Related references:
- references/00_REPO_MAP.md
- references/13_TIME.md
- references/32_SYNC.md
- references/33_IPC.md
- references/41_VFS_CORE_PATH_MOUNT_IO.md
- references/42_POLL_EPOLL.md
- references/42_POLL_EPOLL__B_SOCKET_MESSAGE_ABI.md
- references/42_POLL_EPOLL__C_SELECT_PATH_ABI.md
