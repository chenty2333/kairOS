# 33A — IPC Surface and FD Rights

Part of the Process/Scheduler/Sync/IPC subsystem. See also:
- 33_IPC.md — IPC index
- 33_IPC__B_CHANNEL_PORT.md — Channel/port model
- 33_IPC__C_TRANSFER_OBSERVABILITY.md — Transfer and observability

## IPC Surface and Capability/FD Rights

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

Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE.md
- references/13_TIME.md
- references/20_MEMORY.md
- references/30_PROCESS.md
- references/31_SCHEDULER.md
- references/32_SYNC.md
- references/33_IPC.md
- references/33_IPC__B_CHANNEL_PORT.md
- references/33_IPC__C_TRANSFER_OBSERVABILITY.md
- references/41_VFS_CORE_PATH_MOUNT_IO.md
- references/42_POLL_EPOLL.md
