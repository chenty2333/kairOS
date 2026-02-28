# 33C — IPC Transfer and Observability

Part of the Process/Scheduler/Sync/IPC subsystem. See also:
- 33_IPC.md — IPC index
- 33_IPC__A_SURFACE_AND_FD_RIGHTS.md — IPC surface and rights model
- 33_IPC__B_CHANNEL_PORT.md — Channel/port object model

## Transfer Pipeline, Observability, and Verification

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
- references/30_PROCESS.md
- references/33_IPC.md
- references/33_IPC__A_SURFACE_AND_FD_RIGHTS.md
- references/33_IPC__B_CHANNEL_PORT.md
- references/41_VFS_CORE_PATH_MOUNT_IO.md
- references/42_POLL_EPOLL.md
- references/90_BUILD_TEST_DEBUG.md
- references/92_TESTING_COMMANDS.md
- references/94_TEST_VERDICT_POLICY.md
