# 43 — Block I/O / Filesystem Implementations

Part of the VFS/Block/Filesystems subsystem. See also:
- 41_VFS_CORE_PATH_MOUNT_IO.md — VFS core and mount/file flow
- 42_POLL_EPOLL.md — poll/epoll and wait-core integration

## Block I/O Layer (fs/bio/bio.c)

- Buffer cache: 128 static buf structs (NBUF=128), each with one-page backing storage (`CONFIG_PAGE_SIZE`)
- 32-bucket hash table indexed by `(dev, blockno, block_bytes)`
- LRU eviction: released buffers move to LRU head, allocation takes unused clean buffers from LRU tail; if only dirty victims exist, one is flushed and allocation retries
- Supports variable block-size I/O through `breadn(dev, blockno, block_bytes)`; legacy `bread()` remains as page-sized wrapper
- bwrite(): marks buffer dirty (delayed write)
- Dirty list: pending dirty buffers are tracked globally and flushed via `bsync_dev()` / `bsync_all()`
- brelse(): release buffer (unlock + decrement refcount + update LRU)
- Buffers protected by mutex for concurrent access
- blkdev registration now probes partition tables and registers partition child block devices (`vda1`, `nvme0n1p1` style naming); protective MBR triggers GPT-first scan, otherwise valid MBR entries are used

## Implemented Filesystems

Disk filesystems:
- ext2 (fs/ext2/): full implementation, includes super, inode, block, dir, vnode modules
  - mount feature gate rejects unsupported/journal/ext4-style feature combinations to avoid unsafe writes to incompatible filesystems
  - vnode `fsync` is implemented and flushes ext2 device dirty buffers
- fat32 (fs/fat32/): currently a stub (mount returns -ENOSYS)

Pseudo filesystems:
- devfs (fs/devfs/): device filesystem
- procfs (fs/procfs/): process information filesystem
  - exposes `/proc/mounts` and `/proc/<pid>/mounts`
  - exposes `/proc/<pid>/handles` for per-process handle-to-kobj table snapshots
  - exposes `/proc/<pid>/handle_transfers` for per-process handle-to-transfer-history snapshots
  - exposes `/proc/<pid>/handle_transfers_v2[.<cursor>[.<page_size>]]` for cursor-paged transfer-history snapshots (`token/next_token` + `returned/next_cursor/end` metadata); tokenized v2 paths reuse canonical procfs entries instead of creating one persistent entry per token filename
  - exposes `/proc/ipc/objects/<obj_id>/transfers_v2[.<cursor>[.<page_size>]]` for object-scoped, read-only cursor-token paging (`token/next_token`); tokenized object paths also reuse canonical entries
  - generated procfs read path now uses growable staging buffer (up to 256 KiB) rather than fixed 4 KiB
  - `/proc/self` symlink target is generated per lookup from current task pid
- sysfs (fs/sysfs/): device model filesystem
  - exposes `/sys/ipc` IPC observability files (`channels`, `ports`, `transfers`, `stats`, `hash_stats`) plus v2 object paging controls (`/sys/ipc/objects/{page,cursor,page_size}`) and per-object views (`/sys/ipc/objects/<id>/{summary,transfers,transfers_v2,transfers_cursor,transfers_page_size}`); detached sysfs nodes are reclaimed on last vnode close (not immediate free) under explicit node lifecycle state machine (`INIT/LIVE/DETACHED/DYING/FREED`), object-scoped IPC reads pin live objects by `obj_id` before snapshotting, object rows include `kobj` lifecycle text, and `hash_stats` reports bucket/load/average-chain/collision/depth diagnostics with default rehash recommendation flags for IPC hash tables
  - init phase (`init_fs`) performs a lightweight read+format sanity check on `/sys/ipc/hash_stats` and logs warning-only on failure
- tmpfs (fs/tmpfs/): in-memory filesystem

Special:
- initramfs (fs/initramfs/): CPIO format initramfs parsing and mounting
- pipe (fs/ipc/pipe.c): pipes, accessed through VFS interface
  - Blocking `read()` now returns once any bytes are available; it does not wait to fill the full requested length when the pipe already has data


Related references:
- references/00_REPO_MAP.md
- references/33_IPC.md
- references/41_VFS_CORE_PATH_MOUNT_IO.md
- references/42_POLL_EPOLL.md
- references/50_DRIVERS_BUS_DISCOVERY.md
