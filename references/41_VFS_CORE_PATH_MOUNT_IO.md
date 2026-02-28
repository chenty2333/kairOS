# 41 — VFS Core / Path / Mount / File I/O

Part of the VFS/Block/Filesystems subsystem. See also:
- 42_POLL_EPOLL.md — poll/epoll details
- 43_BLOCK_FS_IMPLEMENTATIONS.md — Block layer and filesystems

## VFS Core

The VFS layer (fs/vfs/) provides a unified filesystem abstraction:

Core data structures:
- vnode (include/kairos/vfs.h): unified abstraction for file/dir/device/pipe/socket/symlink/epoll, contains type, mode, size, ops(file_ops), fs_data, refcount, rwlock, poll_wait_head
- file (include/kairos/vfs.h): open file instance, contains vnode, dentry, offset, flags, refcount
- dentry (include/kairos/dentry.h): directory entry cache entry, contains parent, name, vnode, mnt, mounted, children/child tree, hash, lru, supports negative caching (DENTRY_NEGATIVE)
- mount (include/kairos/vfs.h): mount point, contains mountpoint, ops(vfs_ops), root vnode/dentry, blkdev, mount propagation attributes
- mount_ns: mount namespace, contains root mount/dentry, refcount

Two operation interfaces:
- vfs_ops: filesystem-level operations (mount, unmount, lookup, create, mkdir, symlink, unlink, rmdir, rename, link, mknod, chmod, chown, utimes, statfs)
- file_ops: split into two layers — vnode-level (read, write, readdir, close, stat, truncate, fsync, optional `copy_file_range`) and file-level (open, release, fread, fwrite, ioctl, poll)

VFS initialization (vfs_init): creates vnode_cache and file_cache (kmem_cache), initializes dentry cache and mount mutex.

Filesystem registration: vfs_register_fs() adds fs_type to global fs_type_list.

## Path Resolution (fs/vfs/namei.c)

- vfs_namei_at(): resolves path from base path, supports NAMEI_FOLLOW (follow symlinks), NAMEI_CREATE, NAMEI_EXCL, NAMEI_DIRECTORY, NAMEI_NOFOLLOW
- Automatically crosses mount points during resolution (dentry->mounted)
- vfs_open_at_path(): path resolution + file open, handles O_CREAT/O_EXCL/O_TRUNC/O_DIRECTORY flags
- Linux ABI path-stat/access compatibility:
  - `newfstatat` supports `AT_EMPTY_PATH` and treats empty path without it as `ENOENT`
  - `statx` is wired to the same path resolution and returns `STATX_BASIC_STATS` data
  - `faccessat2`/`faccessat` support `AT_EMPTY_PATH` on fd targets
  - `faccessat2` accepts `AT_EACCESS` (currently same credential source as real IDs) and applies root-friendly access checks
  - `fchmodat`/`fchownat`/`utimensat` accept `AT_EMPTY_PATH` for fd-target metadata updates
  - `fchmodat2` is wired to `fchmodat` semantics and flag validation
  - `openat2` supports `struct open_how` parsing; `RESOLVE_NO_MAGICLINKS` is accepted, other `resolve` constraints are pending
  - `statfs` now resolves the target path before filesystem stat (non-existent paths return `ENOENT`), and `fstatfs` falls back to fd dentry mount when available (`EINVAL` only when no mount context exists)
- `umount2` decodes `flags` using Linux ABI width (`int`/32-bit); supports `UMOUNT_NOFOLLOW`, `MNT_DETACH` lazy-detach, `MNT_FORCE` recognition (`EOPNOTSUPP`), and `MNT_EXPIRE` two-phase semantics (first call `EAGAIN`, second call unmount)
- `umount2` returns `EINVAL` when the resolved path exists but is not a mountpoint (Linux-compatible error class for non-mount targets)
- path.c is a path construction helper (vfs_build_relpath, etc.), not involved in path resolution
- `umount2` follows Linux `int` ABI flag decoding (upper 32 bits ignored); unsupported flags return `EINVAL`
- `mount` validates `mountflags` using Linux ABI `unsigned long` width (native word size); supports semantic superblock flags (`MS_RDONLY`/`MS_NO*`/`MS_RELATIME` family), propagation flags, bind, and remount

## Dentry Cache (fs/vfs/dentry.c)

- 256-bucket hash table (DCACHE_HASH_SIZE), hashed by parent + name + mount
- LRU eviction policy, dcache_count tracks entry count, evicts when exceeding CONFIG_DCACHE_MAX
- Supports negative caching (DENTRY_NEGATIVE) for non-existent paths
- Dentry tree structure: parent/children/child linked lists, supports subtree traversal
- dentry_put/vnode_put use iterative (not recursive) parent-chain release to avoid stack overflow on deep directory trees
- dentry mount ownership is explicit: `dentry_set_mnt()` is the only assignment path for `dentry->mnt`, and performs `vfs_mount_hold()`/`vfs_mount_put()` balancing
- dentry kobj setup is lazy (not done in `dentry_alloc`), avoiding early registration before mount/vnode binding is semantically ready
- `dentry_prune_mount()` supports proactive dcache pruning for unmount/lazy-detach flows

## Mount System (fs/vfs/mount.c)

- mount_list: global mount linked list
- Supports bind mount (MOUNT_F_BIND)
- Mount propagation: private/shared/slave/unbindable implemented; propagation mode changes support `MS_REC` recursive subtree application
- Bind mounts support both `MS_BIND` (single mount) and `MS_BIND|MS_REC` recursive subtree bind; recursive bind mirrors source submount topology under the target subtree
- `MS_BIND|MS_REC` prunes unbindable submount subtrees instead of failing the whole bind operation
- Mount namespace roots hold mount references; clone/set-root/put paths now maintain mount refcounts together with root_dentry refs
- Unmount safety: `vfs_umount()` rejects unmount when child mounts exist or when mount refcount indicates external namespace/root users (returns `-EBUSY`)
- `vfs_umount2(..., VFS_UMOUNT_DETACH)` detaches the mount subtree from namespace visibility (lazy unmount path), then reaps detached mounts when they become reclaimable
- unmount paths proactively prune mount-associated dentries before refcount busy checks/reap, reducing stale dcache retention
- `vfs_mount_is_live()` provides a defensive liveness check for non-owning readers (e.g., observability/sysfs paths)
- Bind mounts reject unbindable sources (`MS_BIND` from `MOUNT_UNBINDABLE` source returns `EINVAL`)
- Root mount strategy (init_fs): prefers initramfs, then tries ext2 on vda-vdz block devices, falls back to devfs on / if all fail
- Mount order: root filesystem → /dev(devfs) → /proc(procfs) → /tmp(tmpfs) → /sys(sysfs)

## Open/Truncate Semantics (fs/vfs/file.c)

- vfs_open_at_path() propagates truncate callback failures when O_TRUNC is requested; open no longer succeeds if underlying truncate fails
- vfs_read/vfs_write guard against NULL vnode and NULL ops before dispatching
- vfs_seek returns -ESPIPE for VNODE_PIPE and VNODE_SOCKET
- Linux `close_range` supports range close and `CLOSE_RANGE_CLOEXEC`; `CLOSE_RANGE_UNSHARE` triggers fdtable copy-on-write before applying the range
- Linux ABI read/write extensions:
  - `pread64`/`pwrite64` and `preadv2`/`pwritev2` are wired through existing positional I/O paths
  - `preadv`/`pwritev` and `preadv2`/`pwritev2` follow Linux split-offset ABI (`pos_l`/`pos_h`)
  - `preadv2` supports `RWF_HIPRI|RWF_NOWAIT`; `pwritev2` supports `RWF_HIPRI|RWF_DSYNC|RWF_SYNC|RWF_NOWAIT`
  - `preadv2`/`pwritev2` decode `flags` using Linux ABI width (`int`/32-bit)
  - `read`/`write`/`close`/`lseek`/`pread64`/`pwrite64`/`readv`/`writev`/`preadv`/`pwritev`/`copy_file_range`/`fsync`/`fdatasync` decode `fd` via Linux ABI `int` width (32-bit); `lseek` decodes `whence` as 32-bit `int`
  - `preadv2`/`pwritev2` with offset `-1` follow non-positional `readv`/`writev` fallback
  - `copy_file_range` first tries optional vnode fast path (`file_ops.copy_file_range`) and falls back to buffered vnode read/write loop when unsupported (`-EOPNOTSUPP`/`-EXDEV`); `flags` (32-bit ABI width) must be zero, source/destination offsets are updated according to copied bytes, and pipe/socket endpoints are rejected
- `vfs_fsync()` now falls back to buffer-cache flush when filesystem-specific `fsync` op is absent; `sys_sync` is wired through `vfs_sync()` to the same flush path


Related references:
- references/00_REPO_MAP.md
- references/12_SYSCALL.md
- references/30_PROCESS.md
- references/33_IPC.md
- references/42_POLL_EPOLL.md
- references/43_BLOCK_FS_IMPLEMENTATIONS.md
- references/50_DRIVERS_BUS_DISCOVERY.md
