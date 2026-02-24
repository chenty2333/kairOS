# 40 — VFS / Block I/O / Filesystems

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
- file_ops: split into two layers — vnode-level (read, write, readdir, close, stat, truncate, fsync) and file-level (open, release, fread, fwrite, ioctl, poll)

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
  - `umount2` decodes `flags` using Linux ABI width (`int`/32-bit); currently only `flags=0` is implemented
- path.c is a path construction helper (vfs_build_relpath, etc.), not involved in path resolution
- `mount`/`umount2` syscall entry handling rejects non-zero high 32-bit flag bits (`EINVAL`) and then applies low-32 Linux flag decoding

## Dentry Cache (fs/vfs/dentry.c)

- 256-bucket hash table (DCACHE_HASH_SIZE), hashed by parent + name + mount
- LRU eviction policy, dcache_count tracks entry count, evicts when exceeding CONFIG_DCACHE_MAX
- Supports negative caching (DENTRY_NEGATIVE) for non-existent paths
- Dentry tree structure: parent/children/child linked lists, supports subtree traversal
- dentry_put/vnode_put use iterative (not recursive) parent-chain release to avoid stack overflow on deep directory trees

## Mount System (fs/vfs/mount.c)

- mount_list: global mount linked list
- Supports bind mount (MOUNT_F_BIND)
- Mount propagation: private/shared/slave implemented, unbindable has enum value only
- Mount namespace roots hold mount references; clone/set-root/put paths now maintain mount refcounts together with root_dentry refs
- Unmount safety: vfs_umount() rejects unmount when child mounts exist or when mount refcount indicates external namespace/root users (returns -EBUSY)
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
  - `copy_file_range` is wired through vnode read/write paths; `flags` (32-bit ABI width) must be zero, source/destination offsets are updated according to copied bytes, and pipe/socket endpoints are rejected

## Block I/O Layer (fs/bio/bio.c)

- Buffer cache: 128 static buf structs (NBUF=128), 4KB each
- 32-bucket hash table indexed by (dev, blockno)
- LRU eviction: released buffers move to LRU head, allocation takes unused non-dirty buffers from LRU tail
- bread(): read block, returns from cache on hit, reads from device via blkdev_read() on miss
- bwrite(): writes block back to device
- brelse(): release buffer (unlock + decrement refcount + update LRU)
- Buffers protected by mutex for concurrent access

## Implemented Filesystems

Disk filesystems:
- ext2 (fs/ext2/): full implementation, includes super, inode, block, dir, vnode modules
- fat32 (fs/fat32/): currently a stub (mount returns -ENOSYS)

Pseudo filesystems:
- devfs (fs/devfs/): device filesystem
- procfs (fs/procfs/): process information filesystem
  - exposes `/proc/mounts` and `/proc/<pid>/mounts`
  - `/proc/self` symlink target is generated per lookup from current task pid
- sysfs (fs/sysfs/): device model filesystem
- tmpfs (fs/tmpfs/): in-memory filesystem

Special:
- initramfs (fs/initramfs/): CPIO format initramfs parsing and mounting
- pipe (fs/ipc/pipe.c): pipes, accessed through VFS interface
  - Blocking `read()` now returns once any bytes are available; it does not wait to fill the full requested length when the pipe already has data

## poll/epoll (fs/poll/)

- vfs_poll.c: VFS poll infrastructure, based on pollwait mechanism
- epoll.c: epoll implementation, epoll instances are VNODE_EPOLL type vnodes
- Event modes: level-trigger default, plus `EPOLLET` and `EPOLLONESHOT` (oneshot requires `EPOLL_CTL_MOD` rearm)
- Linux ABI compatibility includes `epoll_pwait2` (timespec timeout + strict `sigsetsize == sizeof(sigset_t)` checks), `accept4` (`SOCK_NONBLOCK`/`SOCK_CLOEXEC`), and socket message syscalls (`sendmsg`/`recvmsg`/`sendmmsg`/`recvmmsg`)
- Linux ABI compatibility also includes `eventfd2`, `timerfd_create/settime/gettime`, and `signalfd4` via anon-vnode pollable file descriptors
- `epoll_create1`, `eventfd2`, `timerfd_create`, `timerfd_settime`, `signalfd4`, and `inotify_init1` decode `flags` using Linux ABI width (`int`/32-bit)
- `epoll_ctl` decodes `op` as Linux ABI `int` (32-bit), and `epoll_wait` decodes `maxevents`/`timeout` as Linux ABI `int` (32-bit)
- `timerfd_create` accepts `CLOCK_REALTIME`/`CLOCK_MONOTONIC` plus `CLOCK_BOOTTIME`/`*_ALARM` aliases (mapped to realtime/monotonic base clocks)
- `timerfd_settime` accepts `TFD_TIMER_CANCEL_ON_SET` for realtime absolute timers; after `clock_settime(CLOCK_REALTIME, ...)`, reads fail with `ECANCELED` until re-armed
- `inotify_init1`/`inotify_add_watch`/`inotify_rm_watch` are wired; VFS open/write/create/delete/rename/close paths emit inotify events to watched vnodes
- `sendmsg`/`recvmsg` currently support iovec payload and optional peer address; ancillary data (`msg_control`) is not implemented (`msg_controllen` must be zero)
- `recvmsg` bounds source-address copy length by `min(user_msg_namelen, kernel_sockaddr_len)` using width-safe arithmetic (no signed wrap on large `msg_namelen`)
- AF_UNIX stream send paths honor `MSG_NOSIGNAL` (suppress `SIGPIPE`, return `EPIPE` only)
- `recvmmsg` supports `MSG_WAITFORONE` batching behavior and kernel timeout waits (timespec deadline)
- socket message/accept syscall `flags` are decoded using Linux ABI width (`int`/32-bit) for `accept4`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`
- socket control/int arguments are decoded with Linux ABI `int` width (`socket`/`socketpair` domain/type/protocol, socket syscalls `fd`, `listen` backlog, `shutdown` how, `setsockopt`/`getsockopt` level/optname/optlen, `getsockopt` user `optlen_ptr` value, `sendto`/`recvfrom` flags, sockaddr lengths)
- `sendmmsg`/`recvmmsg` decode `vlen` using Linux ABI width (`unsigned int`/32-bit), ignoring upper 32 syscall argument bits
- socket address-length values read from userspace (`accept*`, `recvfrom`, `getsockname`, `getpeername`) are decoded as 32-bit ABI values before range checks
- `poll`/`ppoll` with `nfds=0` now sleep for the requested timeout (or until signal) instead of returning immediately
- `select`/`pselect6` with no watched fds also honor timeout sleep semantics
- `select` updates user `timeval` with remaining time on return (`success`/`EINTR`)
- `ppoll`/`pselect6` now temporarily install the provided signal mask during wait and restore the original mask on return
- raw `ppoll`/`pselect6` also update user `timespec` with remaining timeout on return (`success`/`EINTR`), matching Linux syscall-level ABI
- `renameat2` supports `flags=0` and `RENAME_NOREPLACE` (`EEXIST` when destination already exists)
- aarch64 `open/openat` performs userspace `O_*` bit translation at syscall boundary (`O_DIRECTORY`/`O_NOFOLLOW`/`O_LARGEFILE`), while unsupported `O_DIRECT` still returns `EINVAL`
- `getdents64` follows Linux ABI argument width for `count` (`unsigned int`): upper 32 bits are ignored
- `newfstatat` accepts `AT_NO_AUTOMOUNT` as a compatibility no-op
- `statx` and `newfstatat` both decode `flags` using Linux ABI width (`int`/32-bit)
- `fstatfs`/`fstat`/`getdents64` decode `fd` as Linux ABI `int` (32-bit), and `newfstatat`/`statx` decode `dirfd` as 32-bit `int` before `AT_FDCWD` checks and path resolution
- path-based `*at` syscalls (`fchmodat`, `fchownat`, `utimensat`, `faccessat(2)`, `unlinkat`, `linkat`) decode `flags` via Linux ABI width (`int`/32-bit); `faccessat*` also decodes `mode` as 32-bit
- `dup3` and `pipe2` decode `flags` via Linux ABI width (`int`/32-bit)
- `fcntl` decodes `cmd`/`arg` via Linux ABI `int` width (32-bit)
- `ioctl` decodes `fd`/`cmd` via Linux ABI width (`unsigned int`/32-bit) before in-kernel command routing

Related references:
- references/00_REPO_MAP.md
- references/30_PROCESS_SCHED_SYNC_IPC.md
- references/50_DRIVERS_BUS_DISCOVERY.md
