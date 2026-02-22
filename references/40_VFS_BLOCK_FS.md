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
- path.c is a path construction helper (vfs_build_relpath, etc.), not involved in path resolution

## Dentry Cache (fs/vfs/dentry.c)

- 256-bucket hash table (DCACHE_HASH_SIZE), hashed by parent + name + mount
- LRU eviction policy, dcache_count tracks entry count, evicts when exceeding CONFIG_DCACHE_MAX
- Supports negative caching (DENTRY_NEGATIVE) for non-existent paths
- Dentry tree structure: parent/children/child linked lists, supports subtree traversal

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
- sysfs (fs/sysfs/): device model filesystem
- tmpfs (fs/tmpfs/): in-memory filesystem

Special:
- initramfs (fs/initramfs/): CPIO format initramfs parsing and mounting
- pipe (fs/ipc/pipe.c): pipes, accessed through VFS interface

## poll/epoll (fs/poll/)

- vfs_poll.c: VFS poll infrastructure, based on pollwait mechanism
- epoll.c: epoll implementation, epoll instances are VNODE_EPOLL type vnodes

Related references:
- references/00_REPO_MAP.md
- references/30_PROCESS_SCHED_SYNC_IPC.md
- references/50_DRIVERS_BUS_DISCOVERY.md
