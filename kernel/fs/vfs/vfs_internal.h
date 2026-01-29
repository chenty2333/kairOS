/**
 * kernel/fs/vfs/vfs_internal.h - VFS internal shared state
 */

#ifndef _KAIROS_VFS_INTERNAL_H
#define _KAIROS_VFS_INTERNAL_H

#include <kairos/list.h>
#include <kairos/spinlock.h>
#include <kairos/sync.h>
#include <kairos/types.h>

struct kmem_cache;
struct mount;
struct mount_ns;

extern struct kmem_cache *vnode_cache;
extern struct kmem_cache *file_cache;

extern struct list_head mount_list;
extern struct list_head fs_type_list;
extern spinlock_t vfs_lock;
extern struct mount *root_mount;
extern struct mutex mount_mutex;
extern struct mount_ns init_mnt_ns;

#endif
