/**
 * kernel/fs/vfs/core.c - VFS core initialization
 */

#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/vfs.h>
#include <kairos/dentry.h>

#include "vfs_internal.h"

struct kmem_cache *vnode_cache;
struct kmem_cache *file_cache;

void vfs_init(void) {
    vnode_cache = kmem_cache_create("vnode", sizeof(struct vnode), NULL);
    file_cache = kmem_cache_create("file", sizeof(struct file), NULL);
    dentry_init();
    mutex_init(&mount_mutex, "mount");
    memset(&init_mnt_ns, 0, sizeof(init_mnt_ns));
    atomic_init(&init_mnt_ns.refcount, 1);
    pr_info("VFS: initialized (caches ready)\n");
}

struct file *vfs_file_alloc(void) {
    struct file *file = kmem_cache_alloc(file_cache);
    if (!file)
        return NULL;
    memset(file, 0, sizeof(*file));
    atomic_init(&file->refcount, 1);
    mutex_init(&file->lock, "file");
    return file;
}

void vfs_file_free(struct file *file) {
    if (!file)
        return;
    kmem_cache_free(file_cache, file);
}

void vfs_dump_mounts(void) {
    struct mount *mnt;
    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        pr_info("VFS mount: %s\n", mnt->mountpoint);
    }
    spin_unlock(&vfs_lock);
}

int vfs_register_fs(struct fs_type *fs) {
    if (!fs || !fs->name || !fs->ops)
        return -EINVAL;
    spin_lock(&vfs_lock);
    list_add_tail(&fs->list, &fs_type_list);
    spin_unlock(&vfs_lock);
    return 0;
}
