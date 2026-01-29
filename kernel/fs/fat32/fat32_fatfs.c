/**
 * kernel/fs/fat32/fat32_fatfs.c - FatFs glue (placeholder)
 */

#include <kairos/types.h>

#include "fat32_internal.h"

int fat32_mount_fatfs(struct mount *mnt) {
    (void)mnt;
    return -ENOSYS;
}

int fat32_unmount_fatfs(struct mount *mnt) {
    (void)mnt;
    return 0;
}

struct vnode *fat32_lookup_fatfs(struct vnode *dir, const char *name) {
    (void)dir;
    (void)name;
    return NULL;
}
