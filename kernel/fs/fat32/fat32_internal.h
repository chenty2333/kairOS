/**
 * kernel/fs/fat32/fat32_internal.h - FAT32 internal glue
 */

#ifndef _KAIROS_FAT32_INTERNAL_H
#define _KAIROS_FAT32_INTERNAL_H

#include <kairos/sync.h>
#include <kairos/types.h>

struct blkdev;
struct mount;
struct vnode;

struct fat32_mount {
    struct blkdev *dev;
    void *fatfs;
    struct mutex lock;
};

int fat32_mount_fatfs(struct mount *mnt);
int fat32_unmount_fatfs(struct mount *mnt);
struct vnode *fat32_lookup_fatfs(struct vnode *dir, const char *name);

#endif
