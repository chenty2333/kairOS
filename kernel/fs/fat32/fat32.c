/**
 * kernel/fs/fat32/fat32.c - FAT32 registration (stub)
 */

#include <kairos/printk.h>
#include <kairos/vfs.h>

#include "fat32_internal.h"

static int fat32_mount(struct mount *mnt) {
    (void)mnt;
    return -ENOSYS;
}

static int fat32_unmount(struct mount *mnt) {
    (void)mnt;
    return 0;
}

static struct vfs_ops fat32_ops = {
    .name = "fat32",
    .mount = fat32_mount,
    .unmount = fat32_unmount,
};

static struct fs_type fat32_type = {.name = "fat32", .ops = &fat32_ops};

void fat32_init(void) {
    if (vfs_register_fs(&fat32_type) < 0)
        pr_err("fat32: reg failed\n");
    else
        pr_info("fat32: initialized (stub)\n");
}
