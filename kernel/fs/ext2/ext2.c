/**
 * kernel/fs/ext2/ext2.c - ext2 registration
 */

#include <kairos/printk.h>
#include <kairos/vfs.h>

#include "ext2_internal.h"

static struct vfs_ops ext2_ops = {
    .name = "ext2",
    .mount = ext2_mount,
    .unmount = ext2_unmount,
    .lookup = ext2_lookup,
    .create = ext2_create,
    .mkdir = ext2_mkdir,
    .symlink = ext2_symlink,
    .link = ext2_link,
    .mknod = ext2_mknod,
    .chmod = ext2_chmod,
    .chown = ext2_chown,
    .utimes = ext2_utimes,
    .statfs = ext2_statfs,
    .unlink = ext2_unlink,
    .rmdir = ext2_rmdir,
    .rename = ext2_rename,
};

static struct fs_type ext2_type = {.name = "ext2", .ops = &ext2_ops};

void ext2_init(void) {
    vfs_register_fs(&ext2_type);
}
