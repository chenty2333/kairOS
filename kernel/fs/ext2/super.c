/**
 * kernel/fs/ext2/super.c - ext2 mount helpers
 */

#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>

#include "ext2_internal.h"

int ext2_mount(struct mount *mnt) {
    struct ext2_mount *e = kzalloc(sizeof(*e));
    if (!e)
        return -ENOMEM;
    e->dev = mnt->dev;
    mutex_init(&e->lock, "ext2_mount");
    mutex_init(&e->icache_lock, "ext2_icache");
    INIT_LIST_HEAD(&e->inode_cache);
    e->s_last_alloc_group_blk = 0;
    e->s_last_alloc_group_ino = 0;

    struct buf *bp = bread(mnt->dev, 0);
    if (!bp) {
        kfree(e);
        return -EIO;
    }
    e->sb = kmalloc(sizeof(struct ext2_superblock));
    memcpy(e->sb, bp->data + 1024, sizeof(*e->sb));
    brelse(bp);

    if (e->sb->s_magic != EXT2_SUPER_MAGIC) {
        kfree(e->sb);
        kfree(e);
        return -EINVAL;
    }
    e->block_size = 1024 << e->sb->s_log_block_size;
    e->inodes_per_group = e->sb->s_inodes_per_group;
    e->blocks_per_group = e->sb->s_blocks_per_group;
    e->groups_count = (e->sb->s_blocks_count + e->sb->s_blocks_per_group - 1) /
                      e->sb->s_blocks_per_group;

    size_t gsz = e->groups_count * sizeof(struct ext2_group_desc);
    e->gdt = kmalloc(gsz);
    uint32_t gboff = 0;
    struct buf *gbp = ext2_bread(e, e->sb->s_first_data_block + 1, &gboff);
    if (!gbp) {
        kfree(e->sb);
        kfree(e);
        return -EIO;
    }
    memcpy(e->gdt, gbp->data + gboff, gsz);
    brelse(gbp);

    struct vnode *rv = ext2_create_vnode(e, EXT2_ROOT_INO);
    if (!rv) {
        kfree(e->gdt);
        kfree(e->sb);
        kfree(e);
        return -EIO;
    }
    rv->mount = mnt;
    mnt->root = rv;
    mnt->fs_data = e;
    pr_info("ext2: mounted (%u bytes/block)\n", e->block_size);
    return 0;
}

int ext2_unmount(struct mount *mnt) {
    struct ext2_mount *e = mnt->fs_data;
    if (e) {
        kfree(e->gdt);
        kfree(e->sb);
        kfree(e);
    }
    return 0;
}
