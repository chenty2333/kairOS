/**
 * kernel/fs/ext2/super.c - ext2 mount helpers
 */

#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>

#include "ext2_internal.h"

static void ext2_mount_destroy(struct ext2_mount *mnt) {
    if (!mnt)
        return;
    mnt->magic = 0;
    kfree(mnt->gdt);
    kfree(mnt->sb);
    kfree(mnt);
}

void ext2_mount_get(struct ext2_mount *mnt) {
    if (mnt)
        atomic_inc(&mnt->refcount);
}

void ext2_mount_put(struct ext2_mount *mnt) {
    if (!mnt)
        return;
    uint32_t old = atomic_fetch_sub(&mnt->refcount, 1);
    if (old == 0)
        panic("ext2_mount_put: refcount underflow");
    if (old == 1)
        ext2_mount_destroy(mnt);
}

int ext2_mount(struct mount *mnt) {
    struct ext2_mount *e = kzalloc(sizeof(*e));
    if (!e)
        return -ENOMEM;
    e->magic = EXT2_MOUNT_MAGIC;
    atomic_init(&e->refcount, 1);
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

int ext2_statfs(struct mount *mnt, struct kstatfs *st) {
    struct ext2_mount *e = mnt->fs_data;
    if (!e)
        return -EINVAL;
    memset(st, 0, sizeof(*st));
    st->f_type = EXT2_SUPER_MAGIC;
    st->f_bsize = e->block_size;
    st->f_frsize = e->block_size;
    st->f_blocks = e->sb->s_blocks_count;
    st->f_bfree = e->sb->s_free_blocks_count;
    st->f_bavail = e->sb->s_free_blocks_count - e->sb->s_r_blocks_count;
    st->f_files = e->sb->s_inodes_count;
    st->f_ffree = e->sb->s_free_inodes_count;
    st->f_namelen = EXT2_NAME_LEN;
    return 0;
}

int ext2_unmount(struct mount *mnt) {
    struct ext2_mount *e = mnt->fs_data;
    if (!e)
        return 0;
    if (e->magic != EXT2_MOUNT_MAGIC)
        return -EIO;

    /*
     * mnt->root and mnt->root_dentry hold the baseline root references.
     * Refcount above that means extra live users; refuse unmount.
     */
    if (mnt->root && atomic_read(&mnt->root->refcount) > 2)
        return -EBUSY;
    if (atomic_read(&e->refcount) > 2)
        return -EBUSY;

    mnt->fs_data = NULL;
    ext2_mount_put(e);
    return 0;
}
