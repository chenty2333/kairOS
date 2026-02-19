/**
 * kernel/fs/ext2/inode.c - ext2 inode helpers
 */

#include <kairos/mm.h>
#include <kairos/string.h>

#include "ext2_internal.h"

int ext2_read_inode(struct ext2_mount *mnt, ino_t ino,
                    struct ext2_inode *inode) {
    if (ino == 0 || ino > mnt->sb->s_inodes_count)
        return -EINVAL;
    uint32_t group = (ino - 1) / mnt->inodes_per_group;
    uint32_t index = (ino - 1) % mnt->inodes_per_group;
    uint32_t isz = mnt->sb->s_inode_size ? mnt->sb->s_inode_size : 128;
    uint32_t ipb = mnt->block_size / isz;
    uint32_t block = mnt->gdt[group].bg_inode_table + (index / ipb);
    uint32_t off = (index % ipb) * isz;

    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(mnt, block, &blk_off);
    if (!bp)
        return -EIO;
    memcpy(inode, bp->data + blk_off + off, sizeof(*inode));
    brelse(bp);
    return 0;
}

int ext2_write_inode(struct ext2_mount *mnt, ino_t ino,
                     struct ext2_inode *inode) {
    uint32_t isz = mnt->sb->s_inode_size ? mnt->sb->s_inode_size : 128;
    uint32_t group = (ino - 1) / mnt->inodes_per_group;
    uint32_t idx = (ino - 1) % mnt->inodes_per_group;
    uint32_t boff = (idx * isz) / mnt->block_size;
    uint32_t ioff = (idx * isz) % mnt->block_size;

    uint32_t blk_off = 0;
    struct buf *bp =
        ext2_bread(mnt, mnt->gdt[group].bg_inode_table + boff, &blk_off);
    if (!bp)
        return -EIO;
    uint8_t *dst = bp->data + blk_off + ioff;
    memset(dst, 0, isz);
    size_t csz = MIN((size_t)isz, sizeof(*inode));
    memcpy(dst, inode, csz);
    bwrite(bp);
    brelse(bp);
    return 0;
}

struct vnode *ext2_cache_get(struct ext2_mount *mnt, ino_t ino) {
    if (!mnt)
        return NULL;
    mutex_lock(&mnt->icache_lock);
    struct ext2_inode_data *id;
    list_for_each_entry(id, &mnt->inode_cache, cache_node) {
        if (id->magic != EXT2_INODE_DATA_MAGIC)
            continue;
        if (id->ino == ino && id->vn) {
            vnode_get(id->vn);
            mutex_unlock(&mnt->icache_lock);
            return id->vn;
        }
    }
    mutex_unlock(&mnt->icache_lock);
    return NULL;
}

void ext2_cache_add(struct ext2_inode_data *id) {
    if (!id || !id->mnt)
        return;
    mutex_lock(&id->mnt->icache_lock);
    list_add(&id->cache_node, &id->mnt->inode_cache);
    mutex_unlock(&id->mnt->icache_lock);
}

int ext2_alloc_inode(struct ext2_mount *mnt, ino_t *out) {
    mutex_lock(&mnt->lock);
    uint32_t start_bg = mnt->s_last_alloc_group_ino;

    for (uint32_t i = 0; i < mnt->groups_count; i++) {
        uint32_t bg = (start_bg + i) % mnt->groups_count;

        if (mnt->gdt[bg].bg_free_inodes_count == 0)
            continue;
        uint32_t blk_off = 0;
        struct buf *bp =
            ext2_bread(mnt, mnt->gdt[bg].bg_inode_bitmap, &blk_off);
        if (!bp)
            continue;

        for (uint32_t j = 0; j < mnt->inodes_per_group; j++) {
            uint8_t *bitmap = bp->data + blk_off;
            if (!(bitmap[j / 8] & (1 << (j % 8)))) {
                bitmap[j / 8] |= (1 << (j % 8));
                bwrite(bp);
                mnt->gdt[bg].bg_free_inodes_count--;
                ext2_write_gd(mnt, bg);
                mnt->sb->s_free_inodes_count--;
                *out = bg * mnt->inodes_per_group + j + 1;
                mnt->s_last_alloc_group_ino = bg;
                brelse(bp);
                mutex_unlock(&mnt->lock);
                return 0;
            }
        }
        brelse(bp);
    }
    mutex_unlock(&mnt->lock);
    return -ENOSPC;
}

int ext2_free_inode(struct ext2_mount *mnt, ino_t ino) {
    if (ino == 0 || ino > mnt->sb->s_inodes_count) {
        return -EINVAL;
    }
    uint32_t adj = ino - 1;
    uint32_t bg = adj / mnt->inodes_per_group;
    uint32_t idx = adj % mnt->inodes_per_group;

    mutex_lock(&mnt->lock);
    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(mnt, mnt->gdt[bg].bg_inode_bitmap, &blk_off);
    if (!bp) {
        mutex_unlock(&mnt->lock);
        return -EIO;
    }
    uint8_t *bitmap = bp->data + blk_off;
    bitmap[idx / 8] &= ~(1 << (idx % 8));
    bwrite(bp);
    brelse(bp);
    mnt->gdt[bg].bg_free_inodes_count++;
    ext2_write_gd(mnt, bg);
    mnt->sb->s_free_inodes_count++;
    mutex_unlock(&mnt->lock);
    return 0;
}
