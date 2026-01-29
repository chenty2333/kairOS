/**
 * kernel/fs/ext2/block.c - ext2 block allocator and mapping
 */

#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>

#include "ext2_internal.h"

struct buf *ext2_bread(struct ext2_mount *mnt, uint32_t bnum,
                       uint32_t *blk_off) {
    uint32_t per = ext2_blocks_per_io(mnt);
    uint32_t bio = bnum / per;
    uint32_t off = (bnum % per) * mnt->block_size;
    if (blk_off)
        *blk_off = off;
    return bread(mnt->dev, bio);
}

static int ext2_block_to_path(struct ext2_mount *mnt, uint32_t i_block,
                              struct ext2_path *path) {
    uint32_t ptrs = mnt->block_size / 4;

    if (i_block < 12) {
        path->depth = 0;
        path->offsets[0] = i_block;
        return 0;
    }
    i_block -= 12;

    if (i_block < ptrs) {
        path->depth = 1;
        path->offsets[0] = 12;
        path->offsets[1] = i_block;
        return 0;
    }
    i_block -= ptrs;

    if (i_block < ptrs * ptrs) {
        path->depth = 2;
        path->offsets[0] = 13;
        path->offsets[1] = i_block / ptrs;
        path->offsets[2] = i_block % ptrs;
        return 0;
    }
    i_block -= ptrs * ptrs;

    if (i_block < ptrs * ptrs * ptrs) {
        path->depth = 3;
        path->offsets[0] = 14;
        path->offsets[1] = i_block / (ptrs * ptrs);
        path->offsets[2] = (i_block / ptrs) % ptrs;
        path->offsets[3] = i_block % ptrs;
        return 0;
    }
    return -1;
}

int ext2_get_block(struct ext2_mount *mnt, struct ext2_inode_data *id,
                   uint32_t idx, uint32_t *out, int create) {
    struct ext2_path path;
    if (ext2_block_to_path(mnt, idx, &path) < 0)
        return -EIO;

    uint32_t *p = &id->inode.i_block[path.offsets[0]];
    struct buf *bp = NULL;
    uint32_t bnum = *p;

    if (!bnum) {
        if (!create) {
            *out = 0;
            return 0;
        }
        if (ext2_alloc_block(mnt, &bnum) < 0)
            return -ENOSPC;
        *p = bnum;
        id->inode.i_blocks += (mnt->block_size / 512);
        ext2_write_inode(mnt, id->ino, &id->inode);
        if (path.depth > 0) {
            uint32_t blk_off = 0;
            struct buf *nbp = ext2_bread(mnt, bnum, &blk_off);
            if (nbp) {
                memset(nbp->data + blk_off, 0, mnt->block_size);
                bwrite(nbp);
                brelse(nbp);
            }
        }
    }

    for (int i = 1; i <= path.depth; i++) {
        uint32_t blk_off = 0;
        bp = ext2_bread(mnt, bnum, &blk_off);
        if (!bp)
            return -EIO;

        p = ((uint32_t *)(bp->data + blk_off)) + path.offsets[i];
        bnum = *p;

        if (!bnum) {
            if (!create) {
                brelse(bp);
                *out = 0;
                return 0;
            }
            if (ext2_alloc_block(mnt, &bnum) < 0) {
                brelse(bp);
                return -ENOSPC;
            }
            *p = bnum;
            bwrite(bp);
            id->inode.i_blocks += (mnt->block_size / 512);
            ext2_write_inode(mnt, id->ino, &id->inode);

            if (i < path.depth) {
                uint32_t nboff = 0;
                struct buf *nbp = ext2_bread(mnt, bnum, &nboff);
                if (nbp) {
                    memset(nbp->data + nboff, 0, mnt->block_size);
                    bwrite(nbp);
                    brelse(nbp);
                }
            }
        }
        brelse(bp);
    }

    *out = bnum;
    return 0;
}

int ext2_write_gd(struct ext2_mount *mnt, uint32_t bg) {
    uint32_t bnum = 2 + (bg * sizeof(struct ext2_group_desc)) / mnt->block_size;
    uint32_t off = (bg * sizeof(struct ext2_group_desc)) % mnt->block_size;

    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
    if (!bp)
        return -EIO;
    memcpy(bp->data + blk_off + off, &mnt->gdt[bg],
           sizeof(struct ext2_group_desc));
    bwrite(bp);
    brelse(bp);
    return 0;
}

int ext2_alloc_block(struct ext2_mount *mnt, uint32_t *out) {
    mutex_lock(&mnt->lock);
    uint32_t start_bg = mnt->s_last_alloc_group_blk;

    for (uint32_t i = 0; i < mnt->groups_count; i++) {
        uint32_t bg = (start_bg + i) % mnt->groups_count;

        if (mnt->gdt[bg].bg_free_blocks_count == 0)
            continue;
        uint32_t blk_off = 0;
        struct buf *bp =
            ext2_bread(mnt, mnt->gdt[bg].bg_block_bitmap, &blk_off);
        if (!bp)
            continue;

        for (uint32_t j = 0; j < mnt->blocks_per_group; j++) {
            uint8_t *bitmap = bp->data + blk_off;
            if (!(bitmap[j / 8] & (1 << (j % 8)))) {
                bitmap[j / 8] |= (1 << (j % 8));
                bwrite(bp);
                mnt->gdt[bg].bg_free_blocks_count--;
                ext2_write_gd(mnt, bg);
                mnt->sb->s_free_blocks_count--;
                *out = bg * mnt->blocks_per_group + j;
                mnt->s_last_alloc_group_blk = bg;
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

int ext2_free_block(struct ext2_mount *mnt, uint32_t bnum) {
    if (bnum == 0) {
        return 0;
    }
    uint32_t bg = bnum / mnt->blocks_per_group;
    uint32_t idx = bnum % mnt->blocks_per_group;
    if (bg >= mnt->groups_count) {
        return -EINVAL;
    }

    mutex_lock(&mnt->lock);
    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(mnt, mnt->gdt[bg].bg_block_bitmap, &blk_off);
    if (!bp) {
        mutex_unlock(&mnt->lock);
        return -EIO;
    }
    uint8_t *bitmap = bp->data + blk_off;
    bitmap[idx / 8] &= ~(1 << (idx % 8));
    bwrite(bp);
    brelse(bp);
    mnt->gdt[bg].bg_free_blocks_count++;
    ext2_write_gd(mnt, bg);
    mnt->sb->s_free_blocks_count++;
    mutex_unlock(&mnt->lock);
    return 0;
}

static int ext2_free_indirect(struct ext2_mount *mnt, uint32_t bnum, int depth) {
    if (bnum == 0) {
        return 0;
    }
    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
    if (!bp) {
        return -EIO;
    }
    uint32_t ptrs = mnt->block_size / 4;
    uint32_t *entries = (uint32_t *)(bp->data + blk_off);
    for (uint32_t i = 0; i < ptrs; i++) {
        if (entries[i] == 0) {
            continue;
        }
        if (depth > 0) {
            ext2_free_indirect(mnt, entries[i], depth - 1);
        } else {
            ext2_free_block(mnt, entries[i]);
        }
    }
    brelse(bp);
    ext2_free_block(mnt, bnum);
    return 0;
}

int ext2_truncate_blocks(struct ext2_mount *mnt, ino_t ino,
                         struct ext2_inode *inode) {
    for (int i = 0; i < 12; i++) {
        if (inode->i_block[i]) {
            ext2_free_block(mnt, inode->i_block[i]);
            inode->i_block[i] = 0;
        }
    }
    if (inode->i_block[EXT2_IND_BLOCK]) {
        ext2_free_indirect(mnt, inode->i_block[EXT2_IND_BLOCK], 0);
        inode->i_block[EXT2_IND_BLOCK] = 0;
    }
    if (inode->i_block[EXT2_DIND_BLOCK]) {
        ext2_free_indirect(mnt, inode->i_block[EXT2_DIND_BLOCK], 1);
        inode->i_block[EXT2_DIND_BLOCK] = 0;
    }
    if (inode->i_block[EXT2_TIND_BLOCK]) {
        ext2_free_indirect(mnt, inode->i_block[EXT2_TIND_BLOCK], 2);
        inode->i_block[EXT2_TIND_BLOCK] = 0;
    }
    inode->i_size = 0;
    inode->i_blocks = 0;
    ext2_write_inode(mnt, ino, inode);
    return 0;
}

static void ext2_trunc_indirect(struct ext2_mount *mnt, uint32_t bnum,
                                uint32_t from, int depth, int *freed_all) {
    if (bnum == 0) {
        *freed_all = 1;
        return;
    }
    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
    if (!bp) {
        *freed_all = 0;
        return;
    }
    uint32_t ptrs = mnt->block_size / 4;
    uint32_t *entries = (uint32_t *)(bp->data + blk_off);
    int all_zero = 1;
    int dirty = 0;

    for (uint32_t i = 0; i < ptrs; i++) {
        if (entries[i] == 0) {
            continue;
        }
        if (i < from) {
            all_zero = 0;
            continue;
        }
        if (depth > 0) {
            int child_freed = 0;
            ext2_trunc_indirect(mnt, entries[i], 0, depth - 1, &child_freed);
            if (child_freed) {
                entries[i] = 0;
                dirty = 1;
            } else {
                all_zero = 0;
            }
        } else {
            ext2_free_block(mnt, entries[i]);
            entries[i] = 0;
            dirty = 1;
        }
    }
    if (dirty) {
        bwrite(bp);
    }
    brelse(bp);

    if (all_zero) {
        ext2_free_block(mnt, bnum);
        *freed_all = 1;
    } else {
        *freed_all = 0;
    }
}

int ext2_vnode_truncate(struct vnode *vn, off_t length) {
    struct ext2_inode_data *id = vn->fs_data;
    if (!id) {
        return -EINVAL;
    }
    struct ext2_mount *mnt = id->mnt;

    if (length < 0) {
        return -EINVAL;
    }
    uint64_t new_size = (uint64_t)length;
    uint64_t old_size = id->inode.i_size;

    if (new_size == old_size) {
        return 0;
    }

    if (new_size > old_size) {
        id->inode.i_size = (uint32_t)new_size;
        vn->size = new_size;
        ext2_write_inode(mnt, id->ino, &id->inode);
        return 0;
    }

    if (new_size == 0) {
        ext2_truncate_blocks(mnt, id->ino, &id->inode);
        vn->size = 0;
        return 0;
    }

    uint32_t bs = mnt->block_size;
    uint32_t ptrs = bs / 4;
    uint32_t keep_blocks = (new_size + bs - 1) / bs;

    for (uint32_t i = keep_blocks; i < 12; i++) {
        if (id->inode.i_block[i]) {
            ext2_free_block(mnt, id->inode.i_block[i]);
            id->inode.i_blocks -= (bs / 512);
            id->inode.i_block[i] = 0;
        }
    }

    if (id->inode.i_block[EXT2_IND_BLOCK]) {
        if (keep_blocks <= 12) {
            ext2_free_indirect(mnt, id->inode.i_block[EXT2_IND_BLOCK], 0);
            id->inode.i_block[EXT2_IND_BLOCK] = 0;
        } else if (keep_blocks < 12 + ptrs) {
            int freed = 0;
            ext2_trunc_indirect(mnt, id->inode.i_block[EXT2_IND_BLOCK],
                                keep_blocks - 12, 0, &freed);
            if (freed) {
                id->inode.i_block[EXT2_IND_BLOCK] = 0;
            }
        }
    }

    uint32_t dind_start = 12 + ptrs;
    if (id->inode.i_block[EXT2_DIND_BLOCK]) {
        if (keep_blocks <= dind_start) {
            ext2_free_indirect(mnt, id->inode.i_block[EXT2_DIND_BLOCK], 1);
            id->inode.i_block[EXT2_DIND_BLOCK] = 0;
        } else if (keep_blocks < dind_start + ptrs * ptrs) {
            uint32_t rel = keep_blocks - dind_start;
            uint32_t first_group = rel / ptrs;
            uint32_t first_in_group = rel % ptrs;

            uint32_t blk_off = 0;
            struct buf *bp = ext2_bread(mnt, id->inode.i_block[EXT2_DIND_BLOCK],
                                        &blk_off);
            if (bp) {
                uint32_t *entries = (uint32_t *)(bp->data + blk_off);
                int dirty = 0;
                if (entries[first_group] && first_in_group > 0) {
                    int freed = 0;
                    ext2_trunc_indirect(mnt, entries[first_group],
                                        first_in_group, 0, &freed);
                    if (freed) {
                        entries[first_group] = 0;
                        dirty = 1;
                    }
                    first_group++;
                }
                for (uint32_t i = first_group; i < ptrs; i++) {
                    if (entries[i]) {
                        ext2_free_indirect(mnt, entries[i], 0);
                        entries[i] = 0;
                        dirty = 1;
                    }
                }
                if (dirty) {
                    bwrite(bp);
                }
                brelse(bp);

                int all_zero = 1;
                bp = ext2_bread(mnt, id->inode.i_block[EXT2_DIND_BLOCK],
                                &blk_off);
                if (bp) {
                    entries = (uint32_t *)(bp->data + blk_off);
                    for (uint32_t i = 0; i < ptrs; i++) {
                        if (entries[i]) {
                            all_zero = 0;
                            break;
                        }
                    }
                    brelse(bp);
                }
                if (all_zero) {
                    ext2_free_block(mnt, id->inode.i_block[EXT2_DIND_BLOCK]);
                    id->inode.i_block[EXT2_DIND_BLOCK] = 0;
                }
            }
        }
    }

    uint32_t tind_start = dind_start + ptrs * ptrs;
    if (id->inode.i_block[EXT2_TIND_BLOCK]) {
        if (keep_blocks <= tind_start) {
            ext2_free_indirect(mnt, id->inode.i_block[EXT2_TIND_BLOCK], 2);
            id->inode.i_block[EXT2_TIND_BLOCK] = 0;
        }
    }

    uint32_t count = 0;
    for (int i = 0; i < EXT2_N_BLOCKS; i++) {
        if (id->inode.i_block[i]) {
            count++;
        }
    }
    id->inode.i_blocks = count * (bs / 512);
    id->inode.i_size = (uint32_t)new_size;
    vn->size = new_size;
    ext2_write_inode(mnt, id->ino, &id->inode);
    return 0;
}
