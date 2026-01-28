/**
 * kernel/fs/ext2/ext2.c - ext2 File System Implementation
 */

#include <kairos/blkdev.h>
#include <kairos/buf.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

#define EXT2_SUPER_MAGIC 0xEF53
#define EXT2_IO_BLOCK_SIZE 4096
#define EXT2_ROOT_INO 2
#define EXT2_NAME_LEN 255

/* Inode modes */
#define EXT2_S_IFREG 0x8000
#define EXT2_S_IFDIR 0x4000
#define EXT2_S_IFLNK 0xA000

/* File types */
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR 2
#define EXT2_FT_SYMLINK 7

/* Indirect block levels */
#define EXT2_IND_BLOCK 12
#define EXT2_DIND_BLOCK 13
#define EXT2_TIND_BLOCK 14
#define EXT2_N_BLOCKS 15

struct ext2_superblock {
    uint32_t s_inodes_count, s_blocks_count, s_r_blocks_count,
        s_free_blocks_count, s_free_inodes_count, s_first_data_block,
        s_log_block_size, s_log_frag_size, s_blocks_per_group,
        s_frags_per_group, s_inodes_per_group, s_mtime, s_wtime;
    uint16_t s_mnt_count, s_max_mnt_count, s_magic, s_state, s_errors,
        s_minor_rev_level;
    uint32_t s_lastcheck, s_checkinterval, s_creator_os, s_rev_level;
    uint16_t s_def_resuid, s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size, s_block_group_nr;
    uint32_t s_feature_compat, s_feature_incompat, s_feature_ro_compat;
    uint8_t s_uuid[16];
    char s_volume_name[16], s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;
    uint8_t s_prealloc_blocks, s_prealloc_dir_blocks;
    uint16_t s_padding1;
    uint32_t s_reserved[204];
} __packed;

struct ext2_group_desc {
    uint32_t bg_block_bitmap, bg_inode_bitmap, bg_inode_table;
    uint16_t bg_free_blocks_count, bg_free_inodes_count, bg_used_dirs_count,
        bg_pad;
    uint32_t bg_reserved[3];
} __packed;

struct ext2_inode {
    uint16_t i_mode, i_uid;
    uint32_t i_size, i_atime, i_ctime, i_mtime, i_dtime;
    uint16_t i_gid, i_links_count;
    uint32_t i_blocks, i_flags, i_osd1, i_block[15], i_generation, i_file_acl,
        i_dir_acl, i_faddr;
    uint8_t i_osd2[12];
} __packed;

struct ext2_dirent {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len, file_type;
    char name[EXT2_NAME_LEN];
} __packed;

struct ext2_mount {
    struct blkdev *dev;
    struct ext2_superblock *sb;
    struct ext2_group_desc *gdt;
    uint32_t block_size, groups_count, inodes_per_group, blocks_per_group;
    struct mutex lock;
    struct mutex icache_lock;
    struct list_head inode_cache;
    uint32_t s_last_alloc_group_blk;
    uint32_t s_last_alloc_group_ino;
};

static inline uint32_t ext2_blocks_per_io(struct ext2_mount *mnt) {
    return EXT2_IO_BLOCK_SIZE / mnt->block_size;
}

static struct buf *ext2_bread(struct ext2_mount *mnt, uint32_t bnum,
                              uint32_t *blk_off) {
    uint32_t per = ext2_blocks_per_io(mnt);
    uint32_t bio = bnum / per;
    uint32_t off = (bnum % per) * mnt->block_size;
    if (blk_off)
        *blk_off = off;
    return bread(mnt->dev, bio);
}

struct ext2_inode_data {
    ino_t ino;
    struct ext2_inode inode;
    struct ext2_mount *mnt;
    struct vnode *vn;
    struct list_head cache_node;
};

/* Forward declarations */
static int ext2_write_inode(struct ext2_mount *mnt, ino_t ino, struct ext2_inode *inode);
static int ext2_alloc_block(struct ext2_mount *mnt, uint32_t *out);
static int ext2_vnode_poll(struct vnode *vn, uint32_t events);

static int ext2_read_inode(struct ext2_mount *mnt, ino_t ino,
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

struct ext2_path {
    int depth;
    uint32_t offsets[4];
};

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

static int ext2_get_block(struct ext2_mount *mnt, struct ext2_inode_data *id,
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
        // If this is an indirect block, it must be zeroed
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
            bwrite(bp); // Update the parent indirect block
            id->inode.i_blocks += (mnt->block_size / 512);
            ext2_write_inode(mnt, id->ino, &id->inode); // Update accounting

            // Zero the new block if it's still an intermediate node
            // (not the final data block)
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

static ssize_t ext2_vnode_read(struct vnode *vn, void *buf, size_t len,
                               off_t offset) {
    struct ext2_inode_data *id = vn->fs_data;
    struct ext2_mount *mnt = id->mnt;
    if (vn->type == VNODE_SYMLINK && id->inode.i_blocks == 0 &&
        id->inode.i_size <= sizeof(id->inode.i_block)) {
        if (offset >= (off_t)id->inode.i_size)
            return 0;
        if (offset + len > id->inode.i_size)
            len = id->inode.i_size - offset;
        memcpy(buf, (const char *)id->inode.i_block + offset, len);
        return (ssize_t)len;
    }
    if (offset >= (off_t)id->inode.i_size)
        return 0;
    if (offset + len > id->inode.i_size)
        len = id->inode.i_size - offset;

    size_t total = 0;
    while (len > 0) {
        uint32_t bidx = offset / mnt->block_size,
                 boff = offset % mnt->block_size;
        uint32_t nr = MIN(len, mnt->block_size - boff), bnum;
        if (ext2_get_block(mnt, id, bidx, &bnum, 0) < 0)
            break;

        if (bnum == 0)
            memset((char *)buf + total, 0, nr);
        else {
            uint32_t blk_off = 0;
            struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
            if (!bp)
                break;
            memcpy((char *)buf + total, bp->data + blk_off + boff, nr);
            brelse(bp);
        }
        total += nr;
        offset += nr;
        len -= nr;
    }
    return total;
}

static int ext2_vnode_readdir(struct vnode *vn, struct dirent *ent,
                              off_t *offset) {
    struct ext2_inode_data *id = vn->fs_data;
    struct ext2_mount *mnt = id->mnt;
    if (*offset >= (off_t)id->inode.i_size)
        return 0;

    uint32_t bidx = *offset / mnt->block_size, boff = *offset % mnt->block_size,
             bnum;
    if (ext2_get_block(mnt, id, bidx, &bnum, 0) < 0 || bnum == 0)
        return 0;

    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
    if (!bp)
        return -EIO;

    struct ext2_dirent *de =
        (struct ext2_dirent *)(bp->data + blk_off + boff);
    if (de->inode == 0 || de->rec_len == 0 ||
        de->rec_len < 8 ||
        de->rec_len > (mnt->block_size - boff)) {
        brelse(bp);
        return 0;
    }

    ent->d_ino = de->inode;
    ent->d_off = *offset;
    ent->d_reclen = sizeof(*ent);
    static const uint8_t map[] = {DT_UNKNOWN, DT_REG,  DT_DIR,  DT_CHR,
                                  DT_BLK,     DT_FIFO, DT_SOCK, DT_LNK};
    ent->d_type = (de->file_type < 8) ? map[de->file_type] : DT_UNKNOWN;
    size_t nlen = MIN(de->name_len, CONFIG_NAME_MAX - 1);
    memcpy(ent->d_name, de->name, nlen);
    ent->d_name[nlen] = '\0';

    *offset += de->rec_len;
    brelse(bp);
    return 1;
}

static int ext2_vnode_close(struct vnode *vn) {
    struct ext2_inode_data *id = vn->fs_data;
    if (id && id->mnt) {
        mutex_lock(&id->mnt->icache_lock);
        if (!list_empty(&id->cache_node)) {
            list_del(&id->cache_node);
            INIT_LIST_HEAD(&id->cache_node);
        }
        mutex_unlock(&id->mnt->icache_lock);
    }
    kfree(id);
    kfree(vn);
    return 0;
}

static struct vnode *ext2_cache_get(struct ext2_mount *mnt, ino_t ino) {
    if (!mnt)
        return NULL;
    mutex_lock(&mnt->icache_lock);
    struct ext2_inode_data *id;
    list_for_each_entry(id, &mnt->inode_cache, cache_node) {
        if (id->ino == ino && id->vn) {
            vnode_get(id->vn);
            mutex_unlock(&mnt->icache_lock);
            return id->vn;
        }
    }
    mutex_unlock(&mnt->icache_lock);
    return NULL;
}

static void ext2_cache_add(struct ext2_inode_data *id) {
    if (!id || !id->mnt)
        return;
    mutex_lock(&id->mnt->icache_lock);
    list_add(&id->cache_node, &id->mnt->inode_cache);
    mutex_unlock(&id->mnt->icache_lock);
}

static int ext2_write_inode(struct ext2_mount *mnt, ino_t ino,
                            struct ext2_inode *inode) {
    uint32_t isz = mnt->sb->s_inode_size ? mnt->sb->s_inode_size : 128,
             group = (ino - 1) / mnt->inodes_per_group,
             idx = (ino - 1) % mnt->inodes_per_group;
    uint32_t boff = (idx * isz) / mnt->block_size,
             ioff = (idx * isz) % mnt->block_size;

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

static int ext2_write_gd(struct ext2_mount *mnt, uint32_t bg) {
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

static int ext2_alloc_block(struct ext2_mount *mnt, uint32_t *out) {
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

static int ext2_alloc_inode(struct ext2_mount *mnt, ino_t *out) {
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

static ssize_t ext2_vnode_write(struct vnode *vn, const void *buf, size_t len,
                                off_t offset) {
    struct ext2_inode_data *id = vn->fs_data;
    struct ext2_mount *mnt = id->mnt;
    size_t written = 0;

    while (written < len) {
        uint32_t bidx = (offset + written) / mnt->block_size,
                 boff = (offset + written) % mnt->block_size, bnum;
        size_t nr = MIN(len - written, mnt->block_size - boff);

        if (ext2_get_block(mnt, id, bidx, &bnum, 1) < 0)
            break;

        uint32_t blk_off = 0;
        struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
        if (!bp)
            break;
        memcpy(bp->data + blk_off + boff, (const uint8_t *)buf + written, nr);
        bwrite(bp);
        brelse(bp);
        written += nr;
    }

    if (offset + written > id->inode.i_size) {
        id->inode.i_size = offset + written;
        vn->size = id->inode.i_size;
        ext2_write_inode(mnt, id->ino, &id->inode);
    }
    vfs_poll_wake(vn, POLLIN | POLLOUT);
    return written;
}

static struct file_ops ext2_file_ops = {
    .read = ext2_vnode_read,
    .write = ext2_vnode_write,
    .close = ext2_vnode_close,
    .readdir = ext2_vnode_readdir,
    .poll = ext2_vnode_poll,
};

static struct vnode *ext2_create_vnode(struct ext2_mount *mnt, ino_t ino) {
    struct vnode *cached = ext2_cache_get(mnt, ino);
    if (cached)
        return cached;

    struct ext2_inode_data *id = kmalloc(sizeof(*id));
    struct vnode *vn = kmalloc(sizeof(*vn));
    if (!id || !vn || ext2_read_inode(mnt, ino, &id->inode) < 0) {
        kfree(id);
        kfree(vn);
        return NULL;
    }
    id->ino = ino;
    id->mnt = mnt;
    uint32_t fmt = id->inode.i_mode & 0xF000;
    vn->type = (fmt == EXT2_S_IFDIR)   ? VNODE_DIR
               : (fmt == EXT2_S_IFLNK) ? VNODE_SYMLINK
                                       : VNODE_FILE;
    vn->mode = id->inode.i_mode;
    vn->uid = id->inode.i_uid;
    vn->gid = id->inode.i_gid;
    vn->size = id->inode.i_size;
    vn->ino = ino;
    vn->ops = &ext2_file_ops;
    vn->fs_data = id;
    vn->mount = NULL;
    vn->refcount = 1;
    vn->parent = NULL;
    vn->name[0] = '\0';
    mutex_init(&vn->lock, "ext2_vnode");
    poll_wait_head_init(&vn->pollers);
    id->vn = vn;
    INIT_LIST_HEAD(&id->cache_node);
    ext2_cache_add(id);
    return vn;
}

static int ext2_vnode_poll(struct vnode *vn, uint32_t events) {
    if (!vn)
        return POLLNVAL;

    uint32_t revents = (vn->type == VNODE_DIR) ? POLLIN : (POLLIN | POLLOUT);
    return (int)(revents & events);
}

static struct vnode *ext2_lookup(struct vnode *dir, const char *name) {
    struct ext2_inode_data *id = dir->fs_data;
    off_t off = 0;
    struct dirent de;
    while (ext2_vnode_readdir(dir, &de, &off) > 0) {
        if (strcmp(de.d_name, name) == 0) {
            struct vnode *vn = ext2_create_vnode(id->mnt, de.d_ino);
            if (vn)
                vn->mount = dir->mount;
            return vn;
        }
    }
    return NULL;
}

static int ext2_add_dirent(struct ext2_mount *mnt, ino_t dino, const char *name,
                           ino_t ino, uint8_t type) {
    struct ext2_inode_data di;
    di.mnt = mnt;
    di.ino = dino;
    if (ext2_read_inode(mnt, dino, &di.inode) < 0)
        return -EIO;
    size_t nlen = strlen(name), rlen = ALIGN_UP(8 + nlen, 4);

    uint32_t blocks = (di.inode.i_size + mnt->block_size - 1) / mnt->block_size;
    for (uint32_t i = 0; i < blocks; i++) {
        uint32_t bnum;
        if (ext2_get_block(mnt, &di, i, &bnum, 0) < 0 || bnum == 0)
            continue;
        uint32_t blk_off = 0;
        struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
        if (!bp)
            continue;

        for (uint32_t off = 0; off < mnt->block_size;) {
            struct ext2_dirent *de =
                (struct ext2_dirent *)(bp->data + blk_off + off);
            if (de->rec_len == 0) // Corruption check
                break;
            size_t alen = ALIGN_UP(8 + de->name_len, 4);
            if (de->rec_len - alen >= rlen) {
                struct ext2_dirent *new_de =
                    (struct ext2_dirent *)(bp->data + blk_off + off + alen);
                new_de->inode = ino;
                new_de->rec_len = de->rec_len - alen;
                new_de->name_len = nlen;
                new_de->file_type = type;
                memcpy(new_de->name, name, nlen);
                de->rec_len = alen;
                bwrite(bp);
                brelse(bp);
                return 0;
            }
            off += de->rec_len;
        }
        brelse(bp);
    }

    // No space found, append a new block
    uint32_t nb;
    // Use the new block index (current total blocks)
    // ext2_get_block with create=1 will handle allocation and linkage
    if (ext2_get_block(mnt, &di, blocks, &nb, 1) < 0)
        return -ENOSPC;
    
    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(mnt, nb, &blk_off);
    if (!bp)
        return -EIO;
    
    // Ensure the new directory block is zeroed before initializing.
    memset(bp->data + blk_off, 0, mnt->block_size);
    struct ext2_dirent *de = (struct ext2_dirent *)(bp->data + blk_off);
    de->inode = ino;
    de->rec_len = mnt->block_size;
    de->name_len = nlen;
    de->file_type = type;
    memcpy(de->name, name, nlen);
    bwrite(bp);
    brelse(bp);

    di.inode.i_size += mnt->block_size;
    ext2_write_inode(mnt, dino, &di.inode);
    return 0;
}

static int ext2_create(struct vnode *dir, const char *name, mode_t mode) {
    struct ext2_inode_data *did = dir->fs_data;
    ino_t nino;
    if (ext2_alloc_inode(did->mnt, &nino) < 0)
        return -ENOSPC;
    struct ext2_inode ni;
    memset(&ni, 0, sizeof(ni));
    ni.i_mode = (mode & 0xFFF) | EXT2_S_IFREG;
    ni.i_links_count = 1;
    ext2_write_inode(did->mnt, nino, &ni);
    if (ext2_add_dirent(did->mnt, did->ino, name, nino, EXT2_FT_REG_FILE) < 0)
        return -EIO;
    did->inode.i_links_count++;
    ext2_write_inode(did->mnt, did->ino, &did->inode);
    return 0;
}

static int ext2_symlink(struct vnode *dir, const char *name,
                        const char *target) {
    struct ext2_inode_data *did = dir->fs_data;
    if (!target)
        return -EINVAL;
    size_t tlen = strlen(target);
    ino_t nino;
    if (ext2_alloc_inode(did->mnt, &nino) < 0)
        return -ENOSPC;
    struct ext2_inode ni;
    memset(&ni, 0, sizeof(ni));
    ni.i_mode = 0777 | EXT2_S_IFLNK;
    ni.i_links_count = 1;
    ni.i_size = tlen;
    ext2_write_inode(did->mnt, nino, &ni);
    if (ext2_add_dirent(did->mnt, did->ino, name, nino, EXT2_FT_SYMLINK) < 0)
        return -EIO;

    struct vnode *vn = ext2_create_vnode(did->mnt, nino);
    if (!vn)
        return -EIO;
    ssize_t wr = ext2_vnode_write(vn, target, tlen, 0);
    vnode_put(vn);
    if (wr < 0 || (size_t)wr != tlen)
        return -EIO;

    did->inode.i_links_count++;
    ext2_write_inode(did->mnt, did->ino, &did->inode);
    return 0;
}

static int ext2_mkdir(struct vnode *dir, const char *name, mode_t mode) {
    struct ext2_inode_data *did = dir->fs_data;
    ino_t nino;
    uint32_t db;
    if (ext2_alloc_inode(did->mnt, &nino) < 0 ||
        ext2_alloc_block(did->mnt, &db) < 0)
        return -ENOSPC;
    struct ext2_inode ni;
    memset(&ni, 0, sizeof(ni));
    ni.i_mode = (mode & 0xFFF) | EXT2_S_IFDIR;
    ni.i_size = did->mnt->block_size;
    ni.i_links_count = 2;
    ni.i_block[0] = db;
    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(did->mnt, db, &blk_off);
    if (!bp)
        return -EIO;
    memset(bp->data + blk_off, 0, did->mnt->block_size);
    struct ext2_dirent *de =
        (struct ext2_dirent *)(bp->data + blk_off);
    de->inode = nino;
    de->rec_len = 12;
    de->name_len = 1;
    de->file_type = EXT2_FT_DIR;
    de->name[0] = '.';
    de = (struct ext2_dirent *)(bp->data + blk_off + 12);
    de->inode = did->ino;
    de->rec_len = did->mnt->block_size - 12;
    de->name_len = 2;
    de->file_type = EXT2_FT_DIR;
    de->name[0] = '.';
    de->name[1] = '.';
    bwrite(bp);
    brelse(bp);
    ext2_write_inode(did->mnt, nino, &ni);
    ext2_add_dirent(did->mnt, did->ino, name, nino, EXT2_FT_DIR);
    did->inode.i_links_count++;
    ext2_write_inode(did->mnt, did->ino, &did->inode);
    return 0;
}

static int ext2_mount(struct mount *mnt) {
    struct ext2_mount *e = kzalloc(sizeof(*e));
    if (!e)
        return -ENOMEM;
    e->dev = mnt->dev;
    mutex_init(&e->lock, "ext2_mount");
    mutex_init(&e->icache_lock, "ext2_icache");
    INIT_LIST_HEAD(&e->inode_cache);
    e->s_last_alloc_group_blk = 0;
    e->s_last_alloc_group_ino = 0;

    struct buf *bp =
        bread(mnt->dev, 0); /* Read first 4K, superblock is at 1024 */
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

static int ext2_unmount(struct mount *mnt) {
    struct ext2_mount *e = mnt->fs_data;
    if (e) {
        kfree(e->gdt);
        kfree(e->sb);
        kfree(e);
    }
    return 0;
}

static struct vfs_ops ext2_ops = {.name = "ext2",
                                  .mount = ext2_mount,
                                  .unmount = ext2_unmount,
                                  .lookup = ext2_lookup,
                                  .create = ext2_create,
                                  .mkdir = ext2_mkdir,
                                  .symlink = ext2_symlink};
static struct fs_type ext2_type = {.name = "ext2", .ops = &ext2_ops};
void ext2_init(void) {
    vfs_register_fs(&ext2_type);
}
