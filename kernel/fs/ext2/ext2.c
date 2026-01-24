/**
 * ext2.c - ext2 File System Implementation
 *
 * Basic ext2 filesystem driver for Kairos.
 * Supports: reading files, directories, basic file operations.
 *
 * Note: This is a simplified implementation for Phase 5.
 * Full ext2 support (journaling, extended attributes, etc.) can be added later.
 */

#include <kairos/vfs.h>
#include <kairos/blkdev.h>
#include <kairos/printk.h>
#include <kairos/mm.h>
#include <kairos/types.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>

/*
 * ext2 on-disk structures
 */

#define EXT2_SUPER_MAGIC        0xEF53
#define EXT2_ROOT_INO           2
#define EXT2_NAME_LEN           255

/* File types */
#define EXT2_FT_UNKNOWN         0
#define EXT2_FT_REG_FILE        1
#define EXT2_FT_DIR             2
#define EXT2_FT_CHRDEV          3
#define EXT2_FT_BLKDEV          4
#define EXT2_FT_FIFO            5
#define EXT2_FT_SOCK            6
#define EXT2_FT_SYMLINK         7

/* Inode modes */
#define EXT2_S_IFREG            0x8000
#define EXT2_S_IFDIR            0x4000
#define EXT2_S_IFLNK            0xA000

/* Superblock */
struct ext2_superblock {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    /* Extended fields */
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t  s_uuid[16];
    char     s_volume_name[16];
    char     s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;
    /* Performance hints */
    uint8_t  s_prealloc_blocks;
    uint8_t  s_prealloc_dir_blocks;
    uint16_t s_padding1;
    /* Reserved */
    uint32_t s_reserved[204];
} __packed;

/* Block group descriptor */
struct ext2_group_desc {
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint32_t bg_reserved[3];
} __packed;

/* Inode structure */
struct ext2_inode {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];           /* 12 direct, 1 indirect, 1 double, 1 triple */
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;
    uint32_t i_faddr;
    uint8_t  i_osd2[12];
} __packed;

/* Directory entry */
struct ext2_dirent {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t  name_len;
    uint8_t  file_type;
    char     name[EXT2_NAME_LEN];
} __packed;

/*
 * In-memory structures
 */

/* ext2 mount data */
struct ext2_mount {
    struct blkdev *dev;
    struct ext2_superblock *sb;
    struct ext2_group_desc *gdt;    /* Group descriptor table */
    uint32_t block_size;
    uint32_t groups_count;
    uint32_t inodes_per_group;
    uint32_t blocks_per_group;
    spinlock_t lock;
};

/* ext2 inode data */
struct ext2_inode_data {
    ino_t ino;
    struct ext2_inode inode;
    struct ext2_mount *mnt;
};

/**
 * ext2_read_block - Read a block from disk
 */
static int ext2_read_block(struct ext2_mount *mnt, uint32_t block, void *buf)
{
    uint64_t lba = (uint64_t)block * (mnt->block_size / mnt->dev->sector_size);
    size_t sectors = mnt->block_size / mnt->dev->sector_size;
    return blkdev_read(mnt->dev, lba, buf, sectors);
}

/**
 * ext2_write_block - Write a block to disk
 */
static int ext2_write_block(struct ext2_mount *mnt, uint32_t block, const void *buf)
{
    uint64_t lba = (uint64_t)block * (mnt->block_size / mnt->dev->sector_size);
    size_t sectors = mnt->block_size / mnt->dev->sector_size;
    return blkdev_write(mnt->dev, lba, buf, sectors);
}

/**
 * ext2_read_inode - Read an inode from disk
 */
static int ext2_read_inode(struct ext2_mount *mnt, ino_t ino, struct ext2_inode *inode)
{
    if (ino == 0 || ino > mnt->sb->s_inodes_count) {
        return -EINVAL;
    }

    /* Calculate block group and index */
    uint32_t group = (ino - 1) / mnt->inodes_per_group;
    uint32_t index = (ino - 1) % mnt->inodes_per_group;

    if (group >= mnt->groups_count) {
        return -EINVAL;
    }

    /* Get inode table block */
    uint32_t inode_table = mnt->gdt[group].bg_inode_table;
    uint32_t inode_size = mnt->sb->s_inode_size ? mnt->sb->s_inode_size : 128;
    uint32_t inodes_per_block = mnt->block_size / inode_size;
    uint32_t block = inode_table + (index / inodes_per_block);
    uint32_t offset = (index % inodes_per_block) * inode_size;

    /* Read block */
    void *buf = kmalloc(mnt->block_size);
    if (!buf) {
        return -ENOMEM;
    }

    int ret = ext2_read_block(mnt, block, buf);
    if (ret < 0) {
        kfree(buf);
        return ret;
    }

    /* Copy inode */
    memcpy(inode, (char *)buf + offset, sizeof(*inode));
    kfree(buf);

    return 0;
}

/**
 * ext2_get_block - Get block number for file offset
 */
static int ext2_get_block(struct ext2_mount *mnt, struct ext2_inode *inode,
                          uint32_t block_idx, uint32_t *block_out)
{
    /* Direct blocks */
    if (block_idx < 12) {
        *block_out = inode->i_block[block_idx];
        return 0;
    }

    /* Indirect block */
    uint32_t ptrs_per_block = mnt->block_size / 4;
    block_idx -= 12;

    if (block_idx < ptrs_per_block) {
        uint32_t *indirect = kmalloc(mnt->block_size);
        if (!indirect) {
            return -ENOMEM;
        }

        int ret = ext2_read_block(mnt, inode->i_block[12], indirect);
        if (ret < 0) {
            kfree(indirect);
            return ret;
        }

        *block_out = indirect[block_idx];
        kfree(indirect);
        return 0;
    }

    /* Double indirect - not implemented yet */
    pr_warn("ext2: double indirect blocks not yet supported\n");
    return -ENOSYS;
}

/**
 * ext2_vnode_read - Read from a file
 */
static ssize_t ext2_vnode_read(struct vnode *vn, void *buf, size_t len, off_t offset)
{
    struct ext2_inode_data *idata = vn->fs_data;
    struct ext2_mount *mnt = idata->mnt;
    size_t total_read = 0;

    if (offset >= (off_t)idata->inode.i_size) {
        return 0;
    }

    if (offset + (off_t)len > (off_t)idata->inode.i_size) {
        len = idata->inode.i_size - offset;
    }

    void *block_buf = kmalloc(mnt->block_size);
    if (!block_buf) {
        return -ENOMEM;
    }

    while (len > 0) {
        uint32_t block_idx = offset / mnt->block_size;
        uint32_t block_off = offset % mnt->block_size;
        uint32_t to_read = mnt->block_size - block_off;
        if (to_read > len) {
            to_read = len;
        }

        uint32_t block;
        int ret = ext2_get_block(mnt, &idata->inode, block_idx, &block);
        if (ret < 0) {
            kfree(block_buf);
            return ret;
        }

        if (block == 0) {
            /* Sparse file - return zeros */
            for (uint32_t i = 0; i < to_read; i++) {
                ((char *)buf)[total_read + i] = 0;
            }
        } else {
            ret = ext2_read_block(mnt, block, block_buf);
            if (ret < 0) {
                kfree(block_buf);
                return ret;
            }

            memcpy((char *)buf + total_read, (char *)block_buf + block_off, to_read);
        }

        total_read += to_read;
        offset += to_read;
        len -= to_read;
    }

    kfree(block_buf);
    return total_read;
}

/**
 * ext2_vnode_readdir - Read directory entries
 */
static int ext2_vnode_readdir(struct vnode *vn, struct dirent *ent, off_t *offset)
{
    struct ext2_inode_data *idata = vn->fs_data;
    struct ext2_mount *mnt = idata->mnt;

    if (*offset >= (off_t)idata->inode.i_size) {
        return 0;  /* End of directory */
    }

    /* Read directory block */
    uint32_t block_idx = *offset / mnt->block_size;
    uint32_t block_off = *offset % mnt->block_size;

    uint32_t block;
    int ret = ext2_get_block(mnt, &idata->inode, block_idx, &block);
    if (ret < 0) {
        return ret;
    }

    void *block_buf = kmalloc(mnt->block_size);
    if (!block_buf) {
        return -ENOMEM;
    }

    ret = ext2_read_block(mnt, block, block_buf);
    if (ret < 0) {
        kfree(block_buf);
        return ret;
    }

    /* Parse directory entry */
    struct ext2_dirent *de = (struct ext2_dirent *)((char *)block_buf + block_off);

    if (de->inode == 0 || de->rec_len == 0) {
        kfree(block_buf);
        return 0;  /* End of directory */
    }

    /* Fill VFS dirent */
    ent->d_ino = de->inode;
    ent->d_off = *offset;
    ent->d_reclen = sizeof(*ent);

    switch (de->file_type) {
    case EXT2_FT_REG_FILE:  ent->d_type = DT_REG; break;
    case EXT2_FT_DIR:       ent->d_type = DT_DIR; break;
    case EXT2_FT_SYMLINK:   ent->d_type = DT_LNK; break;
    case EXT2_FT_CHRDEV:    ent->d_type = DT_CHR; break;
    case EXT2_FT_BLKDEV:    ent->d_type = DT_BLK; break;
    case EXT2_FT_FIFO:      ent->d_type = DT_FIFO; break;
    case EXT2_FT_SOCK:      ent->d_type = DT_SOCK; break;
    default:                ent->d_type = DT_UNKNOWN; break;
    }

    size_t name_len = de->name_len < CONFIG_NAME_MAX - 1 ? de->name_len : CONFIG_NAME_MAX - 1;
    strncpy(ent->d_name, de->name, name_len);
    ent->d_name[name_len] = '\0';

    *offset += de->rec_len;
    kfree(block_buf);

    return 1;  /* Success */
}

/**
 * ext2_vnode_close - Close a vnode
 */
static int ext2_vnode_close(struct vnode *vn)
{
    struct ext2_inode_data *idata = vn->fs_data;
    if (idata) {
        kfree(idata);
    }
    kfree(vn);
    return 0;
}

/**
 * ext2_write_inode - Write inode back to disk
 */
static int ext2_write_inode(struct ext2_mount *mnt, ino_t ino, struct ext2_inode *inode)
{
    uint32_t inode_size = mnt->sb->s_inode_size;
    uint32_t block_group = (ino - 1) / mnt->inodes_per_group;
    uint32_t index = (ino - 1) % mnt->inodes_per_group;
    uint32_t block_offset = (index * inode_size) / mnt->block_size;
    uint32_t offset_in_block = (index * inode_size) % mnt->block_size;

    /* Read the block containing this inode */
    uint8_t *block_buf = kmalloc(mnt->block_size);
    if (!block_buf) {
        return -ENOMEM;
    }

    struct ext2_group_desc *gd = &mnt->gdt[block_group];
    uint32_t inode_table_block = gd->bg_inode_table + block_offset;

    int ret = ext2_read_block(mnt, inode_table_block, block_buf);
    if (ret < 0) {
        kfree(block_buf);
        return ret;
    }

    /* Copy inode data */
    memcpy(block_buf + offset_in_block, inode, inode_size);

    /* Write block back */
    ret = ext2_write_block(mnt, inode_table_block, block_buf);
    kfree(block_buf);

    return ret;
}

/**
 * ext2_write_group_desc - Write group descriptor to disk
 * @mnt: ext2 mount structure
 * @bg: block group number
 *
 * Must be called with mnt->lock held.
 */
static int ext2_write_group_desc(struct ext2_mount *mnt, uint32_t bg)
{
    uint32_t gd_block = 2 + (bg * sizeof(struct ext2_group_desc)) / mnt->block_size;
    uint32_t gd_offset = (bg * sizeof(struct ext2_group_desc)) % mnt->block_size;

    uint8_t *gd_buf = kmalloc(mnt->block_size);
    if (!gd_buf) {
        return -ENOMEM;
    }

    int ret = ext2_read_block(mnt, gd_block, gd_buf);
    if (ret < 0) {
        kfree(gd_buf);
        return ret;
    }

    memcpy(gd_buf + gd_offset, &mnt->gdt[bg], sizeof(struct ext2_group_desc));

    ret = ext2_write_block(mnt, gd_block, gd_buf);
    kfree(gd_buf);

    return ret;
}

/**
 * ext2_alloc_block - Allocate a new block
 */
static int ext2_alloc_block(struct ext2_mount *mnt, uint32_t *block_out)
{
    spin_lock(&mnt->lock);

    /* Search each block group for a free block */
    for (uint32_t bg = 0; bg < mnt->groups_count; bg++) {
        struct ext2_group_desc *gd = &mnt->gdt[bg];

        if (gd->bg_free_blocks_count == 0) {
            continue;
        }

        /* Read block bitmap */
        uint8_t *bitmap = kmalloc(mnt->block_size);
        if (!bitmap) {
            spin_unlock(&mnt->lock);
            return -ENOMEM;
        }

        int ret = ext2_read_block(mnt, gd->bg_block_bitmap, bitmap);
        if (ret < 0) {
            kfree(bitmap);
            spin_unlock(&mnt->lock);
            return ret;
        }

        /* Find first free block in bitmap */
        for (uint32_t i = 0; i < mnt->blocks_per_group; i++) {
            if (!(bitmap[i / 8] & (1 << (i % 8)))) {
                /* Found free block - mark as used */
                bitmap[i / 8] |= (1 << (i % 8));

                ret = ext2_write_block(mnt, gd->bg_block_bitmap, bitmap);
                kfree(bitmap);
                if (ret < 0) {
                    spin_unlock(&mnt->lock);
                    return ret;
                }

                gd->bg_free_blocks_count--;
                ret = ext2_write_group_desc(mnt, bg);
                if (ret < 0) {
                    spin_unlock(&mnt->lock);
                    return ret;
                }

                mnt->sb->s_free_blocks_count--;
                *block_out = bg * mnt->blocks_per_group + i;
                spin_unlock(&mnt->lock);
                return 0;
            }
        }

        kfree(bitmap);
    }

    spin_unlock(&mnt->lock);
    return -ENOSPC;
}

/**
 * ext2_free_block - Free an allocated block
 */
static int ext2_free_block(struct ext2_mount *mnt, uint32_t block)
{
    uint32_t bg = block / mnt->blocks_per_group;
    uint32_t index = block % mnt->blocks_per_group;

    if (bg >= mnt->groups_count) {
        return -EINVAL;
    }

    spin_lock(&mnt->lock);

    struct ext2_group_desc *gd = &mnt->gdt[bg];

    /* Read block bitmap */
    uint8_t *bitmap = kmalloc(mnt->block_size);
    if (!bitmap) {
        spin_unlock(&mnt->lock);
        return -ENOMEM;
    }

    int ret = ext2_read_block(mnt, gd->bg_block_bitmap, bitmap);
    if (ret < 0) {
        kfree(bitmap);
        spin_unlock(&mnt->lock);
        return ret;
    }

    /* Check if already free */
    if (!(bitmap[index / 8] & (1 << (index % 8)))) {
        kfree(bitmap);
        spin_unlock(&mnt->lock);
        return -EINVAL;
    }

    /* Clear bit and write back */
    bitmap[index / 8] &= ~(1 << (index % 8));
    ret = ext2_write_block(mnt, gd->bg_block_bitmap, bitmap);
    kfree(bitmap);
    if (ret < 0) {
        spin_unlock(&mnt->lock);
        return ret;
    }

    gd->bg_free_blocks_count++;
    ret = ext2_write_group_desc(mnt, bg);
    if (ret < 0) {
        spin_unlock(&mnt->lock);
        return ret;
    }

    mnt->sb->s_free_blocks_count++;
    spin_unlock(&mnt->lock);
    return 0;
}

/**
 * ext2_alloc_inode - Allocate a new inode
 */
static int ext2_alloc_inode(struct ext2_mount *mnt, ino_t *ino_out)
{
    spin_lock(&mnt->lock);

    /* Search each block group for a free inode */
    for (uint32_t bg = 0; bg < mnt->groups_count; bg++) {
        struct ext2_group_desc *gd = &mnt->gdt[bg];

        if (gd->bg_free_inodes_count == 0) {
            continue;
        }

        /* Read inode bitmap */
        uint8_t *bitmap = kmalloc(mnt->block_size);
        if (!bitmap) {
            spin_unlock(&mnt->lock);
            return -ENOMEM;
        }

        int ret = ext2_read_block(mnt, gd->bg_inode_bitmap, bitmap);
        if (ret < 0) {
            kfree(bitmap);
            spin_unlock(&mnt->lock);
            return ret;
        }

        /* Find first free inode in bitmap */
        for (uint32_t i = 0; i < mnt->inodes_per_group; i++) {
            if (!(bitmap[i / 8] & (1 << (i % 8)))) {
                /* Found free inode - mark as used */
                bitmap[i / 8] |= (1 << (i % 8));

                ret = ext2_write_block(mnt, gd->bg_inode_bitmap, bitmap);
                kfree(bitmap);
                if (ret < 0) {
                    spin_unlock(&mnt->lock);
                    return ret;
                }

                gd->bg_free_inodes_count--;
                ret = ext2_write_group_desc(mnt, bg);
                if (ret < 0) {
                    spin_unlock(&mnt->lock);
                    return ret;
                }

                mnt->sb->s_free_inodes_count--;
                *ino_out = bg * mnt->inodes_per_group + i + 1;
                spin_unlock(&mnt->lock);
                return 0;
            }
        }

        kfree(bitmap);
    }

    spin_unlock(&mnt->lock);
    return -ENOSPC;
}

/**
 * ext2_free_inode - Free an allocated inode
 */
static int ext2_free_inode(struct ext2_mount *mnt, ino_t ino)
{
    if (ino < 1) {
        return -EINVAL;
    }

    uint32_t bg = (ino - 1) / mnt->inodes_per_group;
    uint32_t index = (ino - 1) % mnt->inodes_per_group;

    if (bg >= mnt->groups_count) {
        return -EINVAL;
    }

    spin_lock(&mnt->lock);

    struct ext2_group_desc *gd = &mnt->gdt[bg];

    /* Read inode bitmap */
    uint8_t *bitmap = kmalloc(mnt->block_size);
    if (!bitmap) {
        spin_unlock(&mnt->lock);
        return -ENOMEM;
    }

    int ret = ext2_read_block(mnt, gd->bg_inode_bitmap, bitmap);
    if (ret < 0) {
        kfree(bitmap);
        spin_unlock(&mnt->lock);
        return ret;
    }

    /* Check if already free */
    if (!(bitmap[index / 8] & (1 << (index % 8)))) {
        kfree(bitmap);
        spin_unlock(&mnt->lock);
        return -EINVAL;
    }

    /* Clear bit and write back */
    bitmap[index / 8] &= ~(1 << (index % 8));
    ret = ext2_write_block(mnt, gd->bg_inode_bitmap, bitmap);
    kfree(bitmap);
    if (ret < 0) {
        spin_unlock(&mnt->lock);
        return ret;
    }

    gd->bg_free_inodes_count++;
    ret = ext2_write_group_desc(mnt, bg);
    if (ret < 0) {
        spin_unlock(&mnt->lock);
        return ret;
    }

    mnt->sb->s_free_inodes_count++;
    spin_unlock(&mnt->lock);
    return 0;
}

/**
 * ext2_vnode_write - Write to a file
 */
static ssize_t ext2_vnode_write(struct vnode *vn, const void *buf, size_t len, off_t offset)
{
    struct ext2_inode_data *idata = vn->fs_data;
    struct ext2_mount *mnt = idata->mnt;
    struct ext2_inode *inode = &idata->inode;
    size_t written = 0;

    if (offset < 0) {
        return -EINVAL;
    }

    while (written < len) {
        uint32_t block_idx = (offset + written) / mnt->block_size;
        uint32_t block_offset = (offset + written) % mnt->block_size;
        size_t to_write = MIN(len - written, mnt->block_size - block_offset);

        /* Get or allocate block */
        uint32_t block_num;
        int ret = ext2_get_block(mnt, inode, block_idx, &block_num);
        if (ret < 0) {
            return written > 0 ? written : ret;
        }

        if (block_num == 0) {
            /* Need to allocate new block */
            ret = ext2_alloc_block(mnt, &block_num);
            if (ret < 0) {
                return written > 0 ? written : ret;
            }

            /* Update inode block pointers */
            if (block_idx < 12) {
                inode->i_block[block_idx] = block_num;
            } else {
                /* TODO: Handle indirect blocks for allocation */
                return written > 0 ? written : -ENOSPC;
            }
        }

        /* Read existing block if not writing full block */
        uint8_t *block_buf = kmalloc(mnt->block_size);
        if (!block_buf) {
            return written > 0 ? written : -ENOMEM;
        }

        if (to_write < mnt->block_size || block_offset > 0) {
            ret = ext2_read_block(mnt, block_num, block_buf);
            if (ret < 0 && written == 0) {
                kfree(block_buf);
                return ret;
            }
        }

        /* Copy data */
        memcpy(block_buf + block_offset, (const uint8_t *)buf + written, to_write);

        /* Write block back */
        ret = ext2_write_block(mnt, block_num, block_buf);
        kfree(block_buf);

        if (ret < 0) {
            return written > 0 ? written : ret;
        }

        written += to_write;
    }

    /* Update inode size if necessary */
    if (offset + written > inode->i_size) {
        inode->i_size = offset + written;
        vn->size = inode->i_size;

        /* Write inode back */
        ext2_write_inode(mnt, idata->ino, inode);
    }

    return written;
}

static struct file_ops ext2_file_ops = {
    .read = ext2_vnode_read,
    .write = ext2_vnode_write,
    .close = ext2_vnode_close,
    .readdir = ext2_vnode_readdir,
};

/**
 * ext2_create_vnode - Create a vnode from an inode
 */
static struct vnode *ext2_create_vnode(struct ext2_mount *mnt, ino_t ino)
{
    struct ext2_inode_data *idata;
    struct vnode *vn;
    int ret;

    idata = kmalloc(sizeof(*idata));
    if (!idata) {
        return NULL;
    }

    ret = ext2_read_inode(mnt, ino, &idata->inode);
    if (ret < 0) {
        kfree(idata);
        return NULL;
    }

    idata->ino = ino;
    idata->mnt = mnt;

    vn = kmalloc(sizeof(*vn));
    if (!vn) {
        kfree(idata);
        return NULL;
    }

    /* Determine vnode type */
    if ((idata->inode.i_mode & 0xF000) == EXT2_S_IFDIR) {
        vn->type = VNODE_DIR;
    } else if ((idata->inode.i_mode & 0xF000) == EXT2_S_IFREG) {
        vn->type = VNODE_FILE;
    } else if ((idata->inode.i_mode & 0xF000) == EXT2_S_IFLNK) {
        vn->type = VNODE_SYMLINK;
    } else {
        vn->type = VNODE_FILE;
    }

    vn->mode = idata->inode.i_mode;
    vn->uid = idata->inode.i_uid;
    vn->gid = idata->inode.i_gid;
    vn->size = idata->inode.i_size;
    vn->ino = ino;
    vn->ops = &ext2_file_ops;
    vn->fs_data = idata;
    vn->mount = NULL;  /* Set by caller */
    vn->refcount = 1;
    vn->lock = (spinlock_t)SPINLOCK_INIT;

    return vn;
}

/**
 * ext2_lookup - Look up a file in a directory
 */
static struct vnode *ext2_lookup(struct vnode *dir, const char *name)
{
    struct ext2_inode_data *idata = dir->fs_data;
    struct ext2_mount *mnt = idata->mnt;
    off_t offset = 0;
    size_t name_len = strlen(name);

    /* Read directory entries */
    while (offset < (off_t)idata->inode.i_size) {
        uint32_t block_idx = offset / mnt->block_size;
        uint32_t block_off = offset % mnt->block_size;

        uint32_t block;
        int ret = ext2_get_block(mnt, &idata->inode, block_idx, &block);
        if (ret < 0) {
            return NULL;
        }

        void *block_buf = kmalloc(mnt->block_size);
        if (!block_buf) {
            return NULL;
        }

        ret = ext2_read_block(mnt, block, block_buf);
        if (ret < 0) {
            kfree(block_buf);
            return NULL;
        }

        struct ext2_dirent *de = (struct ext2_dirent *)((char *)block_buf + block_off);

        if (de->inode != 0 && de->name_len == name_len &&
            strncmp(de->name, name, name_len) == 0) {
            /* Found */
            ino_t ino = de->inode;
            kfree(block_buf);

            struct vnode *vn = ext2_create_vnode(mnt, ino);
            if (vn) {
                vn->mount = dir->mount;
            }
            return vn;
        }

        offset += de->rec_len;
        kfree(block_buf);

        if (de->rec_len == 0) {
            break;
        }
    }

    return NULL;  /* Not found */
}

/**
 * ext2_add_dirent - Add directory entry to a directory
 */
static int ext2_add_dirent(struct ext2_mount *mnt, ino_t dir_ino,
                          const char *name, ino_t ino, uint8_t file_type)
{
    struct ext2_inode dir_inode;
    int ret = ext2_read_inode(mnt, dir_ino, &dir_inode);
    if (ret < 0) {
        return ret;
    }

    size_t name_len = strlen(name);
    if (name_len > 255) {
        return -ENAMETOOLONG;
    }

    /* Calculate required entry size (aligned to 4 bytes) */
    size_t rec_len = ALIGN_UP(8 + name_len, 4);

    /* Search for space in existing directory blocks */
    uint32_t num_blocks = (dir_inode.i_size + mnt->block_size - 1) / mnt->block_size;

    for (uint32_t i = 0; i < num_blocks; i++) {
        uint32_t block_num;
        ret = ext2_get_block(mnt, &dir_inode, i, &block_num);
        if (ret < 0 || block_num == 0) {
            continue;
        }

        uint8_t *block_buf = kmalloc(mnt->block_size);
        if (!block_buf) {
            return -ENOMEM;
        }

        ret = ext2_read_block(mnt, block_num, block_buf);
        if (ret < 0) {
            kfree(block_buf);
            return ret;
        }

        /* Scan for free space */
        uint32_t offset = 0;
        while (offset < mnt->block_size) {
            struct ext2_dirent *de = (struct ext2_dirent *)(block_buf + offset);

            if (de->rec_len == 0) {
                break;  /* Invalid entry */
            }

            /* Calculate actual entry size */
            size_t actual_len = ALIGN_UP(8 + de->name_len, 4);
            size_t free_space = de->rec_len - actual_len;

            /* Check if we can fit the new entry here */
            if (free_space >= rec_len) {
                /* Shrink current entry */
                de->rec_len = actual_len;

                /* Add new entry */
                struct ext2_dirent *new_de = (struct ext2_dirent *)(block_buf + offset + actual_len);
                new_de->inode = ino;
                new_de->rec_len = free_space;
                new_de->name_len = name_len;
                new_de->file_type = file_type;
                memcpy(new_de->name, name, name_len);

                /* Write block back */
                ret = ext2_write_block(mnt, block_num, block_buf);
                kfree(block_buf);
                return ret;
            }

            offset += de->rec_len;
        }

        kfree(block_buf);
    }

    /* Need to allocate new block for directory */
    uint32_t new_block;
    ret = ext2_alloc_block(mnt, &new_block);
    if (ret < 0) {
        return ret;
    }

    /* Add block to directory inode */
    if (num_blocks < 12) {
        dir_inode.i_block[num_blocks] = new_block;
    } else {
        /* TODO: Handle indirect blocks */
        return -ENOSPC;
    }

    /* Create new directory entry in the new block */
    uint8_t *block_buf = kzalloc(mnt->block_size);
    if (!block_buf) {
        return -ENOMEM;
    }

    struct ext2_dirent *de = (struct ext2_dirent *)block_buf;
    de->inode = ino;
    de->rec_len = mnt->block_size;  /* Takes entire block */
    de->name_len = name_len;
    de->file_type = file_type;
    memcpy(de->name, name, name_len);

    ret = ext2_write_block(mnt, new_block, block_buf);
    kfree(block_buf);

    if (ret < 0) {
        return ret;
    }

    /* Update directory inode size */
    dir_inode.i_size += mnt->block_size;
    return ext2_write_inode(mnt, dir_ino, &dir_inode);
}

/**
 * ext2_create - Create a new file
 */
static int ext2_create(struct vnode *dir, const char *name, mode_t mode)
{
    if (!dir || dir->type != VNODE_DIR) {
        return -ENOTDIR;
    }

    struct ext2_inode_data *dir_idata = dir->fs_data;
    struct ext2_mount *mnt = dir_idata->mnt;

    /* Allocate new inode */
    ino_t new_ino;
    int ret = ext2_alloc_inode(mnt, &new_ino);
    if (ret < 0) {
        return ret;
    }

    /* Initialize inode */
    struct ext2_inode new_inode;
    for (size_t i = 0; i < sizeof(new_inode); i++) {
        ((uint8_t *)&new_inode)[i] = 0;
    }
    new_inode.i_mode = (mode & 0xFFF) | EXT2_S_IFREG;
    new_inode.i_uid = 0;  /* TODO: Use current process uid */
    new_inode.i_gid = 0;  /* TODO: Use current process gid */
    new_inode.i_size = 0;
    new_inode.i_links_count = 1;

    /* Write inode */
    ret = ext2_write_inode(mnt, new_ino, &new_inode);
    if (ret < 0) {
        return ret;
    }

    /* Add directory entry */
    ret = ext2_add_dirent(mnt, dir_idata->ino, name, new_ino, EXT2_FT_REG_FILE);
    if (ret < 0) {
        ext2_free_inode(mnt, new_ino);
        return ret;
    }

    /* Update directory link count */
    dir_idata->inode.i_links_count++;
    ext2_write_inode(mnt, dir_idata->ino, &dir_idata->inode);

    return 0;
}

/**
 * ext2_mkdir - Create a new directory
 */
static int ext2_mkdir(struct vnode *dir, const char *name, mode_t mode)
{
    if (!dir || dir->type != VNODE_DIR) {
        return -ENOTDIR;
    }

    struct ext2_inode_data *dir_idata = dir->fs_data;
    struct ext2_mount *mnt = dir_idata->mnt;

    /* Allocate new inode */
    ino_t new_ino;
    int ret = ext2_alloc_inode(mnt, &new_ino);
    if (ret < 0) {
        return ret;
    }

    /* Allocate block for directory entries */
    uint32_t dir_block;
    ret = ext2_alloc_block(mnt, &dir_block);
    if (ret < 0) {
        ext2_free_inode(mnt, new_ino);
        return ret;
    }

    /* Initialize inode */
    struct ext2_inode new_inode;
    for (size_t i = 0; i < sizeof(new_inode); i++) {
        ((uint8_t *)&new_inode)[i] = 0;
    }
    new_inode.i_mode = (mode & 0xFFF) | EXT2_S_IFDIR;
    new_inode.i_uid = 0;  /* TODO: Use current process uid */
    new_inode.i_gid = 0;  /* TODO: Use current process gid */
    new_inode.i_size = mnt->block_size;
    new_inode.i_links_count = 2;  /* . and parent */
    new_inode.i_block[0] = dir_block;

    /* Create . and .. entries */
    uint8_t *block_buf = kzalloc(mnt->block_size);
    if (!block_buf) {
        ext2_free_block(mnt, dir_block);
        ext2_free_inode(mnt, new_ino);
        return -ENOMEM;
    }

    /* . entry */
    struct ext2_dirent *de = (struct ext2_dirent *)block_buf;
    de->inode = new_ino;
    de->rec_len = 12;  /* 8 + strlen(".") + padding */
    de->name_len = 1;
    de->file_type = EXT2_FT_DIR;
    de->name[0] = '.';

    /* .. entry */
    de = (struct ext2_dirent *)(block_buf + 12);
    de->inode = dir_idata->ino;
    de->rec_len = mnt->block_size - 12;  /* Rest of block */
    de->name_len = 2;
    de->file_type = EXT2_FT_DIR;
    de->name[0] = '.';
    de->name[1] = '.';

    ret = ext2_write_block(mnt, dir_block, block_buf);
    kfree(block_buf);

    if (ret < 0) {
        ext2_free_block(mnt, dir_block);
        ext2_free_inode(mnt, new_ino);
        return ret;
    }

    /* Write inode */
    ret = ext2_write_inode(mnt, new_ino, &new_inode);
    if (ret < 0) {
        ext2_free_block(mnt, dir_block);
        ext2_free_inode(mnt, new_ino);
        return ret;
    }

    /* Add directory entry to parent */
    ret = ext2_add_dirent(mnt, dir_idata->ino, name, new_ino, EXT2_FT_DIR);
    if (ret < 0) {
        ext2_free_block(mnt, dir_block);
        ext2_free_inode(mnt, new_ino);
        return ret;
    }

    /* Update parent directory link count */
    dir_idata->inode.i_links_count++;
    ext2_write_inode(mnt, dir_idata->ino, &dir_idata->inode);

    return 0;
}

/**
 * ext2_mount - Mount an ext2 filesystem
 */
static int ext2_mount(struct mount *mnt)
{
    struct ext2_mount *ext2;
    struct ext2_superblock *sb;
    int ret;

    if (!mnt->dev) {
        pr_err("ext2: no block device specified\n");
        return -EINVAL;
    }

    ext2 = kzalloc(sizeof(*ext2));
    if (!ext2) {
        return -ENOMEM;
    }

    ext2->dev = mnt->dev;
    ext2->lock = (spinlock_t)SPINLOCK_INIT;

    /* Read superblock (located at offset 1024) */
    sb = kmalloc(sizeof(*sb));
    if (!sb) {
        kfree(ext2);
        return -ENOMEM;
    }

    /* Read sectors containing superblock */
    uint8_t *buf = kmalloc(4096);
    if (!buf) {
        kfree(sb);
        kfree(ext2);
        return -ENOMEM;
    }

    ret = blkdev_read(mnt->dev, 2, buf, 8);  /* Read 4KB starting at sector 2 (offset 1024) */
    if (ret < 0) {
        pr_err("ext2: failed to read superblock: %d\n", ret);
        kfree(buf);
        kfree(sb);
        kfree(ext2);
        return ret;
    }

    memcpy(sb, buf, sizeof(*sb));
    kfree(buf);

    /* Check magic */
    if (sb->s_magic != EXT2_SUPER_MAGIC) {
        pr_err("ext2: invalid magic: 0x%x\n", sb->s_magic);
        kfree(sb);
        kfree(ext2);
        return -EINVAL;
    }

    ext2->sb = sb;
    ext2->block_size = 1024 << sb->s_log_block_size;
    ext2->inodes_per_group = sb->s_inodes_per_group;
    ext2->blocks_per_group = sb->s_blocks_per_group;
    ext2->groups_count = (sb->s_blocks_count + sb->s_blocks_per_group - 1) / sb->s_blocks_per_group;

    pr_info("ext2: block_size=%u, inodes=%u, blocks=%u, groups=%u\n",
            ext2->block_size, sb->s_inodes_count, sb->s_blocks_count, ext2->groups_count);

    /* Read group descriptor table */
    size_t gdt_size = ext2->groups_count * sizeof(struct ext2_group_desc);
    ext2->gdt = kmalloc(gdt_size);
    if (!ext2->gdt) {
        kfree(sb);
        kfree(ext2);
        return -ENOMEM;
    }

    uint32_t gdt_block = sb->s_first_data_block + 1;
    void *gdt_buf = kmalloc(ext2->block_size);
    if (!gdt_buf) {
        kfree(ext2->gdt);
        kfree(sb);
        kfree(ext2);
        return -ENOMEM;
    }

    ret = ext2_read_block(ext2, gdt_block, gdt_buf);
    if (ret < 0) {
        pr_err("ext2: failed to read group descriptor table: %d\n", ret);
        kfree(gdt_buf);
        kfree(ext2->gdt);
        kfree(sb);
        kfree(ext2);
        return ret;
    }

    memcpy(ext2->gdt, gdt_buf, gdt_size);
    kfree(gdt_buf);

    /* Create root vnode */
    struct vnode *root = ext2_create_vnode(ext2, EXT2_ROOT_INO);
    if (!root) {
        pr_err("ext2: failed to read root inode\n");
        kfree(ext2->gdt);
        kfree(sb);
        kfree(ext2);
        return -EIO;
    }

    root->mount = mnt;
    mnt->root = root;
    mnt->fs_data = ext2;

    pr_info("ext2: mounted successfully\n");
    return 0;
}

/**
 * ext2_unmount - Unmount ext2 filesystem
 */
static int ext2_unmount(struct mount *mnt)
{
    struct ext2_mount *ext2 = mnt->fs_data;
    if (ext2) {
        if (ext2->gdt) kfree(ext2->gdt);
        if (ext2->sb) kfree(ext2->sb);
        kfree(ext2);
    }
    return 0;
}

/* ext2 VFS operations */
static struct vfs_ops ext2_vfs_ops = {
    .name = "ext2",
    .mount = ext2_mount,
    .unmount = ext2_unmount,
    .lookup = ext2_lookup,
    .create = ext2_create,
    .mkdir = ext2_mkdir,
    .unlink = NULL,     /* TODO */
    .rmdir = NULL,      /* TODO */
    .rename = NULL,     /* TODO */
    .symlink = NULL,    /* TODO */
    .readlink = NULL,   /* TODO */
    .sync = NULL,       /* TODO */
};

/* ext2 filesystem type */
static struct fs_type ext2_type = {
    .name = "ext2",
    .ops = &ext2_vfs_ops,
};

/**
 * ext2_init - Initialize ext2 filesystem
 */
void ext2_init(void)
{
    int ret = vfs_register_fs(&ext2_type);
    if (ret < 0) {
        pr_err("ext2: failed to register: %d\n", ret);
        return;
    }

    pr_info("ext2: filesystem driver initialized\n");
}
