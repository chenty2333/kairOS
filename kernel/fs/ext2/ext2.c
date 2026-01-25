/**
 * kernel/fs/ext2/ext2.c - ext2 File System Implementation
 */

#include <kairos/blkdev.h>
#include <kairos/buf.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

#define EXT2_SUPER_MAGIC 0xEF53
#define EXT2_ROOT_INO 2
#define EXT2_NAME_LEN 255

/* Inode modes */
#define EXT2_S_IFREG 0x8000
#define EXT2_S_IFDIR 0x4000
#define EXT2_S_IFLNK 0xA000

/* File types */
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR 2

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
    spinlock_t lock;
};

struct ext2_inode_data {
    ino_t ino;
    struct ext2_inode inode;
    struct ext2_mount *mnt;
};

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

    struct buf *bp = bread(mnt->dev, block);
    if (!bp)
        return -EIO;
    memcpy(inode, bp->data + off, sizeof(*inode));
    brelse(bp);
    return 0;
}

static int ext2_get_block(struct ext2_mount *mnt, struct ext2_inode *inode,
                          uint32_t idx, uint32_t *out) {
    if (idx < 12) {
        *out = inode->i_block[idx];
        return 0;
    }
    uint32_t ppb = mnt->block_size / 4;
    idx -= 12;
    if (idx >= ppb)
        return -ENOSYS;

    struct buf *bp = bread(mnt->dev, inode->i_block[12]);
    if (!bp)
        return -EIO;
    *out = ((uint32_t *)bp->data)[idx];
    brelse(bp);
    return 0;
}

static ssize_t ext2_vnode_read(struct vnode *vn, void *buf, size_t len,
                               off_t offset) {
    struct ext2_inode_data *id = vn->fs_data;
    struct ext2_mount *mnt = id->mnt;
    if (offset >= (off_t)id->inode.i_size)
        return 0;
    if (offset + len > id->inode.i_size)
        len = id->inode.i_size - offset;

    size_t total = 0;
    while (len > 0) {
        uint32_t bidx = offset / mnt->block_size,
                 boff = offset % mnt->block_size;
        uint32_t nr = MIN(len, mnt->block_size - boff), bnum;
        if (ext2_get_block(mnt, &id->inode, bidx, &bnum) < 0)
            break;

        if (bnum == 0)
            memset((char *)buf + total, 0, nr);
        else {
            struct buf *bp = bread(mnt->dev, bnum);
            if (!bp)
                break;
            memcpy((char *)buf + total, bp->data + boff, nr);
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
    if (ext2_get_block(mnt, &id->inode, bidx, &bnum) < 0 || bnum == 0)
        return 0;

    struct buf *bp = bread(mnt->dev, bnum);
    if (!bp)
        return -EIO;

    struct ext2_dirent *de = (struct ext2_dirent *)(bp->data + boff);
    if (de->inode == 0 || de->rec_len == 0) {
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
    kfree(vn->fs_data);
    kfree(vn);
    return 0;
}

static int ext2_write_inode(struct ext2_mount *mnt, ino_t ino,
                            struct ext2_inode *inode) {
    uint32_t isz = mnt->sb->s_inode_size,
             group = (ino - 1) / mnt->inodes_per_group,
             idx = (ino - 1) % mnt->inodes_per_group;
    uint32_t boff = (idx * isz) / mnt->block_size,
             ioff = (idx * isz) % mnt->block_size;

    struct buf *bp = bread(mnt->dev, mnt->gdt[group].bg_inode_table + boff);
    if (!bp)
        return -EIO;
    memcpy(bp->data + ioff, inode, isz);
    bwrite(bp);
    brelse(bp);
    return 0;
}

static int ext2_write_gd(struct ext2_mount *mnt, uint32_t bg) {
    uint32_t bnum = 2 + (bg * sizeof(struct ext2_group_desc)) / mnt->block_size;
    uint32_t off = (bg * sizeof(struct ext2_group_desc)) % mnt->block_size;

    struct buf *bp = bread(mnt->dev, bnum);
    if (!bp)
        return -EIO;
    memcpy(bp->data + off, &mnt->gdt[bg], sizeof(struct ext2_group_desc));
    bwrite(bp);
    brelse(bp);
    return 0;
}

static int ext2_alloc_block(struct ext2_mount *mnt, uint32_t *out) {
    spin_lock(&mnt->lock);
    for (uint32_t bg = 0; bg < mnt->groups_count; bg++) {
        if (mnt->gdt[bg].bg_free_blocks_count == 0)
            continue;
        struct buf *bp = bread(mnt->dev, mnt->gdt[bg].bg_block_bitmap);
        if (!bp)
            continue;

        for (uint32_t i = 0; i < mnt->blocks_per_group; i++) {
            if (!(bp->data[i / 8] & (1 << (i % 8)))) {
                bp->data[i / 8] |= (1 << (i % 8));
                bwrite(bp);
                mnt->gdt[bg].bg_free_blocks_count--;
                ext2_write_gd(mnt, bg);
                mnt->sb->s_free_blocks_count--;
                *out = bg * mnt->blocks_per_group + i;
                brelse(bp);
                spin_unlock(&mnt->lock);
                return 0;
            }
        }
        brelse(bp);
    }
    spin_unlock(&mnt->lock);
    return -ENOSPC;
}

static int ext2_alloc_inode(struct ext2_mount *mnt, ino_t *out) {
    spin_lock(&mnt->lock);
    for (uint32_t bg = 0; bg < mnt->groups_count; bg++) {
        if (mnt->gdt[bg].bg_free_inodes_count == 0)
            continue;
        struct buf *bp = bread(mnt->dev, mnt->gdt[bg].bg_inode_bitmap);
        if (!bp)
            continue;

        for (uint32_t i = 0; i < mnt->inodes_per_group; i++) {
            if (!(bp->data[i / 8] & (1 << (i % 8)))) {
                bp->data[i / 8] |= (1 << (i % 8));
                bwrite(bp);
                mnt->gdt[bg].bg_free_inodes_count--;
                ext2_write_gd(mnt, bg);
                mnt->sb->s_free_inodes_count--;
                *out = bg * mnt->inodes_per_group + i + 1;
                brelse(bp);
                spin_unlock(&mnt->lock);
                return 0;
            }
        }
        brelse(bp);
    }
    spin_unlock(&mnt->lock);
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

        if (ext2_get_block(mnt, &id->inode, bidx, &bnum) < 0)
            break;
        if (bnum == 0) {
            if (bidx >= 12 || ext2_alloc_block(mnt, &bnum) < 0)
                break;
            id->inode.i_block[bidx] = bnum;
        }

        struct buf *bp = bread(mnt->dev, bnum);
        if (!bp)
            break;
        memcpy(bp->data + boff, (const uint8_t *)buf + written, nr);
        bwrite(bp);
        brelse(bp);
        written += nr;
    }

    if (offset + written > id->inode.i_size) {
        id->inode.i_size = offset + written;
        vn->size = id->inode.i_size;
        ext2_write_inode(mnt, id->ino, &id->inode);
    }
    return written;
}

static struct file_ops ext2_file_ops = {
    .read = ext2_vnode_read,
    .write = ext2_vnode_write,
    .close = ext2_vnode_close,
    .readdir = ext2_vnode_readdir,
};

static struct vnode *ext2_create_vnode(struct ext2_mount *mnt, ino_t ino) {
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
    spin_init(&vn->lock);
    return vn;
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
    struct ext2_inode di;
    if (ext2_read_inode(mnt, dino, &di) < 0)
        return -EIO;
    size_t nlen = strlen(name), rlen = ALIGN_UP(8 + nlen, 4);

    uint32_t blocks = (di.i_size + mnt->block_size - 1) / mnt->block_size;
    for (uint32_t i = 0; i < blocks; i++) {
        uint32_t bnum;
        if (ext2_get_block(mnt, &di, i, &bnum) < 0 || bnum == 0)
            continue;
        struct buf *bp = bread(mnt->dev, bnum);
        if (!bp)
            continue;

        for (uint32_t off = 0; off < mnt->block_size;) {
            struct ext2_dirent *de = (struct ext2_dirent *)(bp->data + off);
            size_t alen = ALIGN_UP(8 + de->name_len, 4);
            if (de->rec_len - alen >= rlen) {
                struct ext2_dirent *new_de =
                    (struct ext2_dirent *)(bp->data + off + alen);
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

    uint32_t nb;
    if (blocks >= 12 || ext2_alloc_block(mnt, &nb) < 0)
        return -ENOSPC;
    di.i_block[blocks] = nb;
    struct buf *bp = bread(mnt->dev, nb);
    if (!bp)
        return -EIO;
    memset(bp->data, 0, mnt->block_size);
    struct ext2_dirent *de = (struct ext2_dirent *)bp->data;
    de->inode = ino;
    de->rec_len = mnt->block_size;
    de->name_len = nlen;
    de->file_type = type;
    memcpy(de->name, name, nlen);
    bwrite(bp);
    brelse(bp);
    di.i_size += mnt->block_size;
    ext2_write_inode(mnt, dino, &di);
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
    struct buf *bp = bread(did->mnt->dev, db);
    if (!bp)
        return -EIO;
    memset(bp->data, 0, did->mnt->block_size);
    struct ext2_dirent *de = (struct ext2_dirent *)bp->data;
    de->inode = nino;
    de->rec_len = 12;
    de->name_len = 1;
    de->file_type = EXT2_FT_DIR;
    de->name[0] = '.';
    de = (struct ext2_dirent *)(bp->data + 12);
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
    spin_init(&e->lock);

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
    struct buf *gbp = bread(e->dev, e->sb->s_first_data_block + 1);
    if (!gbp) {
        kfree(e->sb);
        kfree(e);
        return -EIO;
    }
    memcpy(e->gdt, gbp->data, gsz);
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
                                  .mkdir = ext2_mkdir};
static struct fs_type ext2_type = {.name = "ext2", .ops = &ext2_ops};
void ext2_init(void) {
    vfs_register_fs(&ext2_type);
}
