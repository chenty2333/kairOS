/**
 * kernel/fs/ext2/ext2_internal.h - ext2 internal structures
 */

#ifndef _KAIROS_EXT2_INTERNAL_H
#define _KAIROS_EXT2_INTERNAL_H

#include <kairos/buf.h>
#include <kairos/list.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

#define EXT2_SUPER_MAGIC 0xEF53
#define EXT2_IO_BLOCK_SIZE 4096
#define EXT2_ROOT_INO 2
#define EXT2_NAME_LEN 255
#define EXT2_MOUNT_MAGIC 0x45585432U
#define EXT2_INODE_DATA_MAGIC 0x49444E32U

/* Inode modes */
#define EXT2_S_IFIFO 0x1000
#define EXT2_S_IFCHR 0x2000
#define EXT2_S_IFDIR 0x4000
#define EXT2_S_IFBLK 0x6000
#define EXT2_S_IFREG 0x8000
#define EXT2_S_IFLNK 0xA000
#define EXT2_S_IFSOCK 0xC000

/* File types */
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR 2
#define EXT2_FT_CHRDEV 3
#define EXT2_FT_BLKDEV 4
#define EXT2_FT_FIFO 5
#define EXT2_FT_SOCK 6
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
    uint32_t magic;
    atomic_t refcount;
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

struct ext2_inode_data {
    uint32_t magic;
    ino_t ino;
    struct ext2_inode inode;
    struct ext2_mount *mnt;
    struct vnode *vn;
    struct list_head cache_node;
};

static inline int ext2_vnode_ctx(struct vnode *vn,
                                 struct ext2_inode_data **id_out,
                                 struct ext2_mount **mnt_out) {
    if (!vn || !id_out || !mnt_out)
        return -EINVAL;

    struct ext2_inode_data *id = (struct ext2_inode_data *)vn->fs_data;
    if (!id || (uintptr_t)id < CONFIG_PAGE_SIZE)
        return -EIO;
    if (id->magic != EXT2_INODE_DATA_MAGIC)
        return -EIO;

    struct ext2_mount *mnt = id->mnt;
    if (!mnt || (uintptr_t)mnt < CONFIG_PAGE_SIZE)
        return -EIO;
    if (mnt->magic != EXT2_MOUNT_MAGIC)
        return -EIO;

    *id_out = id;
    *mnt_out = mnt;
    return 0;
}

struct ext2_path {
    int depth;
    uint32_t offsets[4];
};

static inline uint32_t ext2_blocks_per_io(struct ext2_mount *mnt) {
    return EXT2_IO_BLOCK_SIZE / mnt->block_size;
}

struct buf *ext2_bread(struct ext2_mount *mnt, uint32_t bnum, uint32_t *blk_off);
int ext2_read_inode(struct ext2_mount *mnt, ino_t ino, struct ext2_inode *inode);
int ext2_write_inode(struct ext2_mount *mnt, ino_t ino, struct ext2_inode *inode);
int ext2_alloc_block(struct ext2_mount *mnt, uint32_t *out);
int ext2_free_block(struct ext2_mount *mnt, uint32_t bnum);
int ext2_write_gd(struct ext2_mount *mnt, uint32_t bg);
int ext2_alloc_inode(struct ext2_mount *mnt, ino_t *out);
int ext2_free_inode(struct ext2_mount *mnt, ino_t ino);
void ext2_mount_get(struct ext2_mount *mnt);
void ext2_mount_put(struct ext2_mount *mnt);
int ext2_get_block(struct ext2_mount *mnt, struct ext2_inode_data *id,
                   uint32_t idx, uint32_t *out, int create);
int ext2_truncate_blocks(struct ext2_mount *mnt, ino_t ino,
                         struct ext2_inode *inode);
struct vnode *ext2_cache_get(struct ext2_mount *mnt, ino_t ino);
void ext2_cache_add(struct ext2_inode_data *id);
struct vnode *ext2_create_vnode(struct ext2_mount *mnt, ino_t ino);
int64_t ext2_remove_dirent(struct ext2_mount *mnt, ino_t dino,
                           const char *name);
int ext2_dir_is_empty(struct ext2_mount *mnt, ino_t ino);
int ext2_add_dirent(struct ext2_mount *mnt, ino_t dino, const char *name,
                    ino_t ino, uint8_t type);
int ext2_vnode_poll(struct file *file, uint32_t events);
int ext2_vnode_truncate(struct vnode *vn, off_t length);
ssize_t ext2_vnode_write(struct vnode *vn, const void *buf, size_t len,
                         off_t offset, uint32_t flags);
int ext2_vnode_readdir(struct vnode *vn, struct dirent *ent, off_t *offset);

struct vnode *ext2_lookup(struct vnode *dir, const char *name);
int ext2_create(struct vnode *dir, const char *name, mode_t mode);
int ext2_mkdir(struct vnode *dir, const char *name, mode_t mode);
int ext2_symlink(struct vnode *dir, const char *name, const char *target);
int ext2_unlink(struct vnode *dir, const char *name);
int ext2_rmdir(struct vnode *dir, const char *name);
int ext2_rename(struct vnode *odir, const char *oname,
                struct vnode *ndir, const char *nname);
int ext2_link(struct vnode *dir, const char *name, struct vnode *target);
int ext2_mknod(struct vnode *dir, const char *name, mode_t mode, dev_t dev);
int ext2_chmod(struct vnode *vn, mode_t mode);
int ext2_chown(struct vnode *vn, uid_t uid, gid_t gid);
int ext2_utimes(struct vnode *vn, const struct timespec *atime,
                const struct timespec *mtime);

int ext2_mount(struct mount *mnt);
int ext2_unmount(struct mount *mnt);
int ext2_statfs(struct mount *mnt, struct kstatfs *st);

#endif
