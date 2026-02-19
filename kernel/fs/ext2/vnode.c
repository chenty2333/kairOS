/**
 * kernel/fs/ext2/vnode.c - ext2 vnode operations
 */

#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/string.h>

#include "ext2_internal.h"

static ssize_t ext2_vnode_read(struct vnode *vn, void *buf, size_t len,
                               off_t offset,
                               uint32_t flags __attribute__((unused))) {
    struct ext2_inode_data *id = NULL;
    struct ext2_mount *mnt = NULL;
    int vctx = ext2_vnode_ctx(vn, &id, &mnt);
    if (vctx < 0)
        return vctx;
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
        uint32_t bidx = offset / mnt->block_size;
        uint32_t boff = offset % mnt->block_size;
        uint32_t nr = MIN(len, mnt->block_size - boff);
        uint32_t bnum;
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

ssize_t ext2_vnode_write(struct vnode *vn, const void *buf, size_t len,
                         off_t offset,
                         uint32_t flags __attribute__((unused))) {
    struct ext2_inode_data *id = NULL;
    struct ext2_mount *mnt = NULL;
    int vctx = ext2_vnode_ctx(vn, &id, &mnt);
    if (vctx < 0) {
        pr_err("ext2: write with invalid vnode context\n");
        return vctx;
    }
    size_t written = 0;

    while (written < len) {
        uint32_t bidx = (offset + written) / mnt->block_size;
        uint32_t boff = (offset + written) % mnt->block_size;
        uint32_t bnum;
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

int ext2_vnode_readdir(struct vnode *vn, struct dirent *ent, off_t *offset) {
    struct ext2_inode_data *id = NULL;
    struct ext2_mount *mnt = NULL;
    int vctx = ext2_vnode_ctx(vn, &id, &mnt);
    if (vctx < 0)
        return vctx;
    while (*offset < (off_t)id->inode.i_size) {
        uint32_t bidx = *offset / mnt->block_size;
        uint32_t boff = *offset % mnt->block_size;
        uint32_t bnum;
        if (ext2_get_block(mnt, id, bidx, &bnum, 0) < 0 || bnum == 0)
            return 0;

        uint32_t blk_off = 0;
        struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
        if (!bp)
            return -EIO;

        struct ext2_dirent *de =
            (struct ext2_dirent *)(bp->data + blk_off + boff);
        if (de->rec_len < 8 || de->rec_len > (mnt->block_size - boff)) {
            brelse(bp);
            return -EIO;
        }

        if (de->inode == 0) {
            *offset += de->rec_len;
            brelse(bp);
            continue;
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

    return 0;
}

static int ext2_vnode_close(struct vnode *vn) {
    struct ext2_inode_data *id =
        vn ? (struct ext2_inode_data *)vn->fs_data : NULL;
    struct ext2_mount *mnt = NULL;

    if (id && (uintptr_t)id >= CONFIG_PAGE_SIZE &&
        id->magic == EXT2_INODE_DATA_MAGIC) {
        mnt = id->mnt;
    }

    if (id && mnt && (uintptr_t)mnt >= CONFIG_PAGE_SIZE &&
        mnt->magic == EXT2_MOUNT_MAGIC) {
        mutex_lock(&mnt->icache_lock);
        if (!list_empty(&id->cache_node)) {
            list_del(&id->cache_node);
            INIT_LIST_HEAD(&id->cache_node);
        }
        mutex_unlock(&mnt->icache_lock);
    }
    if (id)
        id->magic = 0;
    kfree(id);
    kfree(vn);
    ext2_mount_put(mnt);
    return 0;
}

int ext2_vnode_poll(struct file *file, uint32_t events) {
    if (!file || !file->vnode)
        return POLLNVAL;
    struct vnode *vn = file->vnode;

    uint32_t revents = (vn->type == VNODE_DIR) ? POLLIN : (POLLIN | POLLOUT);
    return (int)(revents & events);
}

static struct file_ops ext2_file_ops = {
    .read = ext2_vnode_read,
    .write = ext2_vnode_write,
    .close = ext2_vnode_close,
    .readdir = ext2_vnode_readdir,
    .poll = ext2_vnode_poll,
    .truncate = ext2_vnode_truncate,
};

struct vnode *ext2_create_vnode(struct ext2_mount *mnt, ino_t ino) {
    struct vnode *cached = ext2_cache_get(mnt, ino);
    if (cached)
        return cached;

    struct ext2_inode_data *id = kmalloc(sizeof(*id));
    struct vnode *vn = kmalloc(sizeof(*vn));
    if (!id || !vn) {
        kfree(id);
        kfree(vn);
        return NULL;
    }

    ext2_mount_get(mnt);
    if (ext2_read_inode(mnt, ino, &id->inode) < 0) {
        ext2_mount_put(mnt);
        kfree(id);
        kfree(vn);
        return NULL;
    }

    id->magic = EXT2_INODE_DATA_MAGIC;
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
    vn->nlink = id->inode.i_links_count;
    vn->atime = id->inode.i_atime;
    vn->mtime = id->inode.i_mtime;
    vn->ctime = id->inode.i_ctime;
    vn->rdev = 0;
    vn->ops = &ext2_file_ops;
    vn->fs_data = id;
    vn->mount = NULL;
    atomic_init(&vn->refcount, 1);
    vn->parent = NULL;
    vn->name[0] = '\0';
    rwlock_init(&vn->lock, "ext2_vnode");
    poll_wait_head_init(&vn->pollers);
    id->vn = vn;
    INIT_LIST_HEAD(&id->cache_node);
    ext2_cache_add(id);
    return vn;
}
