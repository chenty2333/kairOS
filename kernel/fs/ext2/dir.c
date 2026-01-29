/**
 * kernel/fs/ext2/dir.c - ext2 directory operations
 */

#include <kairos/mm.h>
#include <kairos/string.h>
#include <kairos/types.h>

#include "ext2_internal.h"

struct vnode *ext2_lookup(struct vnode *dir, const char *name) {
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

int ext2_add_dirent(struct ext2_mount *mnt, ino_t dino, const char *name,
                    ino_t ino, uint8_t type) {
    struct ext2_inode_data di;
    di.mnt = mnt;
    di.ino = dino;
    if (ext2_read_inode(mnt, dino, &di.inode) < 0)
        return -EIO;
    size_t nlen = strlen(name);
    size_t rlen = ALIGN_UP(8 + nlen, 4);

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
            if (de->rec_len == 0)
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

    uint32_t nb;
    if (ext2_get_block(mnt, &di, blocks, &nb, 1) < 0)
        return -ENOSPC;

    uint32_t blk_off = 0;
    struct buf *bp = ext2_bread(mnt, nb, &blk_off);
    if (!bp)
        return -EIO;

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

int ext2_create(struct vnode *dir, const char *name, mode_t mode) {
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

int ext2_symlink(struct vnode *dir, const char *name, const char *target) {
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

int ext2_mkdir(struct vnode *dir, const char *name, mode_t mode) {
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

int ext2_mknod(struct vnode *dir, const char *name, mode_t mode, dev_t dev) {
    struct ext2_inode_data *did = dir->fs_data;
    ino_t nino;
    if (ext2_alloc_inode(did->mnt, &nino) < 0) {
        return -ENOSPC;
    }
    struct ext2_inode ni;
    memset(&ni, 0, sizeof(ni));
    ni.i_mode = (uint16_t)mode;
    ni.i_links_count = 1;
    if (S_ISCHR(mode) || S_ISBLK(mode)) {
        ni.i_block[0] = (uint32_t)dev;
        ni.i_block[1] = (uint32_t)dev;
    }
    ext2_write_inode(did->mnt, nino, &ni);

    uint8_t ft = EXT2_FT_REG_FILE;
    if (S_ISCHR(mode)) {
        ft = EXT2_FT_CHRDEV;
    } else if (S_ISBLK(mode)) {
        ft = EXT2_FT_BLKDEV;
    } else if (S_ISFIFO(mode)) {
        ft = EXT2_FT_FIFO;
    }
    if (ext2_add_dirent(did->mnt, did->ino, name, nino, ft) < 0) {
        return -EIO;
    }
    did->inode.i_links_count++;
    ext2_write_inode(did->mnt, did->ino, &did->inode);
    return 0;
}

int ext2_link(struct vnode *dir, const char *name, struct vnode *target) {
    struct ext2_inode_data *did = dir->fs_data;
    struct ext2_inode_data *tid = target->fs_data;
    if (!did || !tid) {
        return -EINVAL;
    }

    uint8_t ft = EXT2_FT_REG_FILE;
    uint16_t fmt = tid->inode.i_mode & 0xF000;
    if (fmt == EXT2_S_IFLNK) {
        ft = EXT2_FT_SYMLINK;
    }

    int ret = ext2_add_dirent(did->mnt, did->ino, name, tid->ino, ft);
    if (ret < 0) {
        return ret;
    }
    tid->inode.i_links_count++;
    ext2_write_inode(did->mnt, tid->ino, &tid->inode);
    return 0;
}

int ext2_chmod(struct vnode *vn, mode_t mode) {
    struct ext2_inode_data *id = vn->fs_data;
    if (!id) {
        return -EINVAL;
    }
    id->inode.i_mode = (id->inode.i_mode & 0xF000) | (mode & 0xFFF);
    ext2_write_inode(id->mnt, id->ino, &id->inode);
    return 0;
}

int ext2_chown(struct vnode *vn, uid_t uid, gid_t gid) {
    struct ext2_inode_data *id = vn->fs_data;
    if (!id) {
        return -EINVAL;
    }
    id->inode.i_uid = (uint16_t)uid;
    id->inode.i_gid = (uint16_t)gid;
    ext2_write_inode(id->mnt, id->ino, &id->inode);
    return 0;
}

int ext2_utimes(struct vnode *vn, const struct timespec *atime,
                const struct timespec *mtime) {
    struct ext2_inode_data *id = vn->fs_data;
    if (!id) {
        return -EINVAL;
    }
    if (atime) {
        id->inode.i_atime = (uint32_t)atime->tv_sec;
    }
    if (mtime) {
        id->inode.i_mtime = (uint32_t)mtime->tv_sec;
    }
    ext2_write_inode(id->mnt, id->ino, &id->inode);
    return 0;
}

int64_t ext2_remove_dirent(struct ext2_mount *mnt, ino_t dino,
                           const char *name) {
    struct ext2_inode_data di;
    di.mnt = mnt;
    di.ino = dino;
    if (ext2_read_inode(mnt, dino, &di.inode) < 0) {
        return -EIO;
    }

    uint32_t blocks = (di.inode.i_size + mnt->block_size - 1) / mnt->block_size;
    size_t nlen = strlen(name);

    for (uint32_t i = 0; i < blocks; i++) {
        uint32_t bnum;
        if (ext2_get_block(mnt, &di, i, &bnum, 0) < 0 || bnum == 0) {
            continue;
        }
        uint32_t blk_off = 0;
        struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
        if (!bp) {
            continue;
        }

        struct ext2_dirent *prev = NULL;
        for (uint32_t off = 0; off < mnt->block_size;) {
            struct ext2_dirent *de =
                (struct ext2_dirent *)(bp->data + blk_off + off);
            if (de->rec_len == 0) {
                break;
            }
            if (de->inode != 0 && de->name_len == nlen &&
                memcmp(de->name, name, nlen) == 0) {
                ino_t victim = de->inode;
                if (prev) {
                    prev->rec_len += de->rec_len;
                } else {
                    de->inode = 0;
                }
                bwrite(bp);
                brelse(bp);
                return (int64_t)victim;
            }
            prev = de;
            off += de->rec_len;
        }
        brelse(bp);
    }
    return -ENOENT;
}

int ext2_unlink(struct vnode *dir, const char *name) {
    struct ext2_inode_data *did = dir->fs_data;
    if (!did) {
        return -EINVAL;
    }

    int64_t victim_ino = ext2_remove_dirent(did->mnt, did->ino, name);
    if (victim_ino < 0) {
        return (int)victim_ino;
    }

    struct ext2_inode vi;
    if (ext2_read_inode(did->mnt, (ino_t)victim_ino, &vi) < 0) {
        return -EIO;
    }

    if ((vi.i_mode & 0xF000) == EXT2_S_IFDIR) {
        return -EISDIR;
    }

    if (vi.i_links_count > 0) {
        vi.i_links_count--;
    }

    if (vi.i_links_count == 0) {
        ext2_truncate_blocks(did->mnt, (ino_t)victim_ino, &vi);
        ext2_free_inode(did->mnt, (ino_t)victim_ino);
    } else {
        ext2_write_inode(did->mnt, (ino_t)victim_ino, &vi);
    }

    struct vnode *cvn = ext2_cache_get(did->mnt, (ino_t)victim_ino);
    if (cvn) {
        cvn->nlink = vi.i_links_count;
        vnode_put(cvn);
    }

    return 0;
}

int ext2_dir_is_empty(struct ext2_mount *mnt, ino_t ino) {
    struct ext2_inode_data di;
    di.mnt = mnt;
    di.ino = ino;
    if (ext2_read_inode(mnt, ino, &di.inode) < 0) {
        return 0;
    }

    uint32_t blocks = (di.inode.i_size + mnt->block_size - 1) / mnt->block_size;
    for (uint32_t i = 0; i < blocks; i++) {
        uint32_t bnum;
        if (ext2_get_block(mnt, &di, i, &bnum, 0) < 0 || bnum == 0) {
            continue;
        }
        uint32_t blk_off = 0;
        struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
        if (!bp) {
            continue;
        }
        for (uint32_t off = 0; off < mnt->block_size;) {
            struct ext2_dirent *de =
                (struct ext2_dirent *)(bp->data + blk_off + off);
            if (de->rec_len == 0) {
                break;
            }
            if (de->inode != 0) {
                if (!(de->name_len == 1 && de->name[0] == '.') &&
                    !(de->name_len == 2 && de->name[0] == '.' &&
                      de->name[1] == '.')) {
                    brelse(bp);
                    return 0;
                }
            }
            off += de->rec_len;
        }
        brelse(bp);
    }
    return 1;
}

int ext2_rmdir(struct vnode *dir, const char *name) {
    struct ext2_inode_data *did = dir->fs_data;
    if (!did) {
        return -EINVAL;
    }

    struct vnode *target = ext2_lookup(dir, name);
    if (!target) {
        return -ENOENT;
    }
    struct ext2_inode_data *tid = target->fs_data;
    if ((tid->inode.i_mode & 0xF000) != EXT2_S_IFDIR) {
        vnode_put(target);
        return -ENOTDIR;
    }
    if (!ext2_dir_is_empty(tid->mnt, tid->ino)) {
        vnode_put(target);
        return -ENOTEMPTY;
    }
    vnode_put(target);

    int64_t victim_ino = ext2_remove_dirent(did->mnt, did->ino, name);
    if (victim_ino < 0) {
        return (int)victim_ino;
    }

    struct ext2_inode vi;
    if (ext2_read_inode(did->mnt, (ino_t)victim_ino, &vi) < 0) {
        return -EIO;
    }
    vi.i_links_count = 0;
    ext2_truncate_blocks(did->mnt, (ino_t)victim_ino, &vi);
    ext2_free_inode(did->mnt, (ino_t)victim_ino);

    if (did->inode.i_links_count > 0) {
        did->inode.i_links_count--;
        ext2_write_inode(did->mnt, did->ino, &did->inode);
        dir->nlink = did->inode.i_links_count;
    }

    return 0;
}

int ext2_rename(struct vnode *odir, const char *oname,
                struct vnode *ndir, const char *nname) {
    struct ext2_inode_data *odid = odir->fs_data;
    struct ext2_inode_data *ndid = ndir->fs_data;
    if (!odid || !ndid) {
        return -EINVAL;
    }
    struct ext2_mount *mnt = odid->mnt;

    struct vnode *src = ext2_lookup(odir, oname);
    if (!src) {
        return -ENOENT;
    }
    struct ext2_inode_data *sid = src->fs_data;
    ino_t src_ino = sid->ino;
    uint16_t src_mode = sid->inode.i_mode;
    int src_is_dir = ((src_mode & 0xF000) == EXT2_S_IFDIR);

    uint8_t ft = EXT2_FT_REG_FILE;
    switch (src_mode & 0xF000) {
    case EXT2_S_IFDIR:
        ft = EXT2_FT_DIR;
        break;
    case EXT2_S_IFLNK:
        ft = EXT2_FT_SYMLINK;
        break;
    case EXT2_S_IFCHR:
        ft = EXT2_FT_CHRDEV;
        break;
    case EXT2_S_IFBLK:
        ft = EXT2_FT_BLKDEV;
        break;
    case EXT2_S_IFIFO:
        ft = EXT2_FT_FIFO;
        break;
    case EXT2_S_IFSOCK:
        ft = EXT2_FT_SOCK;
        break;
    default:
        break;
    }
    vnode_put(src);

    struct vnode *dst = ext2_lookup(ndir, nname);
    if (dst) {
        struct ext2_inode_data *ddid = dst->fs_data;
        int dst_is_dir = ((ddid->inode.i_mode & 0xF000) == EXT2_S_IFDIR);
        vnode_put(dst);

        if (src_is_dir && !dst_is_dir) {
            return -ENOTDIR;
        }
        if (!src_is_dir && dst_is_dir) {
            return -EISDIR;
        }
        int ret;
        if (dst_is_dir) {
            ret = ext2_rmdir(ndir, nname);
        } else {
            ret = ext2_unlink(ndir, nname);
        }
        if (ret < 0) {
            return ret;
        }
    }

    int ret = ext2_add_dirent(mnt, ndid->ino, nname, src_ino, ft);
    if (ret < 0) {
        return ret;
    }

    int64_t removed = ext2_remove_dirent(mnt, odid->ino, oname);
    if (removed < 0) {
        return (int)removed;
    }

    if (src_is_dir && odid->ino != ndid->ino) {
        struct ext2_inode di;
        if (ext2_read_inode(mnt, src_ino, &di) >= 0) {
            uint32_t bnum = di.i_block[0];
            if (bnum != 0) {
                uint32_t blk_off = 0;
                struct buf *bp = ext2_bread(mnt, bnum, &blk_off);
                if (bp) {
                    for (uint32_t off = 0; off < mnt->block_size;) {
                        struct ext2_dirent *de =
                            (struct ext2_dirent *)(bp->data + blk_off + off);
                        if (de->rec_len == 0) {
                            break;
                        }
                        if (de->name_len == 2 && de->name[0] == '.' &&
                            de->name[1] == '.') {
                            de->inode = ndid->ino;
                            bwrite(bp);
                            break;
                        }
                        off += de->rec_len;
                    }
                    brelse(bp);
                }
            }
        }
        if (odid->inode.i_links_count > 0) {
            odid->inode.i_links_count--;
            ext2_write_inode(mnt, odid->ino, &odid->inode);
            odir->nlink = odid->inode.i_links_count;
        }
        ndid->inode.i_links_count++;
        ext2_write_inode(mnt, ndid->ino, &ndid->inode);
        ndir->nlink = ndid->inode.i_links_count;
    }

    return 0;
}
