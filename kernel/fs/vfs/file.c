/**
 * kernel/fs/vfs/file.c - VFS file operations
 */

#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
#include <kairos/dentry.h>
#include <kairos/namei.h>
#include <kairos/pipe.h>

int vfs_open_at_path(const struct path *base, const char *path, int flags,
                     mode_t mode, struct file **fp) {
    if (!path || !fp)
        return -EINVAL;
    uint32_t allowed = O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND |
                       O_NONBLOCK | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC |
                       O_LARGEFILE;
    if (flags & ~allowed)
        return -EINVAL;
    int accmode = flags & O_ACCMODE;
    if (accmode != O_RDONLY && accmode != O_WRONLY && accmode != O_RDWR)
        return -EINVAL;
    if ((flags & O_DIRECTORY) && (flags & O_CREAT))
        return -EINVAL;
    if ((flags & O_TRUNC) && accmode == O_RDONLY)
        return -EACCES;

    int nflags = NAMEI_FOLLOW;
    if (flags & O_DIRECTORY)
        nflags |= NAMEI_DIRECTORY;
    if (flags & O_CREAT)
        nflags |= NAMEI_CREATE;
    if (flags & O_EXCL)
        nflags |= NAMEI_EXCL;
    if (flags & O_NOFOLLOW) {
        nflags |= NAMEI_NOFOLLOW;
        nflags &= ~NAMEI_FOLLOW;
    }

    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei_at(base, path, &resolved, nflags);
    if (ret < 0)
        return ret;
    if (!resolved.dentry)
        return -ENOENT;

    struct vnode *vn = NULL;
    if (resolved.dentry->flags & DENTRY_NEGATIVE) {
        if (!(flags & O_CREAT)) {
            dentry_put(resolved.dentry);
            return -ENOENT;
        }
        if (!resolved.dentry->parent ||
            !resolved.dentry->parent->vnode ||
            !resolved.mnt || !resolved.mnt->ops ||
            !resolved.mnt->ops->create) {
            dentry_put(resolved.dentry);
            return -EOPNOTSUPP;
        }
        ret = resolved.mnt->ops->create(resolved.dentry->parent->vnode,
                                        resolved.dentry->name, mode);
        if (ret < 0) {
            dentry_put(resolved.dentry);
            return ret;
        }
        vn = resolved.mnt->ops->lookup(resolved.dentry->parent->vnode,
                                       resolved.dentry->name);
        if (!vn) {
            dentry_put(resolved.dentry);
            return -EIO;
        }
        dentry_add(resolved.dentry, vn);
        vnode_put(vn);
    } else {
        if ((flags & O_EXCL) && (flags & O_CREAT)) {
            dentry_put(resolved.dentry);
            return -EEXIST;
        }
        vn = resolved.dentry->vnode;
        if (!vn) {
            dentry_put(resolved.dentry);
            return -ENOENT;
        }
        if ((flags & O_NOFOLLOW) && vn->type == VNODE_SYMLINK) {
            dentry_put(resolved.dentry);
            return -ELOOP;
        }
    }

    /*
     * Files keep their own vnode reference independent of dentry lifetime.
     * This must be done for both existing and newly created paths.
     */
    vnode_get(vn);

    struct file *file = vfs_file_alloc();
    if (!file) {
        vnode_put(vn);
        dentry_put(resolved.dentry);
        return -ENOMEM;
    }
    file->vnode = vn;
    file->dentry = resolved.dentry;
    dentry_get(file->dentry);
    file->flags = (uint32_t)(flags & (O_ACCMODE | O_APPEND | O_NONBLOCK));
    if (vfs_build_path_dentry(resolved.dentry, file->path,
                              sizeof(file->path)) < 0) {
        strncpy(file->path, path, sizeof(file->path) - 1);
        file->path[sizeof(file->path) - 1] = '\0';
    }
    if ((flags & O_TRUNC) && vn->ops->truncate) {
        rwlock_write_lock(&vn->lock);
        vn->ops->truncate(vn, 0);
        rwlock_write_unlock(&vn->lock);
    }
    if (vn->ops && vn->ops->open_file) {
        ret = vn->ops->open_file(file);
        if (ret < 0) {
            dentry_put(file->dentry);
            file->dentry = NULL;
            vnode_put(vn);
            vfs_file_free(file);
            dentry_put(resolved.dentry);
            return ret;
        }
    }
    *fp = file;
    dentry_put(resolved.dentry);
    return 0;
}

int vfs_open_at(const char *cwd, const char *path, int flags, mode_t mode,
                struct file **fp) {
    if (!path || !fp)
        return -EINVAL;
    if (path[0] == '/' || !cwd || !cwd[0])
        return vfs_open_at_path(NULL, path, flags, mode, fp);
    struct path base;
    path_init(&base);
    int ret = vfs_namei(cwd, &base, NAMEI_FOLLOW | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    ret = vfs_open_at_path(&base, path, flags, mode, fp);
    if (base.dentry)
        dentry_put(base.dentry);
    return ret;
}

int vfs_open(const char *path, int flags, mode_t mode, struct file **fp) {
    struct process *cur = proc_current();
    if (cur && cur->cwd_dentry) {
        struct path base;
        path_init(&base);
        base.dentry = cur->cwd_dentry;
        base.mnt = cur->cwd_dentry->mnt;
        return vfs_open_at_path(&base, path, flags, mode, fp);
    }
    return vfs_open_at_path(NULL, path, flags, mode, fp);
}

int vfs_close(struct file *file) {
    if (!file)
        return -EINVAL;
    uint32_t old = atomic_fetch_sub(&file->refcount, 1);
    if (old == 0)
        panic("vfs_close: refcount already zero on file '%s'", file->path);
    if (old > 1)
        return 0;
    if (file->vnode && file->vnode->ops && file->vnode->ops->close_file)
        file->vnode->ops->close_file(file);
    if (file->vnode && file->vnode->type == VNODE_PIPE) {
        pipe_close_end(file->vnode, file->flags);
    }
    if (file->dentry) {
        dentry_put(file->dentry);
        file->dentry = NULL;
    }
    vnode_put(file->vnode);
    vfs_file_free(file);
    return 0;
}

void file_put(struct file *file) {
    vfs_close(file);
}

ssize_t vfs_read(struct file *file, void *buf, size_t len) {
    if (!file)
        return -EINVAL;
    if (file->vnode->type == VNODE_DIR)
        return -EISDIR;
    if (file->vnode->type == VNODE_PIPE) {
        return pipe_read_file(file, buf, len);
    }
    if (file->vnode->ops->read_file) {
        mutex_lock(&file->lock);
        ssize_t ret = file->vnode->ops->read_file(file, buf, len);
        if (ret > 0)
            file->offset += ret;
        mutex_unlock(&file->lock);
        return ret;
    }
    if (!file->vnode->ops->read)
        return -EINVAL;
    rwlock_read_lock(&file->vnode->lock);
    mutex_lock(&file->lock);
    ssize_t ret = file->vnode->ops->read(file->vnode, buf, len, file->offset, file->flags);
    if (ret > 0)
        file->offset += ret;
    mutex_unlock(&file->lock);
    rwlock_read_unlock(&file->vnode->lock);
    return ret;
}

ssize_t vfs_write(struct file *file, const void *buf, size_t len) {
    if (!file)
        return -EINVAL;
    if (file->vnode->type == VNODE_DIR)
        return -EISDIR;
    if (file->vnode->type == VNODE_PIPE) {
        return pipe_write_file(file, buf, len);
    }
    if (file->vnode->ops->write_file) {
        mutex_lock(&file->lock);
        if (file->flags & O_APPEND)
            file->offset = file->vnode->size;
        ssize_t ret = file->vnode->ops->write_file(file, buf, len);
        if (ret > 0)
            file->offset += ret;
        mutex_unlock(&file->lock);
        return ret;
    }
    if (!file->vnode->ops->write)
        return -EINVAL;
    rwlock_write_lock(&file->vnode->lock);
    mutex_lock(&file->lock);
    if (file->flags & O_APPEND)
        file->offset = file->vnode->size;
    ssize_t ret = file->vnode->ops->write(file->vnode, buf, len, file->offset, file->flags);
    if (ret > 0)
        file->offset += ret;
    mutex_unlock(&file->lock);
    rwlock_write_unlock(&file->vnode->lock);
    return ret;
}

int vfs_ioctl(struct file *file, uint64_t cmd, uint64_t arg) {
    if (!file || !file->vnode || !file->vnode->ops)
        return -ENOTTY;
    if (file->vnode->ops->ioctl_file)
        return file->vnode->ops->ioctl_file(file, cmd, arg);
    if (!file->vnode->ops->ioctl)
        return -ENOTTY;
    return file->vnode->ops->ioctl(file->vnode, cmd, arg);
}

off_t vfs_seek(struct file *file, off_t offset, int whence) {
    off_t next;
    if (whence == SEEK_END) {
        rwlock_read_lock(&file->vnode->lock);
        mutex_lock(&file->lock);
        next = file->vnode->size + offset;
        if (next >= 0)
            file->offset = next;
        mutex_unlock(&file->lock);
        rwlock_read_unlock(&file->vnode->lock);
        return (next < 0) ? -EINVAL : next;
    }
    mutex_lock(&file->lock);
    if (whence == SEEK_SET)
        next = offset;
    else if (whence == SEEK_CUR)
        next = file->offset + offset;
    else {
        mutex_unlock(&file->lock);
        return -EINVAL;
    }
    if (next < 0) {
        mutex_unlock(&file->lock);
        return -EINVAL;
    }
    file->offset = next;
    mutex_unlock(&file->lock);
    return next;
}

int vfs_statfs(struct mount *mnt, struct kstatfs *st) {
    if (!mnt || !st)
        return -EINVAL;
    if (!mnt->ops || !mnt->ops->statfs)
        return -ENOSYS;
    return mnt->ops->statfs(mnt, st);
}

int vfs_stat(const char *path, struct stat *st) {
    if (!path || !st)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, NAMEI_FOLLOW);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    ret = vfs_stat_vnode(resolved.dentry->vnode, st);
    dentry_put(resolved.dentry);
    return ret;
}

int vfs_stat_vnode(struct vnode *vn, struct stat *st) {
    if (!vn)
        return -EINVAL;
    rwlock_read_lock(&vn->lock);
    if (vn->ops->stat) {
        int ret = vn->ops->stat(vn, st);
        rwlock_read_unlock(&vn->lock);
        return ret;
    }
    memset(st, 0, sizeof(*st));
    st->st_ino = vn->ino;
    st->st_mode = vn->mode;
    st->st_size = vn->size;
    st->st_uid = vn->uid;
    st->st_gid = vn->gid;
    st->st_nlink = vn->nlink;
    st->st_atime = vn->atime;
    st->st_mtime = vn->mtime;
    st->st_ctime = vn->ctime;
    st->st_rdev = vn->rdev;
    st->st_blksize = CONFIG_PAGE_SIZE;
    rwlock_read_unlock(&vn->lock);
    return 0;
}

int vfs_fstat(struct file *file, struct stat *st) {
    return vfs_stat_vnode(file->vnode, st);
}

int vfs_mkdir(const char *path, mode_t mode) {
    if (!path)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, NAMEI_CREATE | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    if (!resolved.dentry) {
        return -ENOENT;
    }
    if (!(resolved.dentry->flags & DENTRY_NEGATIVE)) {
        dentry_put(resolved.dentry);
        return -EEXIST;
    }
    if (!resolved.dentry->parent || !resolved.dentry->parent->vnode ||
        !resolved.mnt || !resolved.mnt->ops || !resolved.mnt->ops->mkdir) {
        dentry_put(resolved.dentry);
        return -ENOSYS;
    }
    ret = resolved.mnt->ops->mkdir(resolved.dentry->parent->vnode,
                                   resolved.dentry->name, mode);
    if (ret == 0) {
        struct vnode *vn =
            resolved.mnt->ops->lookup(resolved.dentry->parent->vnode,
                                      resolved.dentry->name);
        if (vn) {
            dentry_add(resolved.dentry, vn);
            vnode_put(vn);
        }
    }
    dentry_put(resolved.dentry);
    return ret;
}

int vfs_rmdir(const char *path) {
    if (!path)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->parent ||
        !resolved.dentry->parent->vnode || !resolved.mnt ||
        !resolved.mnt->ops || !resolved.mnt->ops->rmdir) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOSYS;
    }
    if (resolved.dentry->mounted) {
        dentry_put(resolved.dentry);
        return -EBUSY;
    }
    ret = resolved.mnt->ops->rmdir(resolved.dentry->parent->vnode,
                                   resolved.dentry->name);
    if (ret == 0)
        dentry_drop(resolved.dentry);
    dentry_put(resolved.dentry);
    return ret;
}

int vfs_readdir(struct file *file, struct dirent *ent) {
    if (!file || !file->vnode->ops->readdir)
        return -ENOSYS;
    rwlock_read_lock(&file->vnode->lock);
    mutex_lock(&file->lock);
    int ret = file->vnode->ops->readdir(file->vnode, ent, &file->offset);
    mutex_unlock(&file->lock);
    rwlock_read_unlock(&file->vnode->lock);
    return ret;
}

int vfs_unlink(const char *path) {
    if (!path)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, 0);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->parent ||
        !resolved.dentry->parent->vnode || !resolved.mnt ||
        !resolved.mnt->ops || !resolved.mnt->ops->unlink) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOSYS;
    }
    if (resolved.dentry->mounted) {
        dentry_put(resolved.dentry);
        return -EBUSY;
    }
    ret = resolved.mnt->ops->unlink(resolved.dentry->parent->vnode,
                                    resolved.dentry->name);
    if (ret == 0)
        dentry_drop(resolved.dentry);
    dentry_put(resolved.dentry);
    return ret;
}

int vfs_rename(const char *old, const char *new) {
    struct path oldp, newp;
    path_init(&oldp);
    path_init(&newp);
    int ret = vfs_namei(old, &oldp, 0);
    if (ret < 0)
        return ret;
    ret = vfs_namei(new, &newp, NAMEI_CREATE);
    if (ret < 0) {
        if (oldp.dentry)
            dentry_put(oldp.dentry);
        return ret;
    }
    if (!oldp.dentry || !newp.dentry || !oldp.dentry->parent ||
        !newp.dentry->parent || !oldp.mnt || !newp.mnt ||
        oldp.mnt != newp.mnt || !oldp.mnt->ops ||
        !oldp.mnt->ops->rename) {
        if (oldp.dentry)
            dentry_put(oldp.dentry);
        if (newp.dentry)
            dentry_put(newp.dentry);
        return -EXDEV;
    }
    if (oldp.dentry->mounted) {
        dentry_put(oldp.dentry);
        dentry_put(newp.dentry);
        return -EBUSY;
    }

    ret = oldp.mnt->ops->rename(oldp.dentry->parent->vnode, oldp.dentry->name,
                                newp.dentry->parent->vnode, newp.dentry->name);
    if (ret == 0) {
        if (newp.dentry && !(newp.dentry->flags & DENTRY_NEGATIVE))
            dentry_drop(newp.dentry);
        dentry_move(oldp.dentry, newp.dentry->parent, newp.dentry->name);
    }
    if (oldp.dentry)
        dentry_put(oldp.dentry);
    if (newp.dentry)
        dentry_put(newp.dentry);
    return ret;
}

int vfs_symlink(const char *target, const char *linkpath) {
    if (!target || !linkpath)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(linkpath, &resolved, NAMEI_CREATE);
    if (ret < 0)
        return ret;
    if (!resolved.dentry) {
        return -ENOENT;
    }
    if (!(resolved.dentry->flags & DENTRY_NEGATIVE)) {
        dentry_put(resolved.dentry);
        return -EEXIST;
    }
    if (!resolved.dentry->parent || !resolved.dentry->parent->vnode ||
        !resolved.mnt || !resolved.mnt->ops || !resolved.mnt->ops->symlink) {
        dentry_put(resolved.dentry);
        return -ENOSYS;
    }
    ret = resolved.mnt->ops->symlink(resolved.dentry->parent->vnode,
                                     resolved.dentry->name, target);
    if (ret == 0) {
        struct vnode *vn =
            resolved.mnt->ops->lookup(resolved.dentry->parent->vnode,
                                      resolved.dentry->name);
        if (vn) {
            dentry_add(resolved.dentry, vn);
            vnode_put(vn);
        }
    }
    dentry_put(resolved.dentry);
    return ret;
}

int vfs_fsync(struct file *file, int datasync) {
    if (!file || !file->vnode)
        return -EINVAL;
    if (!file->vnode->ops || !file->vnode->ops->fsync)
        return 0;
    return file->vnode->ops->fsync(file->vnode, datasync);
}

ssize_t vfs_readlink(const char *path, char *buf, size_t bufsz) {
    if (!path || !buf || bufsz == 0)
        return -EINVAL;
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, 0);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    if (resolved.dentry->vnode->type != VNODE_SYMLINK) {
        dentry_put(resolved.dentry);
        return -EINVAL;
    }
    ssize_t rl = vfs_readlink_vnode(resolved.dentry->vnode, buf, bufsz, false);
    dentry_put(resolved.dentry);
    return rl;
}
