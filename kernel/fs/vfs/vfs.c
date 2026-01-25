/**
 * kernel/fs/vfs/vfs.c - Virtual File System Implementation
 */

#include <kairos/blkdev.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

static LIST_HEAD(mount_list);
static LIST_HEAD(fs_type_list);
static spinlock_t vfs_lock = SPINLOCK_INIT;
static struct mount *root_mount = NULL;

static struct kmem_cache *vnode_cache;
static struct kmem_cache *file_cache;

int vfs_normalize_path(const char *cwd, const char *input, char *output) {
    char temp[CONFIG_PATH_MAX], *stack[32];
    int top = 0;
    if (!output || !input)
        return -EINVAL;

    if (input[0] == '/') {
        if (strlen(input) >= CONFIG_PATH_MAX)
            return -ENAMETOOLONG;
        strcpy(temp, input);
    } else {
        if (!cwd || cwd[0] != '/')
            return -EINVAL;
        if (strlen(cwd) + strlen(input) + 2 >= CONFIG_PATH_MAX)
            return -ENAMETOOLONG;
        strcpy(temp, cwd);
        if (temp[strlen(temp) - 1] != '/')
            strcat(temp, "/");
        strcat(temp, input);
    }

    char *p = temp;
    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        char *start = p;
        while (*p && *p != '/')
            p++;
        char saved = *p;
        *p = '\0';
        if (strcmp(start, ".") == 0)
            ;
        else if (strcmp(start, "..") == 0) {
            if (top > 0)
                top--;
        } else {
            if (top < 32)
                stack[top++] = start;
            else
                return -ENAMETOOLONG;
        }
        *p = saved;
    }

    char *out = output;
    *out++ = '/';
    for (int i = 0; i < top; i++) {
        size_t len = strlen(stack[i]);
        memcpy(out, stack[i], len);
        out += len;
        if (i < top - 1)
            *out++ = '/';
    }
    *out = '\0';
    return 0;
}

void vfs_init(void) {
    vnode_cache = kmem_cache_create("vnode", sizeof(struct vnode), NULL);
    file_cache = kmem_cache_create("file", sizeof(struct file), NULL);
    pr_info("VFS: initialized (caches ready)\n");
}

int vfs_register_fs(struct fs_type *fs) {
    if (!fs || !fs->name || !fs->ops)
        return -EINVAL;
    spin_lock(&vfs_lock);
    list_add_tail(&fs->list, &fs_type_list);
    spin_unlock(&vfs_lock);
    return 0;
}

static struct fs_type *find_fs_type(const char *name) {
    struct fs_type *fs;
    list_for_each_entry(fs, &fs_type_list, list) {
        if (strcmp(fs->name, name) == 0)
            return fs;
    }
    return NULL;
}

static struct mount *find_mount(const char *path) {
    struct mount *mnt, *best = NULL;
    size_t best_len = 0;
    if (!root_mount)
        return NULL;
    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        size_t len = strlen(mnt->mountpoint);
        if (strncmp(path, mnt->mountpoint, len) == 0 &&
            (path[len] == '\0' || path[len] == '/' || len == 1)) {
            if (len > best_len) {
                best = mnt;
                best_len = len;
            }
        }
    }
    spin_unlock(&vfs_lock);
    return best;
}

int vfs_mount(const char *src, const char *tgt, const char *fstype,
              uint32_t flags) {
    struct fs_type *fs;
    struct mount *mnt = NULL;
    struct blkdev *dev = NULL;
    int ret = -ENOMEM;
    spin_lock(&vfs_lock);
    fs = find_fs_type(fstype);
    spin_unlock(&vfs_lock);
    if (!fs)
        return -ENODEV;
    if (src && !(dev = blkdev_get(src)))
        return -ENODEV;
    if (!(mnt = kzalloc(sizeof(*mnt))) ||
        !(mnt->mountpoint = kmalloc(strlen(tgt) + 1)))
        goto err;
    strcpy(mnt->mountpoint, tgt);
    mnt->ops = fs->ops;
    mnt->dev = dev;
    mnt->flags = flags;
    if ((ret = mnt->ops->mount(mnt)) < 0)
        goto err;
    spin_lock(&vfs_lock);
    list_add_tail(&mnt->list, &mount_list);
    if (strcmp(tgt, "/") == 0)
        root_mount = mnt;
    spin_unlock(&vfs_lock);
    return 0;
err:
    if (mnt) {
        kfree(mnt->mountpoint);
        kfree(mnt);
    }
    if (dev)
        blkdev_put(dev);
    return ret;
}

int vfs_umount(const char *tgt) {
    struct mount *mnt;
    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        if (strcmp(mnt->mountpoint, tgt) == 0) {
            list_del(&mnt->list);
            if (mnt == root_mount)
                root_mount = NULL;
            spin_unlock(&vfs_lock);
            if (mnt->ops->unmount)
                mnt->ops->unmount(mnt);
            if (mnt->dev)
                blkdev_put(mnt->dev);
            kfree(mnt->mountpoint);
            kfree(mnt);
            return 0;
        }
    }
    spin_unlock(&vfs_lock);
    return -ENOENT;
}

struct vnode *vfs_lookup(const char *path) {
    char norm[CONFIG_PATH_MAX], comp[CONFIG_NAME_MAX];
    struct vnode *vn, *dir;
    struct process *cur = proc_current();
    if (!path || vfs_normalize_path(cur ? cur->cwd : "/", path, norm) < 0)
        return NULL;
    struct mount *mnt = find_mount(norm);
    if (!mnt || !(dir = mnt->root))
        return NULL;
    vnode_get(dir);
    const char *p = norm + strlen(mnt->mountpoint);
    if (strlen(mnt->mountpoint) > 1 && *p == '/')
        p++;
    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        const char *end = p;
        while (*end && *end != '/')
            end++;
        size_t len = end - p;
        if (len >= CONFIG_NAME_MAX) {
            vnode_put(dir);
            return NULL;
        }
        memcpy(comp, p, len);
        comp[len] = '\0';
        if (!mnt->ops->lookup || !(vn = mnt->ops->lookup(dir, comp))) {
            vnode_put(dir);
            return NULL;
        }
        vnode_put(dir);
        dir = vn;
        p = end;
    }
    return dir;
}

struct vnode *vfs_lookup_parent(const char *path, char *name) {
    if (!path || !name || path[0] != '/')
        return NULL;
    const char *last = strrchr(path, '/');
    if (!last)
        return NULL;
    strncpy(name, last + 1, CONFIG_NAME_MAX - 1);
    name[CONFIG_NAME_MAX - 1] = '\0';
    if (last == path)
        return vfs_lookup("/");
    char parent[CONFIG_PATH_MAX];
    size_t len = last - path;
    memcpy(parent, path, len);
    parent[len] = '\0';
    return vfs_lookup(parent);
}

int vfs_open(const char *path, int flags, mode_t mode, struct file **fp) {
    struct vnode *vn = vfs_lookup(path);
    if (!vn && (flags & O_CREAT)) {
        char name[CONFIG_NAME_MAX];
        struct vnode *parent = vfs_lookup_parent(path, name);
        struct mount *mnt = find_mount(path);
        if (parent && mnt && mnt->ops->create &&
            mnt->ops->create(parent, name, mode) >= 0)
            vn = vfs_lookup(path);
        if (parent)
            vnode_put(parent);
    }
    if (!vn)
        return -ENOENT;
    if ((flags & O_DIRECTORY) && vn->type != VNODE_DIR) {
        vnode_put(vn);
        return -ENOTDIR;
    }
    struct file *file = kmem_cache_alloc(file_cache);
    if (!file) {
        vnode_put(vn);
        return -ENOMEM;
    }
    memset(file, 0, sizeof(*file));
    file->vnode = vn;
    file->flags = flags;
    file->refcount = 1;
    spin_init(&file->lock);
    if ((flags & O_TRUNC) && vn->ops->truncate)
        vn->ops->truncate(vn, 0);
    *fp = file;
    return 0;
}

int vfs_close(struct file *file) {
    if (!file)
        return -EINVAL;
    spin_lock(&file->lock);
    if (--file->refcount > 0) {
        spin_unlock(&file->lock);
        return 0;
    }
    spin_unlock(&file->lock);
    if (file->vnode->ops->close)
        file->vnode->ops->close(file->vnode);
    vnode_put(file->vnode);
    kmem_cache_free(file_cache, file);
    return 0;
}

ssize_t vfs_read(struct file *file, void *buf, size_t len) {
    if (!file || !file->vnode->ops->read)
        return -EINVAL;
    spin_lock(&file->lock);
    ssize_t ret = file->vnode->ops->read(file->vnode, buf, len, file->offset);
    if (ret > 0)
        file->offset += ret;
    spin_unlock(&file->lock);
    return ret;
}

ssize_t vfs_write(struct file *file, const void *buf, size_t len) {
    if (!file || !file->vnode->ops->write)
        return -EINVAL;
    spin_lock(&file->lock);
    if (file->flags & O_APPEND)
        file->offset = file->vnode->size;
    ssize_t ret = file->vnode->ops->write(file->vnode, buf, len, file->offset);
    if (ret > 0)
        file->offset += ret;
    spin_unlock(&file->lock);
    return ret;
}

off_t vfs_seek(struct file *file, off_t offset, int whence) {
    spin_lock(&file->lock);
    off_t next = (whence == SEEK_SET)   ? offset
                 : (whence == SEEK_CUR) ? file->offset + offset
                                        : file->vnode->size + offset;
    if (next < 0) {
        spin_unlock(&file->lock);
        return -EINVAL;
    }
    file->offset = next;
    spin_unlock(&file->lock);
    return next;
}

int vfs_stat(const char *path, struct stat *st) {
    struct vnode *vn = vfs_lookup(path);
    if (!vn)
        return -ENOENT;
    int ret = vfs_fstat(&(struct file){.vnode = vn}, st);
    vnode_put(vn);
    return ret;
}

int vfs_fstat(struct file *file, struct stat *st) {
    struct vnode *vn = file->vnode;
    if (vn->ops->stat)
        return vn->ops->stat(vn, st);
    st->st_ino = vn->ino;
    st->st_mode = vn->mode;
    st->st_size = vn->size;
    st->st_uid = vn->uid;
    st->st_gid = vn->gid;
    return 0;
}

int vfs_mkdir(const char *path, mode_t mode) {
    char name[CONFIG_NAME_MAX];
    struct vnode *parent = vfs_lookup_parent(path, name);
    struct mount *mnt = find_mount(path);
    int ret = (parent && mnt && mnt->ops->mkdir)
                  ? mnt->ops->mkdir(parent, name, mode)
                  : -ENOSYS;
    if (parent)
        vnode_put(parent);
    return ret;
}

int vfs_rmdir(const char *path) {
    char name[CONFIG_NAME_MAX];
    struct vnode *parent = vfs_lookup_parent(path, name);
    struct mount *mnt = find_mount(path);
    int ret = (parent && mnt && mnt->ops->rmdir) ? mnt->ops->rmdir(parent, name)
                                                 : -ENOSYS;
    if (parent)
        vnode_put(parent);
    return ret;
}

int vfs_readdir(struct file *file, struct dirent *ent) {
    if (!file || !file->vnode->ops->readdir)
        return -ENOSYS;
    spin_lock(&file->lock);
    int ret = file->vnode->ops->readdir(file->vnode, ent, &file->offset);
    spin_unlock(&file->lock);
    return ret;
}

int vfs_unlink(const char *path) {
    char name[CONFIG_NAME_MAX];
    struct vnode *parent = vfs_lookup_parent(path, name);
    struct mount *mnt = find_mount(path);
    int ret = (parent && mnt && mnt->ops->unlink)
                  ? mnt->ops->unlink(parent, name)
                  : -ENOSYS;
    if (parent)
        vnode_put(parent);
    return ret;
}

int vfs_rename(const char *old, const char *new) {
    char on[CONFIG_NAME_MAX], nn[CONFIG_NAME_MAX];
    struct vnode *od = vfs_lookup_parent(old, on),
                 *nd = vfs_lookup_parent(new, nn);
    int ret = -EXDEV;
    if (od && nd && od->mount == nd->mount && od->mount->ops->rename)
        ret = od->mount->ops->rename(od, on, nd, nn);
    if (od)
        vnode_put(od);
    if (nd)
        vnode_put(nd);
    return ret;
}

void vnode_get(struct vnode *vn) {
    if (vn) {
        spin_lock(&vn->lock);
        vn->refcount++;
        spin_unlock(&vn->lock);
    }
}
void vnode_put(struct vnode *vn) {
    if (!vn)
        return;
    spin_lock(&vn->lock);
    if (--vn->refcount == 0) {
        spin_unlock(&vn->lock);
        if (vn->ops->close)
            vn->ops->close(vn);
    } else
        spin_unlock(&vn->lock);
}
