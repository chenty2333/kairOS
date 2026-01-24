/**
 * vfs.c - Virtual File System Implementation
 *
 * This implements the VFS layer which provides a unified interface
 * to different file systems (ext2, fat32, devfs).
 */

#include <kairos/vfs.h>
#include <kairos/blkdev.h>
#include <kairos/types.h>
#include <kairos/printk.h>
#include <kairos/mm.h>
#include <kairos/spinlock.h>
#include <kairos/list.h>
#include <kairos/process.h>
#include <kairos/string.h>

/*
 * Global VFS State
 */
static LIST_HEAD(mount_list);           /* List of all mounts */
static LIST_HEAD(fs_type_list);         /* List of registered file systems */
static spinlock_t vfs_lock = SPINLOCK_INIT;

static struct mount *root_mount = NULL; /* Root filesystem mount */

/**
 * vfs_normalize_path - Resolve . and .. components and handle relative paths
 *
 * @cwd: Current working directory (must be absolute)
 * @input: Input path (relative or absolute)
 * @output: Buffer to store result (must be CONFIG_PATH_MAX)
 *
 * Returns 0 on success, negative error on failure.
 */
int vfs_normalize_path(const char *cwd, const char *input, char *output)
{
    char temp[CONFIG_PATH_MAX];
    char *stack[32];  // Stack for path components
    int top = 0;
    
    if (!output || !input) return -EINVAL;

    // 1. Construct initial full path
    if (input[0] == '/') {
        // Absolute path
        if (strlen(input) >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
        strcpy(temp, input);
    } else {
        // Relative path
        if (!cwd || cwd[0] != '/') return -EINVAL;
        size_t cwd_len = strlen(cwd);
        size_t input_len = strlen(input);
        if (cwd_len + 1 + input_len >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
        
        strcpy(temp, cwd);
        if (temp[cwd_len - 1] != '/') {
            strcat(temp, "/");
        }
        strcat(temp, input);
    }

    // 2. Split and process components
    char *p = temp;
    
    // Skip leading slashes
    while (*p == '/') p++;
    
    while (*p) {
        char *start = p;
        while (*p && *p != '/') p++;
        
        if (p != start) {
            // Null-terminate component temporarily
            char saved = *p;
            *p = '\0';
            
            if (strcmp(start, ".") == 0) {
                // Ignore .
            } else if (strcmp(start, "..") == 0) {
                // Pop from stack
                if (top > 0) top--;
            } else {
                // Push to stack
                if (top < 32) {
                    stack[top++] = start;
                } else {
                    return -ENAMETOOLONG; // Path too deep
                }
            }
            
            *p = saved; // Restore
        }
        
        while (*p == '/') p++;
    }

    // 3. Reconstruct path
    char *out = output;
    *out++ = '/';
    
    for (int i = 0; i < top; i++) {
        size_t len = strlen(stack[i]);
        if ((out - output) + len + 1 >= CONFIG_PATH_MAX) return -ENAMETOOLONG;
        
        strcpy(out, stack[i]);
        out += len;
        if (i < top - 1) {
            *out++ = '/';
        }
    }
    *out = '\0';
    
    // Special case: if result is empty string (popped everything), it's root
    if (output[0] == '\0') {
        output[0] = '/';
        output[1] = '\0';
    }

    return 0;
}

/**
 * vfs_init - Initialize the VFS subsystem
 */
void vfs_init(void)
{
    pr_info("VFS: initializing virtual file system\n");
}

/**
 * vfs_register_fs - Register a file system type
 */
int vfs_register_fs(struct fs_type *fs)
{
    if (!fs || !fs->name || !fs->ops) {
        return -EINVAL;
    }

    spin_lock(&vfs_lock);
    list_add_tail(&fs->list, &fs_type_list);
    spin_unlock(&vfs_lock);

    pr_info("VFS: registered file system: %s\n", fs->name);
    return 0;
}

/**
 * vfs_unregister_fs - Unregister a file system type
 */
int vfs_unregister_fs(struct fs_type *fs)
{
    if (!fs) {
        return -EINVAL;
    }

    spin_lock(&vfs_lock);
    list_del(&fs->list);
    spin_unlock(&vfs_lock);

    pr_info("VFS: unregistered file system: %s\n", fs->name);
    return 0;
}

/**
 * find_fs_type - Find registered file system by name
 */
static struct fs_type *find_fs_type(const char *name)
{
    struct fs_type *fs;

    list_for_each_entry(fs, &fs_type_list, list) {
        if (strcmp(fs->name, name) == 0) {
            return fs;
        }
    }

    return NULL;
}

/**
 * vfs_mount - Mount a file system
 *
 * @source: Device name (e.g., "vda") or NULL for pseudo-filesystems
 * @target: Mount point path (e.g., "/", "/dev")
 * @fstype: File system type (e.g., "ext2", "devfs")
 * @flags: Mount flags (MS_RDONLY, etc.)
 */
int vfs_mount(const char *source, const char *target,
              const char *fstype, uint32_t flags)
{
    struct fs_type *fs;
    struct mount *mnt;
    struct blkdev *dev = NULL;
    int ret;

    if (!target || !fstype) {
        return -EINVAL;
    }

    /* Find file system type */
    spin_lock(&vfs_lock);
    fs = find_fs_type(fstype);
    spin_unlock(&vfs_lock);

    if (!fs) {
        pr_err("VFS: unknown file system type: %s\n", fstype);
        return -ENODEV;
    }

    /* Get block device if source specified */
    if (source) {
        dev = blkdev_get(source);
        if (!dev) {
            pr_err("VFS: block device not found: %s\n", source);
            return -ENODEV;
        }
    }

    /* Allocate mount structure */
    mnt = kmalloc(sizeof(*mnt));
    if (!mnt) {
        if (dev) {
            blkdev_put(dev);
        }
        return -ENOMEM;
    }

    /* Initialize mount */
    mnt->mountpoint = kmalloc(strlen(target) + 1);
    if (!mnt->mountpoint) {
        kfree(mnt);
        if (dev) {
            blkdev_put(dev);
        }
        return -ENOMEM;
    }
    strncpy(mnt->mountpoint, target, strlen(target) + 1);
    mnt->ops = fs->ops;
    mnt->dev = dev;
    mnt->flags = flags;
    mnt->fs_data = NULL;
    mnt->root = NULL;

    /* Call filesystem-specific mount */
    ret = mnt->ops->mount(mnt);
    if (ret < 0) {
        pr_err("VFS: mount failed for %s: %d\n", fstype, ret);
        kfree(mnt->mountpoint);
        kfree(mnt);
        if (dev) {
            blkdev_put(dev);
        }
        return ret;
    }

    /* Add to mount list */
    spin_lock(&vfs_lock);
    list_add_tail(&mnt->list, &mount_list);

    /* Set as root if mounting at "/" */
    if (strcmp(target, "/") == 0) {
        root_mount = mnt;
    }
    spin_unlock(&vfs_lock);

    pr_info("VFS: mounted %s at %s (fs=%s)\n",
            source ? source : "none", target, fstype);
    return 0;
}

/**
 * vfs_umount - Unmount a file system
 */
int vfs_umount(const char *target)
{
    struct mount *mnt;
    int ret;

    if (!target) {
        return -EINVAL;
    }

    /* Find mount point */
    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        if (strcmp(mnt->mountpoint, target) == 0) {
            goto found;
        }
    }
    spin_unlock(&vfs_lock);
    return -ENOENT;

found:
    /* Remove from list */
    list_del(&mnt->list);
    if (mnt == root_mount) {
        root_mount = NULL;
    }
    spin_unlock(&vfs_lock);

    /* Call filesystem-specific unmount */
    if (mnt->ops->unmount) {
        ret = mnt->ops->unmount(mnt);
        if (ret < 0) {
            pr_warn("VFS: unmount warning for %s: %d\n", target, ret);
        }
    }

    /* Release resources */
    if (mnt->dev) {
        blkdev_put(mnt->dev);
    }
    kfree(mnt->mountpoint);
    kfree(mnt);

    pr_info("VFS: unmounted %s\n", target);
    return 0;
}

/**
 * find_mount - Find mount point for a path
 *
 * Returns the mount whose mountpoint is the longest prefix of path.
 */
static struct mount *find_mount(const char *path)
{
    struct mount *mnt, *best = NULL;
    size_t best_len = 0;

    /* Must have root mounted */
    if (!root_mount) {
        return NULL;
    }

    spin_lock(&vfs_lock);
    list_for_each_entry(mnt, &mount_list, list) {
        size_t len = strlen(mnt->mountpoint);

        /* Check if mountpoint is a prefix of path */
        if (strncmp(path, mnt->mountpoint, len) == 0) {
            /* Handle both "/" and "/foo" mount points */
            if (path[len] == '\0' || path[len] == '/' || len == 1) {
                if (len > best_len) {
                    best = mnt;
                    best_len = len;
                }
            }
        }
    }
    spin_unlock(&vfs_lock);

    return best;
}

/**
 * vfs_lookup - Look up a file by path
 *
 * Returns vnode for the file, or NULL if not found.
 */
struct vnode *vfs_lookup(const char *path)
{
    struct mount *mnt;
    struct vnode *vn, *dir;
    char component[CONFIG_NAME_MAX];
    const char *p, *end;
    size_t mount_len;
    char normalized_path[CONFIG_PATH_MAX];

    if (!path) {
        return NULL;
    }

    /* Normalize path */
    struct process *cur = proc_current();
    const char *cwd = (cur) ? cur->cwd : "/";
    
    if (vfs_normalize_path(cwd, path, normalized_path) < 0) {
        return NULL;
    }
    
    /* Use normalized path for lookup */
    path = normalized_path;

    if (path[0] != '/') {
        return NULL; /* Should not happen after normalization */
    }

    /* Find mount point */
    mnt = find_mount(path);
    if (!mnt) {
        return NULL;
    }

    /* Start from mount root */
    dir = mnt->root;
    if (!dir) {
        return NULL;
    }
    vnode_get(dir);

    /* Skip mountpoint prefix */
    mount_len = strlen(mnt->mountpoint);
    p = path + mount_len;
    if (mount_len > 1 && *p == '/') {
        p++;  /* Skip the '/' after mountpoint */
    }

    /* If we're looking up the mount point itself, return root */
    if (*p == '\0') {
        return dir;
    }

    /* Parse path components */
    while (*p) {
        /* Skip leading slashes */
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        /* Extract component */
        end = p;
        while (*end && *end != '/') {
            end++;
        }

        size_t len = end - p;
        if (len >= CONFIG_NAME_MAX) {
            vnode_put(dir);
            return NULL;
        }

        strncpy(component, p, len);
        component[len] = '\0';

        /* Lookup component in directory */
        if (!mnt->ops->lookup) {
            vnode_put(dir);
            return NULL;
        }

        vn = mnt->ops->lookup(dir, component);
        vnode_put(dir);

        if (!vn) {
            return NULL;
        }

        dir = vn;
        p = end;
    }

    return dir;
}

/**
 * vfs_lookup_parent - Look up parent directory and get filename
 *
 * @path: Full path
 * @name: Buffer to store filename (must be at least CONFIG_NAME_MAX bytes)
 *
 * Returns parent directory vnode, with name filled in.
 */
struct vnode *vfs_lookup_parent(const char *path, char *name)
{
    char parent_path[CONFIG_PATH_MAX];
    const char *p;
    size_t len;

    if (!path || !name || path[0] != '/') {
        return NULL;
    }

    /* Find last '/' */
    p = path + strlen(path) - 1;
    while (p > path && *p != '/') {
        p--;
    }

    /* Extract filename */
    strncpy(name, p + 1, CONFIG_NAME_MAX - 1);
    name[CONFIG_NAME_MAX - 1] = '\0';

    /* Extract parent path */
    if (p == path) {
        /* Parent is root */
        return vfs_lookup("/");
    }

    len = p - path;
    if (len >= CONFIG_PATH_MAX) {
        return NULL;
    }

    strncpy(parent_path, path, len);
    parent_path[len] = '\0';

    return vfs_lookup(parent_path);
}

/**
 * vfs_open - Open a file
 */
int vfs_open(const char *path, int flags, mode_t mode, struct file **fp)
{
    struct vnode *vn;
    struct file *file;

    if (!path || !fp) {
        return -EINVAL;
    }

    /* Try to lookup existing file */
    vn = vfs_lookup(path);

    /* If doesn't exist and O_CREAT, create it */
    if (!vn && (flags & O_CREAT)) {
        struct vnode *parent;
        char name[CONFIG_NAME_MAX];
        struct mount *mnt;
        int ret;

        parent = vfs_lookup_parent(path, name);
        if (!parent) {
            return -ENOENT;
        }

        /* Find mount for parent */
        mnt = find_mount(path);
        if (!mnt || !mnt->ops->create) {
            vnode_put(parent);
            return -ENOSYS;
        }

        /* Create file */
        ret = mnt->ops->create(parent, name, mode);
        vnode_put(parent);

        if (ret < 0) {
            return ret;
        }

        /* Lookup newly created file */
        vn = vfs_lookup(path);
        if (!vn) {
            return -EIO;
        }
    }

    if (!vn) {
        return -ENOENT;
    }

    /* Check if O_DIRECTORY and vnode is not a directory */
    if ((flags & O_DIRECTORY) && vn->type != VNODE_DIR) {
        vnode_put(vn);
        return -ENOTDIR;
    }

    /* Allocate file structure */
    file = kmalloc(sizeof(*file));
    if (!file) {
        vnode_put(vn);
        return -ENOMEM;
    }

    file->vnode = vn;
    file->offset = 0;
    file->flags = flags;
    file->refcount = 1;
    file->lock = (spinlock_t)SPINLOCK_INIT;

    /* Truncate if requested */
    if ((flags & O_TRUNC) && vn->ops && vn->ops->truncate) {
        vn->ops->truncate(vn, 0);
    }

    *fp = file;
    return 0;
}

/**
 * vfs_close - Close a file
 */
int vfs_close(struct file *file)
{
    if (!file) {
        return -EINVAL;
    }

    spin_lock(&file->lock);
    file->refcount--;

    if (file->refcount == 0) {
        spin_unlock(&file->lock);

        /* Call close operation if provided */
        if (file->vnode && file->vnode->ops && file->vnode->ops->close) {
            file->vnode->ops->close(file->vnode);
        }

        /* Release vnode */
        if (file->vnode) {
            vnode_put(file->vnode);
        }

        kfree(file);
        return 0;
    }

    spin_unlock(&file->lock);
    return 0;
}

/**
 * vfs_read - Read from a file
 */
ssize_t vfs_read(struct file *file, void *buf, size_t len)
{
    ssize_t ret;

    if (!file || !buf) {
        return -EINVAL;
    }

    struct vnode *vn = file->vnode;
    if (!vn || !vn->ops || !vn->ops->read) {
        return -ENOSYS;
    }

    spin_lock(&file->lock);
    ret = vn->ops->read(vn, buf, len, file->offset);
    if (ret > 0) {
        file->offset += ret;
    }
    spin_unlock(&file->lock);

    return ret;
}

/**
 * vfs_write - Write to a file
 */
ssize_t vfs_write(struct file *file, const void *buf, size_t len)
{
    ssize_t ret;

    if (!file || !buf) {
        return -EINVAL;
    }

    struct vnode *vn = file->vnode;
    if (!vn || !vn->ops || !vn->ops->write) {
        return -ENOSYS;
    }

    spin_lock(&file->lock);

    /* Handle O_APPEND */
    if (file->flags & O_APPEND) {
        file->offset = vn->size;
    }

    ret = vn->ops->write(vn, buf, len, file->offset);
    if (ret > 0) {
        file->offset += ret;
    }
    spin_unlock(&file->lock);

    return ret;
}

/**
 * vfs_seek - Seek in a file
 */
off_t vfs_seek(struct file *file, off_t offset, int whence)
{
    off_t new_offset;

    if (!file) {
        return -EINVAL;
    }

    spin_lock(&file->lock);

    switch (whence) {
    case SEEK_SET:
        new_offset = offset;
        break;
    case SEEK_CUR:
        new_offset = file->offset + offset;
        break;
    case SEEK_END:
        new_offset = file->vnode->size + offset;
        break;
    default:
        spin_unlock(&file->lock);
        return -EINVAL;
    }

    if (new_offset < 0) {
        spin_unlock(&file->lock);
        return -EINVAL;
    }

    file->offset = new_offset;
    spin_unlock(&file->lock);

    return new_offset;
}

/**
 * vfs_stat - Get file status
 */
int vfs_stat(const char *path, struct stat *st)
{
    struct vnode *vn;
    int ret;

    if (!path || !st) {
        return -EINVAL;
    }

    vn = vfs_lookup(path);
    if (!vn) {
        return -ENOENT;
    }

    if (vn->ops && vn->ops->stat) {
        ret = vn->ops->stat(vn, st);
    } else {
        /* Fill in basic info */
        st->st_ino = vn->ino;
        st->st_mode = vn->mode;
        st->st_size = vn->size;
        st->st_uid = vn->uid;
        st->st_gid = vn->gid;
        ret = 0;
    }

    vnode_put(vn);
    return ret;
}

/**
 * vfs_fstat - Get file status by file descriptor
 */
int vfs_fstat(struct file *file, struct stat *st)
{
    if (!file || !st) {
        return -EINVAL;
    }

    struct vnode *vn = file->vnode;
    if (!vn) {
        return -EINVAL;
    }

    if (vn->ops && vn->ops->stat) {
        return vn->ops->stat(vn, st);
    }

    /* Fill in basic info */
    st->st_ino = vn->ino;
    st->st_mode = vn->mode;
    st->st_size = vn->size;
    st->st_uid = vn->uid;
    st->st_gid = vn->gid;
    return 0;
}

/**
 * vfs_mkdir - Create a directory
 */
int vfs_mkdir(const char *path, mode_t mode)
{
    struct vnode *parent;
    char name[CONFIG_NAME_MAX];
    struct mount *mnt;
    int ret;

    if (!path) {
        return -EINVAL;
    }

    parent = vfs_lookup_parent(path, name);
    if (!parent) {
        return -ENOENT;
    }

    mnt = find_mount(path);
    if (!mnt || !mnt->ops->mkdir) {
        vnode_put(parent);
        return -ENOSYS;
    }

    ret = mnt->ops->mkdir(parent, name, mode);
    vnode_put(parent);

    return ret;
}

/**
 * vfs_rmdir - Remove a directory
 */
int vfs_rmdir(const char *path)
{
    struct vnode *parent;
    char name[CONFIG_NAME_MAX];
    struct mount *mnt;
    int ret;

    if (!path) {
        return -EINVAL;
    }

    parent = vfs_lookup_parent(path, name);
    if (!parent) {
        return -ENOENT;
    }

    mnt = find_mount(path);
    if (!mnt || !mnt->ops->rmdir) {
        vnode_put(parent);
        return -ENOSYS;
    }

    ret = mnt->ops->rmdir(parent, name);
    vnode_put(parent);

    return ret;
}

/**
 * vfs_readdir - Read directory entry
 */
int vfs_readdir(struct file *file, struct dirent *ent)
{
    if (!file || !ent) {
        return -EINVAL;
    }

    struct vnode *vn = file->vnode;
    if (!vn || !vn->ops || !vn->ops->readdir) {
        return -ENOSYS;
    }

    spin_lock(&file->lock);
    int ret = vn->ops->readdir(vn, ent, &file->offset);
    spin_unlock(&file->lock);

    return ret;
}

/**
 * vfs_unlink - Delete a file
 */
int vfs_unlink(const char *path)
{
    struct vnode *parent;
    char name[CONFIG_NAME_MAX];
    struct mount *mnt;
    int ret;

    if (!path) {
        return -EINVAL;
    }

    parent = vfs_lookup_parent(path, name);
    if (!parent) {
        return -ENOENT;
    }

    mnt = find_mount(path);
    if (!mnt || !mnt->ops->unlink) {
        vnode_put(parent);
        return -ENOSYS;
    }

    ret = mnt->ops->unlink(parent, name);
    vnode_put(parent);

    return ret;
}

/**
 * vfs_rename - Rename a file
 */
int vfs_rename(const char *oldpath, const char *newpath)
{
    struct vnode *olddir, *newdir;
    char oldname[CONFIG_NAME_MAX], newname[CONFIG_NAME_MAX];
    struct mount *mnt;
    int ret;

    if (!oldpath || !newpath) {
        return -EINVAL;
    }

    olddir = vfs_lookup_parent(oldpath, oldname);
    if (!olddir) {
        return -ENOENT;
    }

    newdir = vfs_lookup_parent(newpath, newname);
    if (!newdir) {
        vnode_put(olddir);
        return -ENOENT;
    }

    /* Must be on same filesystem */
    if (olddir->mount != newdir->mount) {
        vnode_put(olddir);
        vnode_put(newdir);
        return -EXDEV;
    }

    mnt = olddir->mount;
    if (!mnt || !mnt->ops->rename) {
        vnode_put(olddir);
        vnode_put(newdir);
        return -ENOSYS;
    }

    ret = mnt->ops->rename(olddir, oldname, newdir, newname);

    vnode_put(olddir);
    vnode_put(newdir);

    return ret;
}

/**
 * vnode_get - Increment vnode reference count
 */
void vnode_get(struct vnode *vn)
{
    if (vn) {
        spin_lock(&vn->lock);
        vn->refcount++;
        spin_unlock(&vn->lock);
    }
}

/**
 * vnode_put - Decrement vnode reference count
 */
void vnode_put(struct vnode *vn)
{
    if (!vn) {
        return;
    }

    spin_lock(&vn->lock);
    vn->refcount--;

    if (vn->refcount == 0) {
        spin_unlock(&vn->lock);
        /* vnode should be freed by filesystem */
        if (vn->ops && vn->ops->close) {
            vn->ops->close(vn);
        }
        return;
    }

    spin_unlock(&vn->lock);
}
