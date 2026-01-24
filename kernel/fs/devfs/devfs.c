/**
 * devfs.c - Device File System
 *
 * Provides /dev/null, /dev/zero, /dev/console and other device files.
 * This is a simple in-memory filesystem.
 */

#include <kairos/vfs.h>
#include <kairos/printk.h>
#include <kairos/mm.h>
#include <kairos/arch.h>
#include <kairos/types.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>

/* Device types */
#define DEVFS_NULL      1
#define DEVFS_ZERO      2
#define DEVFS_CONSOLE   3

/* Device node structure */
struct devfs_node {
    char name[CONFIG_NAME_MAX];
    ino_t ino;
    int dev_type;
    struct vnode vn;
    struct devfs_node *next;
};

/* devfs mount data */
struct devfs_mount {
    struct devfs_node *root;
    struct devfs_node *devices;
    ino_t next_ino;
    spinlock_t lock;
};

/* Forward declarations */
static struct vnode *devfs_lookup(struct vnode *dir, const char *name);
static ssize_t devfs_dev_read(struct vnode *vn, void *buf, size_t len, off_t offset);
static ssize_t devfs_dev_write(struct vnode *vn, const void *buf, size_t len, off_t offset);
static int devfs_dev_close(struct vnode *vn);
static int devfs_readdir(struct vnode *vn, struct dirent *ent, off_t *offset);

/* Device file operations */
static struct file_ops devfs_dev_ops = {
    .read = devfs_dev_read,
    .write = devfs_dev_write,
    .close = devfs_dev_close,
    .readdir = NULL,
};

/* Directory operations */
static struct file_ops devfs_dir_ops = {
    .read = NULL,
    .write = NULL,
    .close = devfs_dev_close,
    .readdir = devfs_readdir,
};

/**
 * devfs_create_device - Create a device node
 */
static struct devfs_node *devfs_create_device(struct devfs_mount *dm,
                                               const char *name, int dev_type)
{
    struct devfs_node *node = kmalloc(sizeof(*node));
    if (!node) {
        return NULL;
    }

    strncpy(node->name, name, CONFIG_NAME_MAX - 1);
    node->name[CONFIG_NAME_MAX - 1] = '\0';
    node->ino = dm->next_ino++;
    node->dev_type = dev_type;
    node->next = dm->devices;
    dm->devices = node;

    /* Initialize vnode */
    node->vn.type = VNODE_DEVICE;
    node->vn.mode = S_IFCHR | 0666;
    node->vn.uid = 0;
    node->vn.gid = 0;
    node->vn.size = 0;
    node->vn.ino = node->ino;
    node->vn.ops = &devfs_dev_ops;
    node->vn.fs_data = node;
    node->vn.mount = NULL;  /* Set during mount */
    node->vn.refcount = 1;
    node->vn.lock = (spinlock_t)SPINLOCK_INIT;

    return node;
}

/**
 * devfs_mount - Mount devfs
 */
static int devfs_mount(struct mount *mnt)
{
    struct devfs_mount *dm;

    /* Allocate mount data */
    dm = kzalloc(sizeof(*dm));
    if (!dm) {
        return -ENOMEM;
    }

    dm->next_ino = 1;
    dm->lock = (spinlock_t)SPINLOCK_INIT;

    /* Create root directory node */
    dm->root = kmalloc(sizeof(*dm->root));
    if (!dm->root) {
        kfree(dm);
        return -ENOMEM;
    }

    dm->root->name[0] = '\0';
    dm->root->ino = dm->next_ino++;
    dm->root->dev_type = 0;
    dm->root->next = NULL;

    /* Initialize root vnode */
    dm->root->vn.type = VNODE_DIR;
    dm->root->vn.mode = S_IFDIR | 0755;
    dm->root->vn.uid = 0;
    dm->root->vn.gid = 0;
    dm->root->vn.size = 0;
    dm->root->vn.ino = dm->root->ino;
    dm->root->vn.ops = &devfs_dir_ops;
    dm->root->vn.fs_data = dm->root;
    dm->root->vn.mount = mnt;
    dm->root->vn.refcount = 1;
    dm->root->vn.lock = (spinlock_t)SPINLOCK_INIT;

    /* Create standard devices */
    struct devfs_node *dev;

    dev = devfs_create_device(dm, "null", DEVFS_NULL);
    if (dev) {
        dev->vn.mount = mnt;
    }

    dev = devfs_create_device(dm, "zero", DEVFS_ZERO);
    if (dev) {
        dev->vn.mount = mnt;
    }

    dev = devfs_create_device(dm, "console", DEVFS_CONSOLE);
    if (dev) {
        dev->vn.mount = mnt;
    }

    mnt->fs_data = dm;
    mnt->root = &dm->root->vn;

    pr_info("devfs: mounted with devices: null, zero, console\n");
    return 0;
}

/**
 * devfs_unmount - Unmount devfs
 */
static int devfs_unmount(struct mount *mnt)
{
    struct devfs_mount *dm = mnt->fs_data;
    if (!dm) {
        return 0;
    }

    /* Free all device nodes */
    struct devfs_node *node = dm->devices;
    while (node) {
        struct devfs_node *next = node->next;
        kfree(node);
        node = next;
    }

    /* Free root */
    if (dm->root) {
        kfree(dm->root);
    }

    kfree(dm);
    return 0;
}

/**
 * devfs_lookup - Look up a file in devfs
 */
static struct vnode *devfs_lookup(struct vnode *dir, const char *name)
{
    struct devfs_node *dir_node = dir->fs_data;
    struct devfs_mount *dm = dir->mount->fs_data;

    if (!dir_node || !dm) {
        return NULL;
    }

    /* Only root directory is supported */
    if (dir_node != dm->root) {
        return NULL;
    }

    /* Search for device */
    spin_lock(&dm->lock);
    struct devfs_node *node = dm->devices;
    while (node) {
        if (strcmp(node->name, name) == 0) {
            vnode_get(&node->vn);
            spin_unlock(&dm->lock);
            return &node->vn;
        }
        node = node->next;
    }
    spin_unlock(&dm->lock);

    return NULL;
}

/**
 * devfs_dev_read - Read from a device
 */
static ssize_t devfs_dev_read(struct vnode *vn, void *buf, size_t len, off_t offset)
{
    struct devfs_node *node = vn->fs_data;
    (void)offset;  /* Devices ignore offset */

    if (!node || !buf) {
        return -EINVAL;
    }

    switch (node->dev_type) {
    case DEVFS_NULL:
        /* /dev/null always returns EOF */
        return 0;

    case DEVFS_ZERO:
        /* /dev/zero returns zeros */
        memset(buf, 0, len);
        return (ssize_t)len;

    case DEVFS_CONSOLE:
        /* /dev/console: reading not implemented yet */
        return -ENOSYS;

    default:
        return -EINVAL;
    }
}

/**
 * devfs_dev_write - Write to a device
 */
static ssize_t devfs_dev_write(struct vnode *vn, const void *buf, size_t len, off_t offset)
{
    struct devfs_node *node = vn->fs_data;
    (void)offset;  /* Devices ignore offset */

    if (!node || !buf) {
        return -EINVAL;
    }

    switch (node->dev_type) {
    case DEVFS_NULL:
        /* /dev/null discards all writes */
        return (ssize_t)len;

    case DEVFS_ZERO:
        /* /dev/zero discards all writes */
        return (ssize_t)len;

    case DEVFS_CONSOLE:
        /* /dev/console: write to console */
        {
            const char *p = buf;
            for (size_t i = 0; i < len; i++) {
                arch_early_putchar(p[i]);
            }
            return (ssize_t)len;
        }

    default:
        return -EINVAL;
    }
}

/**
 * devfs_dev_close - Close a device
 */
static int devfs_dev_close(struct vnode *vn)
{
    /* Devices don't need special close handling */
    (void)vn;
    return 0;
}

/**
 * devfs_readdir - Read directory entries
 */
static int devfs_readdir(struct vnode *vn, struct dirent *ent, off_t *offset)
{
    struct devfs_node *dir_node = vn->fs_data;
    struct devfs_mount *dm = vn->mount->fs_data;

    if (!dir_node || !dm || !ent || !offset) {
        return -EINVAL;
    }

    /* Only root directory is supported */
    if (dir_node != dm->root) {
        return -ENOTDIR;
    }

    spin_lock(&dm->lock);

    /* Find the device at the current offset */
    struct devfs_node *node = dm->devices;
    off_t idx = 0;

    while (node && idx < *offset) {
        node = node->next;
        idx++;
    }

    if (!node) {
        spin_unlock(&dm->lock);
        return 0;  /* End of directory */
    }

    /* Fill in directory entry */
    ent->d_ino = node->ino;
    ent->d_off = idx;
    ent->d_reclen = sizeof(*ent);
    ent->d_type = DT_CHR;
    strncpy(ent->d_name, node->name, CONFIG_NAME_MAX - 1);
    ent->d_name[CONFIG_NAME_MAX - 1] = '\0';

    *offset = idx + 1;

    spin_unlock(&dm->lock);
    return 1;  /* Success, entry filled */
}

/* VFS operations for devfs */
static struct vfs_ops devfs_vfs_ops = {
    .name = "devfs",
    .mount = devfs_mount,
    .unmount = devfs_unmount,
    .lookup = devfs_lookup,
    .create = NULL,  /* devfs is read-only */
    .mkdir = NULL,
    .unlink = NULL,
    .rmdir = NULL,
    .rename = NULL,
    .symlink = NULL,
    .readlink = NULL,
    .sync = NULL,
};

/* File system type structure */
static struct fs_type devfs_type = {
    .name = "devfs",
    .ops = &devfs_vfs_ops,
};

/**
 * devfs_init - Initialize devfs
 */
void devfs_init(void)
{
    int ret = vfs_register_fs(&devfs_type);
    if (ret < 0) {
        pr_err("devfs: failed to register: %d\n", ret);
        return;
    }

    pr_info("devfs: initialized\n");
}
