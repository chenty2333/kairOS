/**
 * kernel/fs/devfs/devfs.c - Device File System
 */

#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

/* Device types */
#define DEVFS_NULL 1
#define DEVFS_ZERO 2
#define DEVFS_CONSOLE 3

struct devfs_node {
    char name[CONFIG_NAME_MAX];
    ino_t ino;
    int dev_type;
    struct vnode vn;
    struct devfs_node *next;
};

struct devfs_mount {
    struct devfs_node *root;
    struct devfs_node *devices;
    ino_t next_ino;
    spinlock_t lock;
};

static struct vnode *devfs_lookup(struct vnode *dir, const char *name);
static ssize_t devfs_dev_read(struct vnode *vn, void *buf, size_t len,
                              off_t offset);
static ssize_t devfs_dev_write(struct vnode *vn, const void *buf, size_t len,
                               off_t offset);
static int devfs_dev_close(struct vnode *vn);
static int devfs_readdir(struct vnode *vn, struct dirent *ent, off_t *offset);

static struct file_ops devfs_dev_ops = {
    .read = devfs_dev_read,
    .write = devfs_dev_write,
    .close = devfs_dev_close,
};

static struct file_ops devfs_dir_ops = {
    .close = devfs_dev_close,
    .readdir = devfs_readdir,
};

static void devfs_init_vnode(struct vnode *vn, struct mount *mnt,
                             struct devfs_node *node, enum vnode_type type,
                             int mode, struct file_ops *ops) {
    vn->type = type;
    vn->mode = mode;
    vn->uid = vn->gid = vn->size = 0;
    vn->ino = node->ino;
    vn->ops = ops;
    vn->fs_data = node;
    vn->mount = mnt;
    vn->refcount = 1;
    spin_init(&vn->lock);
}

static struct devfs_node *devfs_create_device(struct devfs_mount *dm,
                                              struct mount *mnt,
                                              const char *name, int type) {
    struct devfs_node *node = kzalloc(sizeof(*node));
    if (!node)
        return NULL;

    strncpy(node->name, name, CONFIG_NAME_MAX - 1);
    node->ino = dm->next_ino++;
    node->dev_type = type;
    node->next = dm->devices;
    dm->devices = node;

    devfs_init_vnode(&node->vn, mnt, node, VNODE_DEVICE, S_IFCHR | 0666,
                     &devfs_dev_ops);
    return node;
}

static int devfs_mount(struct mount *mnt) {
    struct devfs_mount *dm = kzalloc(sizeof(*dm));
    if (!dm)
        return -ENOMEM;

    dm->next_ino = 1;
    spin_init(&dm->lock);

    if (!(dm->root = kzalloc(sizeof(*dm->root)))) {
        kfree(dm);
        return -ENOMEM;
    }

    dm->root->ino = dm->next_ino++;
    devfs_init_vnode(&dm->root->vn, mnt, dm->root, VNODE_DIR, S_IFDIR | 0755,
                     &devfs_dir_ops);

    devfs_create_device(dm, mnt, "null", DEVFS_NULL);
    devfs_create_device(dm, mnt, "zero", DEVFS_ZERO);
    devfs_create_device(dm, mnt, "console", DEVFS_CONSOLE);

    mnt->fs_data = dm;
    mnt->root = &dm->root->vn;
    pr_info("devfs: mounted (null, zero, console)\n");
    return 0;
}

static int devfs_unmount(struct mount *mnt) {
    struct devfs_mount *dm = mnt->fs_data;
    if (!dm)
        return 0;

    struct devfs_node *node = dm->devices;
    while (node) {
        struct devfs_node *next = node->next;
        kfree(node);
        node = next;
    }
    kfree(dm->root);
    kfree(dm);
    return 0;
}

static struct vnode *devfs_lookup(struct vnode *dir, const char *name) {
    struct devfs_mount *dm = dir->mount->fs_data;
    if (dir->fs_data != dm->root)
        return NULL;

    spin_lock(&dm->lock);
    for (struct devfs_node *n = dm->devices; n; n = n->next) {
        if (strcmp(n->name, name) == 0) {
            vnode_get(&n->vn);
            spin_unlock(&dm->lock);
            return &n->vn;
        }
    }
    spin_unlock(&dm->lock);
    return NULL;
}

static ssize_t devfs_dev_read(struct vnode *vn, void *buf, size_t len,
                              off_t off __attribute__((unused))) {
    struct devfs_node *node = vn->fs_data;
    if (!node || !buf)
        return -EINVAL;

    switch (node->dev_type) {
    case DEVFS_NULL:
        return 0;
    case DEVFS_ZERO:
        memset(buf, 0, len);
        return (ssize_t)len;
    default:
        return -ENOSYS;
    }
}

static ssize_t devfs_dev_write(struct vnode *vn, const void *buf, size_t len,
                               off_t off __attribute__((unused))) {
    struct devfs_node *node = vn->fs_data;
    if (!node || !buf)
        return -EINVAL;

    if (node->dev_type == DEVFS_CONSOLE) {
        const char *p = buf;
        for (size_t i = 0; i < len; i++)
            arch_early_putchar(p[i]);
    }
    return (ssize_t)len;
}

static int devfs_dev_close(struct vnode *vn __attribute__((unused))) {
    return 0;
}

static int devfs_readdir(struct vnode *vn, struct dirent *ent, off_t *offset) {
    struct devfs_mount *dm = vn->mount->fs_data;
    if (vn->fs_data != dm->root)
        return -ENOTDIR;

    spin_lock(&dm->lock);
    struct devfs_node *n = dm->devices;
    off_t idx = 0;
    while (n && idx < *offset) {
        n = n->next;
        idx++;
    }

    if (!n) {
        spin_unlock(&dm->lock);
        return 0;
    }

    ent->d_ino = n->ino;
    ent->d_off = idx;
    ent->d_reclen = sizeof(*ent);
    ent->d_type = DT_CHR;
    strncpy(ent->d_name, n->name, CONFIG_NAME_MAX - 1);
    *offset = idx + 1;

    spin_unlock(&dm->lock);
    return 1;
}

static struct vfs_ops devfs_vfs_ops = {
    .name = "devfs",
    .mount = devfs_mount,
    .unmount = devfs_unmount,
    .lookup = devfs_lookup,
};

static struct fs_type devfs_type = {
    .name = "devfs",
    .ops = &devfs_vfs_ops,
};

void devfs_init(void) {
    if (vfs_register_fs(&devfs_type) < 0)
        pr_err("devfs: reg failed\n");
    else
        pr_info("devfs: initialized\n");
}