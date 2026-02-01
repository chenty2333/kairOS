/**
 * kernel/fs/devfs/devfs.c - Device File System
 */

#include <kairos/blkdev.h>
#include <kairos/console.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/ioctl.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

/* Device types */
#define DEVFS_NULL 1
#define DEVFS_ZERO 2
#define DEVFS_CONSOLE 3
#define DEVFS_BLOCK 4
#define DEVFS_CUSTOM 5

struct devfs_node {
    char name[CONFIG_NAME_MAX];
    ino_t ino;
    int dev_type;
    struct blkdev *blk;
    struct file_ops *ops;
    void *priv;
    struct vnode vn;
    struct devfs_node *next;
};

struct devfs_mount {
    struct devfs_node *root;
    struct devfs_node *devices;
    ino_t next_ino;
    spinlock_t lock;
};

struct devfs_add_ctx {
    struct devfs_mount *dm;
    struct mount *mnt;
};

struct devfs_custom_reg {
    char name[CONFIG_NAME_MAX];
    struct file_ops *ops;
    void *priv;
    struct devfs_custom_reg *next;
};

static struct devfs_mount *devfs_active;
static struct devfs_custom_reg *devfs_registry;
static spinlock_t devfs_global_lock = SPINLOCK_INIT;

static struct vnode *devfs_lookup(struct vnode *dir, const char *name);
static ssize_t devfs_dev_read(struct vnode *vn, void *buf, size_t len,
                              off_t offset);
static ssize_t devfs_dev_write(struct vnode *vn, const void *buf, size_t len,
                               off_t offset);
static int devfs_dev_close(struct vnode *vn);
static int devfs_readdir(struct vnode *vn, struct dirent *ent, off_t *offset);
static int devfs_dev_poll(struct vnode *vn, uint32_t events);
static int devfs_dir_poll(struct vnode *vn, uint32_t events);
static int devfs_dev_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg);

static struct file_ops devfs_dev_ops = {
    .read = devfs_dev_read,
    .write = devfs_dev_write,
    .close = devfs_dev_close,
    .ioctl = devfs_dev_ioctl,
    .poll = devfs_dev_poll,
};

static struct file_ops devfs_dir_ops = {
    .close = devfs_dev_close,
    .readdir = devfs_readdir,
    .poll = devfs_dir_poll,
};

static void devfs_init_vnode(struct vnode *vn, struct mount *mnt,
                             struct devfs_node *node, enum vnode_type type,
                             int mode, struct file_ops *ops) {
    vn->type = type;
    vn->mode = mode;
    vn->uid = vn->gid = vn->size = 0;
    vn->ino = node->ino;
    vn->nlink = 1;
    vn->atime = vn->mtime = vn->ctime = 0;
    vn->rdev = 0;
    vn->ops = ops;
    vn->fs_data = node;
    vn->mount = mnt;
    vn->refcount = 1;
    vn->parent = NULL;
    vn->name[0] = '\0';
    mutex_init(&vn->lock, "devfs_vnode");
    poll_wait_head_init(&vn->pollers);
}

static struct devfs_node *devfs_create_custom(struct devfs_mount *dm,
                                              struct mount *mnt,
                                              const char *name,
                                              struct file_ops *ops,
                                              void *priv) {
    struct devfs_node *node = kzalloc(sizeof(*node));
    if (!node)
        return NULL;

    strncpy(node->name, name, CONFIG_NAME_MAX - 1);
    node->ino = dm->next_ino++;
    node->dev_type = DEVFS_CUSTOM;
    node->blk = NULL;
    node->ops = ops;
    node->priv = priv;
    node->next = dm->devices;
    dm->devices = node;

    devfs_init_vnode(&node->vn, mnt, node, VNODE_DEVICE, S_IFCHR | 0666,
                     &devfs_dev_ops);
    return node;
}

static struct devfs_node *devfs_create_device(struct devfs_mount *dm,
                                              struct mount *mnt,
                                              const char *name, int type,
                                              struct blkdev *blk) {
    struct devfs_node *node = kzalloc(sizeof(*node));
    if (!node)
        return NULL;

    strncpy(node->name, name, CONFIG_NAME_MAX - 1);
    node->ino = dm->next_ino++;
    node->dev_type = type;
    node->blk = blk;
    node->ops = NULL;
    node->priv = NULL;
    node->next = dm->devices;
    dm->devices = node;

    mode_t mode = (type == DEVFS_BLOCK) ? (S_IFBLK | 0666) : (S_IFCHR | 0666);
    devfs_init_vnode(&node->vn, mnt, node, VNODE_DEVICE, mode,
                     &devfs_dev_ops);
    if (type == DEVFS_CONSOLE)
        console_attach_vnode(&node->vn);
    return node;
}

static void devfs_add_blkdev(struct blkdev *dev, void *arg) {
    struct devfs_add_ctx *ctx = (struct devfs_add_ctx *)arg;
    if (!ctx || !ctx->dm || !ctx->mnt)
        return;
    devfs_create_device(ctx->dm, ctx->mnt, dev->name, DEVFS_BLOCK, dev);
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

    devfs_create_device(dm, mnt, "null", DEVFS_NULL, NULL);
    devfs_create_device(dm, mnt, "zero", DEVFS_ZERO, NULL);
    devfs_create_device(dm, mnt, "console", DEVFS_CONSOLE, NULL);

    struct devfs_add_ctx ctx = {.dm = dm, .mnt = mnt};
    blkdev_for_each(devfs_add_blkdev, &ctx);

    spin_lock(&devfs_global_lock);
    devfs_active = dm;
    struct devfs_custom_reg *reg = devfs_registry;
    while (reg) {
        devfs_create_custom(dm, mnt, reg->name, reg->ops, reg->priv);
        reg = reg->next;
    }
    spin_unlock(&devfs_global_lock);

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

    if (len == 0)
        return 0;

    switch (node->dev_type) {
    case DEVFS_CUSTOM:
        if (node->ops && node->ops->read)
            return node->ops->read(vn, buf, len, off);
        return -ENOSYS;
    case DEVFS_NULL:
        return 0;
    case DEVFS_ZERO:
        memset(buf, 0, len);
        return (ssize_t)len;
    case DEVFS_CONSOLE:
        return console_read(vn, buf, len, 0);
    default:
        return -ENOSYS;
    }
}

static ssize_t devfs_dev_write(struct vnode *vn, const void *buf, size_t len,
                               off_t off __attribute__((unused))) {
    struct devfs_node *node = vn->fs_data;
    if (!node || !buf)
        return -EINVAL;

    if (node->dev_type == DEVFS_CUSTOM) {
        if (node->ops && node->ops->write)
            return node->ops->write(vn, buf, len, off);
        return -ENOSYS;
    }

    if (node->dev_type == DEVFS_CONSOLE)
        return console_write(vn, buf, len, off);
    return (ssize_t)len;
}

static int devfs_dev_close(struct vnode *vn __attribute__((unused))) {
    return 0;
}

static int devfs_dev_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg) {
    struct devfs_node *node = vn ? (struct devfs_node *)vn->fs_data : NULL;
    if (!node)
        return -EINVAL;
    if (node->dev_type == DEVFS_CUSTOM) {
        if (node->ops && node->ops->ioctl)
            return node->ops->ioctl(vn, cmd, arg);
        return -ENOSYS;
    }
    if (node->dev_type == DEVFS_BLOCK) {
        if (!arg)
            return -EFAULT;
        if (!node->blk)
            return -ENODEV;
        switch (cmd) {
        case BLKGETSIZE64: {
            uint64_t size = node->blk->sector_count * node->blk->sector_size;
            if (copy_to_user((void *)arg, &size, sizeof(size)) < 0)
                return -EFAULT;
            return 0;
        }
        case BLKGETSIZE: {
            uint64_t sectors =
                (node->blk->sector_count * node->blk->sector_size) / 512;
            if (copy_to_user((void *)arg, &sectors, sizeof(sectors)) < 0)
                return -EFAULT;
            return 0;
        }
        case BLKROGET: {
            int ro = 0;
            if (copy_to_user((void *)arg, &ro, sizeof(ro)) < 0)
                return -EFAULT;
            return 0;
        }
        case BLKSSZGET: {
            uint32_t sz = node->blk->sector_size;
            if (copy_to_user((void *)arg, &sz, sizeof(sz)) < 0)
                return -EFAULT;
            return 0;
        }
        default:
            return -ENOTTY;
        }
    }
    if (node->dev_type == DEVFS_CONSOLE)
        return console_ioctl(vn, cmd, arg);
    return -ENOTTY;
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
    ent->d_type = (n->dev_type == DEVFS_BLOCK) ? DT_BLK : DT_CHR;
    strncpy(ent->d_name, n->name, CONFIG_NAME_MAX - 1);
    *offset = idx + 1;

    spin_unlock(&dm->lock);
    return 1;
}

static int devfs_dev_poll(struct vnode *vn, uint32_t events) {
    struct devfs_node *node = vn ? (struct devfs_node *)vn->fs_data : NULL;
    if (!node)
        return POLLNVAL;

    uint32_t revents = 0;
    switch (node->dev_type) {
    case DEVFS_CONSOLE:
        return console_poll(vn, events);
    case DEVFS_NULL:
    case DEVFS_ZERO:
    case DEVFS_BLOCK:
        revents |= POLLIN | POLLOUT;
        break;
    case DEVFS_CUSTOM:
        if (node->ops && node->ops->poll)
            return node->ops->poll(vn, events);
        revents |= POLLIN | POLLOUT;
        break;
    default:
        revents |= POLLERR;
        break;
    }
    return (int)(revents & events);
}

static int devfs_dir_poll(struct vnode *vn __attribute__((unused)),
                          uint32_t events) {
    return (int)(events & (POLLIN | POLLOUT));
}

static int devfs_statfs(struct mount *mnt __attribute__((unused)),
                        struct kstatfs *st) {
    memset(st, 0, sizeof(*st));
    st->f_type = 0x1373;
    st->f_bsize = CONFIG_PAGE_SIZE;
    st->f_frsize = CONFIG_PAGE_SIZE;
    st->f_namelen = CONFIG_NAME_MAX;
    return 0;
}

static struct vfs_ops devfs_vfs_ops = {
    .name = "devfs",
    .mount = devfs_mount,
    .unmount = devfs_unmount,
    .lookup = devfs_lookup,
    .statfs = devfs_statfs,
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

static const char *devfs_basename(const char *path) {
    if (!path)
        return NULL;
    const char *last = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/')
            last = p + 1;
    }
    return *last ? last : path;
}

int devfs_register_node(const char *path, struct file_ops *ops, void *priv) {
    const char *name = devfs_basename(path);
    if (!name || !name[0])
        return -EINVAL;

    spin_lock(&devfs_global_lock);
    struct devfs_custom_reg *reg = devfs_registry;
    while (reg) {
        if (strcmp(reg->name, name) == 0) {
            reg->ops = ops;
            reg->priv = priv;
            break;
        }
        reg = reg->next;
    }
    if (!reg) {
        reg = kzalloc(sizeof(*reg));
        if (!reg) {
            spin_unlock(&devfs_global_lock);
            return -ENOMEM;
        }
        strncpy(reg->name, name, CONFIG_NAME_MAX - 1);
        reg->ops = ops;
        reg->priv = priv;
        reg->next = devfs_registry;
        devfs_registry = reg;
    }

    struct devfs_mount *dm = devfs_active;
    spin_unlock(&devfs_global_lock);

    if (dm) {
        spin_lock(&dm->lock);
        struct devfs_node *node =
            devfs_create_custom(dm, dm->root->vn.mount, name, ops, priv);
        spin_unlock(&dm->lock);
        return node ? 0 : -ENOMEM;
    }

    return 0;
}

int devfs_register_dir(const char *path) {
    (void)path;
    return 0;
}

void *devfs_get_priv(struct vnode *vn) {
    struct devfs_node *node = vn ? (struct devfs_node *)vn->fs_data : NULL;
    return node ? node->priv : NULL;
}
