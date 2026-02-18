/**
 * kernel/fs/sysfs/sysfs.c - Kernel attribute tree filesystem
 *
 * Virtual filesystem exposing kernel object hierarchy at /sys.
 * Tree structure managed by kernel APIs; userspace sees read-only VFS.
 */

#include <kairos/config.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sysfs.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

#define SYSFS_SUPER_MAGIC 0x62656572
#define SYSFS_BUF_SIZE    4096

/* ------------------------------------------------------------------ */
/*  Data structures                                                    */
/* ------------------------------------------------------------------ */

enum sysfs_node_type { SYSFS_DIR, SYSFS_FILE, SYSFS_LINK };

struct sysfs_node {
    struct vnode vn;
    char name[CONFIG_NAME_MAX];
    enum sysfs_node_type type;
    ino_t ino;
    const struct sysfs_attribute *attr;   /* SYSFS_FILE */
    struct sysfs_node *link_target;       /* SYSFS_LINK */
    struct sysfs_node *parent;
    struct list_head children;
    struct list_head sibling;
};

struct sysfs_mount {
    struct sysfs_node *root;
    ino_t next_ino;
    spinlock_t lock;
    struct mount *mnt;
};

/* Global sysfs state — initialized before any mount */
static struct sysfs_mount sysfs_sb;
static struct sysfs_node *sysfs_root_node;
static struct sysfs_node *sysfs_bus_node;
static struct sysfs_node *sysfs_class_node;
static struct sysfs_node *sysfs_devices_node;
static struct sysfs_node *sysfs_kernel_node;

/* Forward declarations */
static struct vnode *sysfs_lookup(struct vnode *dir, const char *name);
static int sysfs_readdir(struct vnode *vn, struct dirent *ent, off_t *off);
static ssize_t sysfs_file_read(struct vnode *vn, void *buf, size_t len,
                                off_t off);
static ssize_t sysfs_file_write(struct vnode *vn, const void *buf, size_t len,
                                 off_t off);
static ssize_t sysfs_link_read(struct vnode *vn, void *buf, size_t len,
                                off_t off);
static int sysfs_close(struct vnode *vn);
static int sysfs_dir_poll(struct vnode *vn, uint32_t events);
static int sysfs_file_poll(struct vnode *vn, uint32_t events);

static struct file_ops sysfs_dir_ops = {
    .readdir = sysfs_readdir,
    .poll = sysfs_dir_poll,
    .close = sysfs_close,
};

static struct file_ops sysfs_file_fops = {
    .read = sysfs_file_read,
    .write = sysfs_file_write,
    .poll = sysfs_file_poll,
    .close = sysfs_close,
};

static struct file_ops sysfs_link_fops = {
    .read = sysfs_link_read,
    .poll = sysfs_file_poll,
    .close = sysfs_close,
};

/* ------------------------------------------------------------------ */
/*  Vnode helpers                                                      */
/* ------------------------------------------------------------------ */

static void sysfs_init_vnode(struct vnode *vn, struct sysfs_node *sn,
                             enum vnode_type type, mode_t mode,
                             struct file_ops *ops) {
    vn->type = type;
    vn->mode = mode;
    vn->uid = 0;
    vn->gid = 0;
    vn->size = 0;
    vn->ino = sn->ino;
    vn->nlink = 1;
    vn->atime = vn->mtime = vn->ctime = 0;
    vn->rdev = 0;
    vn->ops = ops;
    vn->fs_data = sn;
    vn->mount = sysfs_sb.mnt;
    vn->refcount = 1;
    vn->parent = NULL;
    vn->name[0] = '\0';
    mutex_init(&vn->lock, "sysfs_vn");
    poll_wait_head_init(&vn->pollers);
}

static struct sysfs_node *sysfs_find_child(struct sysfs_node *dir,
                                           const char *name) {
    struct sysfs_node *child;
    list_for_each_entry(child, &dir->children, sibling) {
        if (strcmp(child->name, name) == 0)
            return child;
    }
    return NULL;
}

static struct sysfs_node *sysfs_alloc_node(struct sysfs_node *parent,
                                           const char *name,
                                           enum sysfs_node_type type,
                                           mode_t mode) {
    struct sysfs_node *sn = kzalloc(sizeof(*sn));
    if (!sn)
        return NULL;

    strncpy(sn->name, name, CONFIG_NAME_MAX - 1);
    sn->name[CONFIG_NAME_MAX - 1] = '\0';
    sn->type = type;
    sn->ino = sysfs_sb.next_ino++;
    sn->attr = NULL;
    sn->link_target = NULL;
    sn->parent = parent;
    INIT_LIST_HEAD(&sn->children);
    INIT_LIST_HEAD(&sn->sibling);

    enum vnode_type vtype;
    struct file_ops *ops;
    switch (type) {
    case SYSFS_DIR:
        vtype = VNODE_DIR;
        ops = &sysfs_dir_ops;
        break;
    case SYSFS_FILE:
        vtype = VNODE_FILE;
        ops = &sysfs_file_fops;
        break;
    case SYSFS_LINK:
        vtype = VNODE_SYMLINK;
        ops = &sysfs_link_fops;
        break;
    default:
        kfree(sn);
        return NULL;
    }

    sysfs_init_vnode(&sn->vn, sn, vtype, mode, ops);

    if (parent) {
        list_add_tail(&sn->sibling, &parent->children);
        vnode_set_parent(&sn->vn, &parent->vn, sn->name);
    }
    return sn;
}

static void sysfs_free_node(struct sysfs_node *sn) {
    if (!sn)
        return;
    struct sysfs_node *child, *tmp;
    list_for_each_entry_safe(child, tmp, &sn->children, sibling) {
        list_del(&child->sibling);
        sysfs_free_node(child);
    }
    kfree(sn);
}

/* ------------------------------------------------------------------ */
/*  File operations                                                    */
/* ------------------------------------------------------------------ */

static ssize_t sysfs_file_read(struct vnode *vn, void *buf, size_t len,
                                off_t off) {
    struct sysfs_node *sn = vn->fs_data;
    if (!sn || sn->type != SYSFS_FILE || !sn->attr || !sn->attr->show)
        return -EINVAL;

    /* TODO: consider stack buffer or per-node cache to avoid kmalloc per read */
    char *kbuf = kmalloc(SYSFS_BUF_SIZE);
    if (!kbuf)
        return -ENOMEM;

    ssize_t total = sn->attr->show(sn->attr->priv, kbuf, SYSFS_BUF_SIZE);
    if (total < 0) {
        kfree(kbuf);
        return total;
    }

    if (off >= total) {
        kfree(kbuf);
        return 0;
    }
    size_t avail = (size_t)(total - off);
    if (len > avail)
        len = avail;
    memcpy(buf, kbuf + off, len);
    kfree(kbuf);
    return (ssize_t)len;
}

static ssize_t sysfs_file_write(struct vnode *vn, const void *buf, size_t len,
                                 off_t off __attribute__((unused))) {
    struct sysfs_node *sn = vn->fs_data;
    if (!sn || sn->type != SYSFS_FILE || !sn->attr || !sn->attr->store)
        return -EPERM;
    if (!(sn->attr->mode & 0200))
        return -EPERM;
    return sn->attr->store(sn->attr->priv, buf, len);
}

static int sysfs_build_path(struct sysfs_node *node, char *buf, size_t bufsz) {
    /* Collect ancestors up to root */
    struct sysfs_node *chain[32];
    int depth = 0;
    for (struct sysfs_node *n = node; n && n->parent; n = n->parent) {
        if (depth >= 32)
            return -ENAMETOOLONG;
        chain[depth++] = n;
    }
    size_t pos = 0;
    for (int i = depth - 1; i >= 0; i--) {
        size_t nlen = strlen(chain[i]->name);
        if (pos + 1 + nlen >= bufsz)
            return -ENAMETOOLONG;
        buf[pos++] = '/';
        memcpy(buf + pos, chain[i]->name, nlen);
        pos += nlen;
    }
    if (pos == 0 && bufsz > 1) {
        buf[pos++] = '/';
    }
    buf[pos] = '\0';
    return (int)pos;
}

static ssize_t sysfs_link_read(struct vnode *vn, void *buf, size_t len,
                                off_t off) {
    struct sysfs_node *sn = vn->fs_data;
    if (!sn || sn->type != SYSFS_LINK || !sn->link_target)
        return -EINVAL;

    char pathbuf[CONFIG_PATH_MAX];
    int plen = sysfs_build_path(sn->link_target, pathbuf, sizeof(pathbuf));
    if (plen < 0)
        return plen;

    size_t tlen = (size_t)plen;
    if ((size_t)off >= tlen)
        return 0;
    size_t avail = tlen - (size_t)off;
    if (len > avail)
        len = avail;
    memcpy(buf, pathbuf + off, len);
    return (ssize_t)len;
}

static int sysfs_close(struct vnode *vn __attribute__((unused))) {
    return 0;
}

static int sysfs_dir_poll(struct vnode *vn __attribute__((unused)),
                          uint32_t events) {
    return (int)(events & (POLLIN | POLLOUT));
}

static int sysfs_file_poll(struct vnode *vn __attribute__((unused)),
                           uint32_t events) {
    return (int)(events & (POLLIN | POLLOUT));
}

/* ------------------------------------------------------------------ */
/*  Directory operations                                               */
/* ------------------------------------------------------------------ */

static int sysfs_readdir(struct vnode *vn, struct dirent *ent, off_t *off) {
    struct sysfs_node *dir = vn->fs_data;
    if (!dir)
        return -EINVAL;

    spin_lock(&sysfs_sb.lock);
    off_t idx = 0;
    struct sysfs_node *child = NULL;
    struct list_head *pos;
    for (pos = dir->children.next; pos != &dir->children; pos = pos->next) {
        if (idx == *off) {
            child = list_entry(pos, struct sysfs_node, sibling);
            break;
        }
        idx++;
    }
    if (!child) {
        spin_unlock(&sysfs_sb.lock);
        return 0;
    }

    ent->d_ino = child->ino;
    ent->d_off = idx;
    ent->d_reclen = sizeof(*ent);
    if (child->type == SYSFS_DIR)
        ent->d_type = DT_DIR;
    else if (child->type == SYSFS_LINK)
        ent->d_type = DT_LNK;
    else
        ent->d_type = DT_REG;
    strncpy(ent->d_name, child->name, CONFIG_NAME_MAX - 1);
    *off = idx + 1;
    spin_unlock(&sysfs_sb.lock);
    return 1;
}

/* ------------------------------------------------------------------ */
/*  VFS operations                                                     */
/* ------------------------------------------------------------------ */

static struct vnode *sysfs_lookup(struct vnode *dir, const char *name) {
    if (!dir || !name)
        return NULL;
    struct sysfs_node *d = dir->fs_data;
    if (!d)
        return NULL;

    spin_lock(&sysfs_sb.lock);
    struct sysfs_node *child = sysfs_find_child(d, name);
    if (child)
        vnode_get(&child->vn);
    spin_unlock(&sysfs_sb.lock);
    return child ? &child->vn : NULL;
}

static void sysfs_fix_mount_recursive(struct sysfs_node *node,
                                      struct mount *mnt) {
    node->vn.mount = mnt;
    struct sysfs_node *child;
    list_for_each_entry(child, &node->children, sibling)
        sysfs_fix_mount_recursive(child, mnt);
}

static int sysfs_mount_op(struct mount *mnt) {
    sysfs_sb.mnt = mnt;

    /* Update all existing vnodes to point to this mount */
    if (sysfs_root_node)
        sysfs_fix_mount_recursive(sysfs_root_node, mnt);

    mnt->fs_data = &sysfs_sb;
    mnt->root = &sysfs_root_node->vn;
    pr_info("sysfs: mounted\n");
    return 0;
}

static int sysfs_unmount_op(struct mount *mnt __attribute__((unused))) {
    /* sysfs is a singleton; don't free the tree */
    return 0;
}

static int sysfs_statfs_op(struct mount *mnt __attribute__((unused)),
                           struct kstatfs *st) {
    memset(st, 0, sizeof(*st));
    st->f_type = SYSFS_SUPER_MAGIC;
    st->f_bsize = CONFIG_PAGE_SIZE;
    st->f_frsize = CONFIG_PAGE_SIZE;
    st->f_namelen = CONFIG_NAME_MAX;
    return 0;
}

static struct vfs_ops sysfs_vfs_ops = {
    .name = "sysfs",
    .mount = sysfs_mount_op,
    .unmount = sysfs_unmount_op,
    .lookup = sysfs_lookup,
    .statfs = sysfs_statfs_op,
};

static struct fs_type sysfs_type = {
    .name = "sysfs",
    .ops = &sysfs_vfs_ops,
};

/* ------------------------------------------------------------------ */
/*  Kernel API                                                         */
/* ------------------------------------------------------------------ */

struct sysfs_node *sysfs_mkdir(struct sysfs_node *parent, const char *name) {
    if (!parent || !name)
        return NULL;

    spin_lock(&sysfs_sb.lock);
    if (sysfs_find_child(parent, name)) {
        spin_unlock(&sysfs_sb.lock);
        return NULL;
    }
    struct sysfs_node *sn = sysfs_alloc_node(parent, name, SYSFS_DIR,
                                             S_IFDIR | 0555);
    spin_unlock(&sysfs_sb.lock);
    return sn;
}

void sysfs_rmdir(struct sysfs_node *node) {
    if (!node)
        return;
    spin_lock(&sysfs_sb.lock);
    list_del(&node->sibling);
    sysfs_free_node(node);
    spin_unlock(&sysfs_sb.lock);
}

struct sysfs_node *sysfs_create_file(struct sysfs_node *parent,
                                     const struct sysfs_attribute *attr) {
    if (!parent || !attr || !attr->name)
        return NULL;

    spin_lock(&sysfs_sb.lock);
    if (sysfs_find_child(parent, attr->name)) {
        spin_unlock(&sysfs_sb.lock);
        return NULL;
    }
    mode_t mode = S_IFREG | (attr->mode & 07777);
    struct sysfs_node *sn = sysfs_alloc_node(parent, attr->name, SYSFS_FILE,
                                             mode);
    if (sn)
        sn->attr = attr;
    spin_unlock(&sysfs_sb.lock);
    return sn;
}

void sysfs_remove_file(struct sysfs_node *node) {
    if (!node)
        return;
    spin_lock(&sysfs_sb.lock);
    list_del(&node->sibling);
    kfree(node);
    spin_unlock(&sysfs_sb.lock);
}

int sysfs_create_files(struct sysfs_node *parent,
                       const struct sysfs_attribute *attrs, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (!sysfs_create_file(parent, &attrs[i])) {
            /* Rollback previously created files */
            while (i-- > 0) {
                spin_lock(&sysfs_sb.lock);
                struct sysfs_node *f = sysfs_find_child(parent, attrs[i].name);
                if (f) {
                    list_del(&f->sibling);
                    kfree(f);
                }
                spin_unlock(&sysfs_sb.lock);
            }
            return -ENOMEM;
        }
    }
    return 0;
}

struct sysfs_node *sysfs_create_link(struct sysfs_node *parent,
                                     const char *name,
                                     struct sysfs_node *target) {
    if (!parent || !name || !target)
        return NULL;

    spin_lock(&sysfs_sb.lock);
    if (sysfs_find_child(parent, name)) {
        spin_unlock(&sysfs_sb.lock);
        return NULL;
    }
    struct sysfs_node *sn = sysfs_alloc_node(parent, name, SYSFS_LINK,
                                             S_IFLNK | 0777);
    if (sn) {
        sn->link_target = target;
        char pathbuf[CONFIG_PATH_MAX];
        int plen = sysfs_build_path(target, pathbuf, sizeof(pathbuf));
        sn->vn.size = (plen > 0) ? (uint64_t)plen : strlen(target->name);
    }
    spin_unlock(&sysfs_sb.lock);
    return sn;
}

struct sysfs_node *sysfs_root(void) { return sysfs_root_node; }
struct sysfs_node *sysfs_bus_dir(void) { return sysfs_bus_node; }
struct sysfs_node *sysfs_class_dir(void) { return sysfs_class_node; }
struct sysfs_node *sysfs_devices_dir(void) { return sysfs_devices_node; }

/* ------------------------------------------------------------------ */
/*  Initialization                                                     */
/* ------------------------------------------------------------------ */

void sysfs_init(void) {
    sysfs_sb.next_ino = 1;
    spin_init(&sysfs_sb.lock);
    sysfs_sb.mnt = NULL;

    /* Create root node */
    sysfs_root_node = kzalloc(sizeof(*sysfs_root_node));
    if (!sysfs_root_node) {
        pr_err("sysfs: failed to allocate root\n");
        return;
    }
    strncpy(sysfs_root_node->name, "/", CONFIG_NAME_MAX - 1);
    sysfs_root_node->type = SYSFS_DIR;
    /* Single-threaded init context — no lock needed for root ino */
    sysfs_root_node->ino = sysfs_sb.next_ino++;
    sysfs_root_node->parent = NULL;
    INIT_LIST_HEAD(&sysfs_root_node->children);
    INIT_LIST_HEAD(&sysfs_root_node->sibling);
    sysfs_init_vnode(&sysfs_root_node->vn, sysfs_root_node, VNODE_DIR,
                     S_IFDIR | 0555, &sysfs_dir_ops);
    sysfs_sb.root = sysfs_root_node;

    /* Create top-level directories */
    spin_lock(&sysfs_sb.lock);
    sysfs_bus_node = sysfs_alloc_node(sysfs_root_node, "bus", SYSFS_DIR,
                                      S_IFDIR | 0555);
    sysfs_class_node = sysfs_alloc_node(sysfs_root_node, "class", SYSFS_DIR,
                                        S_IFDIR | 0555);
    sysfs_devices_node = sysfs_alloc_node(sysfs_root_node, "devices", SYSFS_DIR,
                                          S_IFDIR | 0555);
    sysfs_kernel_node = sysfs_alloc_node(sysfs_root_node, "kernel", SYSFS_DIR,
                                         S_IFDIR | 0555);
    spin_unlock(&sysfs_sb.lock);

    if (vfs_register_fs(&sysfs_type) < 0)
        pr_err("sysfs: registration failed\n");
    else
        pr_info("sysfs: initialized\n");
}
