/**
 * kernel/fs/initramfs/initramfs.c - initramfs (cpio newc) filesystem
 */

#include <kairos/config.h>
#include <kairos/initramfs.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/vfs.h>

#define INITRAMFS_SUPER_MAGIC 0x01021994
#define CPIO_HDR_LEN 110
#define CPIO_FIELD_SIZE 8
#define CPIO_OFF_INO (6 + CPIO_FIELD_SIZE * 0)
#define CPIO_OFF_MODE (6 + CPIO_FIELD_SIZE * 1)
#define CPIO_OFF_UID (6 + CPIO_FIELD_SIZE * 2)
#define CPIO_OFF_GID (6 + CPIO_FIELD_SIZE * 3)
#define CPIO_OFF_NLINK (6 + CPIO_FIELD_SIZE * 4)
#define CPIO_OFF_MTIME (6 + CPIO_FIELD_SIZE * 5)
#define CPIO_OFF_FILESIZE (6 + CPIO_FIELD_SIZE * 6)
#define CPIO_OFF_RDEVMAJOR (6 + CPIO_FIELD_SIZE * 9)
#define CPIO_OFF_RDEVMINOR (6 + CPIO_FIELD_SIZE * 10)
#define CPIO_OFF_NAMESIZE (6 + CPIO_FIELD_SIZE * 11)

struct initramfs_blob;

struct initramfs_node {
    struct vnode vn;
    char name[CONFIG_NAME_MAX];
    mode_t mode;
    struct initramfs_blob *blob;
    size_t size;
    ino_t ino;
    struct initramfs_node *parent;
    struct list_head children;
    struct list_head sibling;
};

struct initramfs_blob {
    void *data;
    size_t size;
    uint32_t refcount;
};

struct initramfs_ino_map {
    uint32_t ino;
    struct initramfs_node *node;
    struct list_head list;
};

struct initramfs_meta {
    ino_t ino;
    uid_t uid;
    gid_t gid;
    nlink_t nlink;
    uint32_t mtime;
    dev_t rdev;
};

struct initramfs_mount {
    struct initramfs_node *root;
    ino_t next_ino;
    spinlock_t lock;
};

static const void *initramfs_image;
static size_t initramfs_image_size;
static bool initramfs_has_image;
static bool initramfs_mounted;

static struct vnode *initramfs_lookup(struct vnode *dir, const char *name);
static int initramfs_readdir(struct vnode *vn, struct dirent *ent, off_t *off);
static ssize_t initramfs_read(struct vnode *vn, void *buf, size_t len,
                              off_t off);
static int initramfs_mkdir(struct vnode *dir, const char *name, mode_t mode);
static int initramfs_close(struct vnode *vn);
static int initramfs_dir_poll(struct vnode *vn, uint32_t events);
static int initramfs_file_poll(struct vnode *vn, uint32_t events);

static struct file_ops initramfs_dir_ops = {
    .readdir = initramfs_readdir,
    .poll = initramfs_dir_poll,
    .close = initramfs_close,
};

static struct file_ops initramfs_file_ops = {
    .read = initramfs_read,
    .poll = initramfs_file_poll,
    .close = initramfs_close,
};

static void initramfs_init_vnode(struct vnode *vn, struct mount *mnt,
                                 struct initramfs_node *node,
                                 enum vnode_type type, mode_t mode,
                                 struct file_ops *ops) {
    vn->type = type;
    vn->mode = mode;
    vn->uid = 0;
    vn->gid = 0;
    vn->size = node->size;
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
    mutex_init(&vn->lock, "initramfs_vn");
    poll_wait_head_init(&vn->pollers);
}

static void initramfs_apply_meta(struct initramfs_node *node,
                                 const struct initramfs_meta *meta) {
    if (!node || !meta)
        return;
    node->vn.uid = meta->uid;
    node->vn.gid = meta->gid;
    node->vn.nlink = meta->nlink ? meta->nlink : 1;
    node->vn.atime = node->vn.mtime = node->vn.ctime = (time_t)meta->mtime;
    node->vn.rdev = meta->rdev;
}

static struct initramfs_node *initramfs_find_child(struct initramfs_node *dir,
                                                   const char *name) {
    struct initramfs_node *child;
    list_for_each_entry(child, &dir->children, sibling) {
        if (strcmp(child->name, name) == 0)
            return child;
    }
    return NULL;
}

static struct initramfs_node *initramfs_alloc_node(struct initramfs_mount *im,
                                                   struct mount *mnt,
                                                   struct initramfs_node *parent,
                                                   const char *name,
                                                   enum vnode_type type,
                                                   mode_t mode,
                                                   const struct initramfs_meta *meta) {
    struct initramfs_node *node = kzalloc(sizeof(*node));
    if (!node)
        return NULL;
    strncpy(node->name, name, CONFIG_NAME_MAX - 1);
    node->name[CONFIG_NAME_MAX - 1] = '\0';
    node->mode = mode;
    node->size = 0;
    node->blob = NULL;
    if (meta && meta->ino) {
        node->ino = meta->ino;
        if (node->ino >= im->next_ino)
            im->next_ino = node->ino + 1;
    } else {
        node->ino = im->next_ino++;
    }
    node->parent = parent;
    INIT_LIST_HEAD(&node->children);
    INIT_LIST_HEAD(&node->sibling);

    enum vnode_type vtype = type;
    struct file_ops *ops = (type == VNODE_DIR) ? &initramfs_dir_ops
                                               : &initramfs_file_ops;
    initramfs_init_vnode(&node->vn, mnt, node, vtype, mode, ops);
    initramfs_apply_meta(node, meta);
    if (parent) {
        list_add_tail(&node->sibling, &parent->children);
        vnode_set_parent(&node->vn, &parent->vn, node->name);
    }
    return node;
}

static struct initramfs_node *initramfs_ensure_dir(struct initramfs_mount *im,
                                                   struct mount *mnt,
                                                   struct initramfs_node *parent,
                                                   const char *name,
                                                   mode_t mode) {
    struct initramfs_node *child = initramfs_find_child(parent, name);
    if (child) {
        if (child->vn.type != VNODE_DIR)
            return NULL;
        return child;
    }
    mode_t dmode = (mode & S_IFMT) ? mode : (S_IFDIR | 0755);
    if ((dmode & S_IFMT) != S_IFDIR)
        dmode = S_IFDIR | 0755;
    return initramfs_alloc_node(im, mnt, parent, name, VNODE_DIR, dmode, NULL);
}

static bool cpio_parse_u32(const char *p, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 8; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v |= (uint32_t)(c - 'A' + 10);
        else
            return false;
    }
    *out = v;
    return true;
}

static const char *cpio_align4(const char *p) {
    uintptr_t v = (uintptr_t)p;
    v = (v + 3) & ~(uintptr_t)3;
    return (const char *)v;
}

static struct initramfs_blob *initramfs_blob_alloc(const void *data,
                                                   size_t size,
                                                   bool nul_term) {
    size_t alloc = size + (nul_term ? 1 : 0);
    struct initramfs_blob *blob = kzalloc(sizeof(*blob));
    if (!blob)
        return NULL;
    if (alloc > 0) {
        blob->data = kmalloc(alloc);
        if (!blob->data) {
            kfree(blob);
            return NULL;
        }
        if (size > 0)
            memcpy(blob->data, data, size);
        if (nul_term)
            ((char *)blob->data)[size] = '\0';
    }
    blob->size = size;
    blob->refcount = 1;
    return blob;
}

static void initramfs_blob_get(struct initramfs_blob *blob) {
    if (blob)
        blob->refcount++;
}

static void initramfs_blob_put(struct initramfs_blob *blob) {
    if (!blob)
        return;
    if (--blob->refcount == 0) {
        if (blob->data)
            kfree(blob->data);
        kfree(blob);
    }
}

static struct initramfs_node *initramfs_find_inode(struct list_head *map,
                                                   uint32_t ino) {
    struct initramfs_ino_map *ent;
    list_for_each_entry(ent, map, list) {
        if (ent->ino == ino)
            return ent->node;
    }
    return NULL;
}

static int initramfs_map_add(struct list_head *map, uint32_t ino,
                             struct initramfs_node *node) {
    struct initramfs_ino_map *ent = kzalloc(sizeof(*ent));
    if (!ent)
        return -ENOMEM;
    ent->ino = ino;
    ent->node = node;
    INIT_LIST_HEAD(&ent->list);
    list_add_tail(&ent->list, map);
    return 0;
}

static void initramfs_map_free(struct list_head *map) {
    struct initramfs_ino_map *ent, *tmp;
    list_for_each_entry_safe(ent, tmp, map, list) {
        list_del(&ent->list);
        kfree(ent);
    }
}

static const char *initramfs_normalize_path(const char *in, char *out,
                                            size_t outsz) {
    if (!in || !out || outsz == 0)
        return NULL;
    while (in[0] == '/' || (in[0] == '.' && in[1] == '/')) {
        if (in[0] == '/')
            in++;
        else
            in += 2;
    }
    size_t len = strnlen(in, outsz);
    if (len >= outsz)
        return NULL;
    memcpy(out, in, len + 1);
    while (len > 0 && out[len - 1] == '/') {
        out[len - 1] = '\0';
        len--;
    }
    return out;
}

static int initramfs_add_entry(struct initramfs_mount *im, struct mount *mnt,
                               const char *path, mode_t mode, uid_t uid,
                               gid_t gid, uint32_t nlink, uint32_t mtime,
                               uint32_t ino, dev_t rdev, const void *data,
                               size_t size, struct list_head *ino_map) {
    if (!path || !path[0])
        return 0;

    char path_buf[CONFIG_PATH_MAX];
    const char *norm = initramfs_normalize_path(path, path_buf,
                                                sizeof(path_buf));
    if (!norm || !norm[0])
        return 0;
    if (strcmp(norm, ".") == 0 || strcmp(norm, "..") == 0)
        return 0;

    struct initramfs_node *dir = im->root;
    char *p = path_buf;
    while (1) {
        char *slash = strchr(p, '/');
        if (slash)
            *slash = '\0';
        if (p[0] != '\0') {
            if (slash) {
                dir = initramfs_ensure_dir(im, mnt, dir, p, S_IFDIR | 0755);
                if (!dir)
                    return -EINVAL;
            } else {
                break;
            }
        }
        if (!slash)
            break;
        p = slash + 1;
    }

    if (!p[0])
        return 0;

    struct initramfs_meta meta = {
        .ino = ino,
        .uid = uid,
        .gid = gid,
        .nlink = nlink,
        .mtime = mtime,
        .rdev = rdev,
    };

    if ((mode & S_IFMT) == S_IFDIR) {
        struct initramfs_node *existing = initramfs_find_child(dir, p);
        if (existing) {
            existing->mode = mode;
            existing->vn.mode = mode;
            if (meta.ino) {
                existing->ino = meta.ino;
                existing->vn.ino = meta.ino;
                if (existing->ino >= im->next_ino)
                    im->next_ino = existing->ino + 1;
            }
            initramfs_apply_meta(existing, &meta);
            return 0;
        }
        return initramfs_alloc_node(im, mnt, dir, p, VNODE_DIR, mode, &meta)
                   ? 0
                   : -ENOMEM;
    }

    enum vnode_type vtype = VNODE_FILE;
    if ((mode & S_IFMT) == S_IFLNK)
        vtype = VNODE_SYMLINK;
    else if ((mode & S_IFMT) != S_IFREG)
        return 0;

    if (initramfs_find_child(dir, p))
        return 0;

    if (vtype == VNODE_FILE && ino_map && nlink > 1 && ino != 0) {
        struct initramfs_node *link_target = initramfs_find_inode(ino_map, ino);
        if (link_target) {
            if (!link_target->blob && size > 0) {
                struct initramfs_blob *blob =
                    initramfs_blob_alloc(data, size, false);
                if (!blob)
                    return -ENOMEM;
                link_target->blob = blob;
                link_target->size = size;
                link_target->vn.size = size;
            }
            if (link_target->blob) {
                struct initramfs_node *ln =
                    initramfs_alloc_node(im, mnt, dir, p, vtype, mode, &meta);
                if (!ln)
                    return -ENOMEM;
                ln->blob = link_target->blob;
                initramfs_blob_get(ln->blob);
                ln->size = link_target->size;
                ln->vn.size = link_target->size;
                return 0;
            }
        }
    }

    struct initramfs_node *node =
        initramfs_alloc_node(im, mnt, dir, p, vtype, mode, &meta);
    if (!node)
        return -ENOMEM;

    if (size > 0) {
        struct initramfs_blob *blob =
            initramfs_blob_alloc(data, size, vtype == VNODE_SYMLINK);
        if (!blob)
            return -ENOMEM;
        node->blob = blob;
        node->size = size;
        node->vn.size = size;
    }

    if (vtype == VNODE_FILE && ino_map && nlink > 1 && ino != 0) {
        if (!initramfs_find_inode(ino_map, ino))
            initramfs_map_add(ino_map, ino, node);
    }

    return 0;
}

static int initramfs_populate(struct initramfs_mount *im, struct mount *mnt,
                              const void *image, size_t size) {
    const char *p = (const char *)image;
    const char *end = p + size;

    struct list_head ino_map;
    INIT_LIST_HEAD(&ino_map);

    while (p + CPIO_HDR_LEN <= end) {
        if (memcmp(p, "070701", 6) != 0) {
            pr_warn("initramfs: bad cpio magic\n");
            initramfs_map_free(&ino_map);
            return -EINVAL;
        }

        uint32_t ino = 0;
        uint32_t mode = 0;
        uint32_t uid = 0;
        uint32_t gid = 0;
        uint32_t nlink = 0;
        uint32_t mtime = 0;
        uint32_t rdev_major = 0;
        uint32_t rdev_minor = 0;
        uint32_t namesize = 0;
        uint32_t filesize = 0;
        if (!cpio_parse_u32(p + CPIO_OFF_INO, &ino) ||
            !cpio_parse_u32(p + CPIO_OFF_MODE, &mode) ||
            !cpio_parse_u32(p + CPIO_OFF_UID, &uid) ||
            !cpio_parse_u32(p + CPIO_OFF_GID, &gid) ||
            !cpio_parse_u32(p + CPIO_OFF_NLINK, &nlink) ||
            !cpio_parse_u32(p + CPIO_OFF_MTIME, &mtime) ||
            !cpio_parse_u32(p + CPIO_OFF_FILESIZE, &filesize) ||
            !cpio_parse_u32(p + CPIO_OFF_RDEVMAJOR, &rdev_major) ||
            !cpio_parse_u32(p + CPIO_OFF_RDEVMINOR, &rdev_minor) ||
            !cpio_parse_u32(p + CPIO_OFF_NAMESIZE, &namesize)) {
            pr_warn("initramfs: invalid cpio header\n");
            initramfs_map_free(&ino_map);
            return -EINVAL;
        }

        const char *name_start = p + CPIO_HDR_LEN;
        const char *name_end = name_start + namesize;
        if (name_end > end) {
            initramfs_map_free(&ino_map);
            return -EINVAL;
        }

        if (namesize == 0 || namesize >= CONFIG_PATH_MAX) {
            pr_warn("initramfs: invalid name size\n");
            initramfs_map_free(&ino_map);
            return -EINVAL;
        }
        char name_buf[CONFIG_PATH_MAX];
        memcpy(name_buf, name_start, (size_t)namesize);
        name_buf[namesize - 1] = '\0';
        if (strcmp(name_buf, "TRAILER!!!") == 0)
            break;

        const char *data_start = cpio_align4(name_end);
        const char *data_end = data_start + filesize;
        if (data_end > end) {
            initramfs_map_free(&ino_map);
            return -EINVAL;
        }

        dev_t rdev = (dev_t)((rdev_major << 16) | (rdev_minor & 0xFFFF));
        initramfs_add_entry(im, mnt, name_buf, (mode_t)mode, (uid_t)uid,
                            (gid_t)gid, nlink, mtime, ino, rdev, data_start,
                            (size_t)filesize, &ino_map);

        p = cpio_align4(data_end);
    }

    initramfs_map_free(&ino_map);
    return 0;
}

static struct vnode *initramfs_lookup(struct vnode *dir, const char *name) {
    if (!dir || !name)
        return NULL;
    struct initramfs_node *d = dir->fs_data;
    if (!d || dir->type != VNODE_DIR)
        return NULL;
    struct initramfs_mount *im = dir->mount->fs_data;
    if (!im)
        return NULL;

    spin_lock(&im->lock);
    struct initramfs_node *child = initramfs_find_child(d, name);
    if (child)
        vnode_get(&child->vn);
    spin_unlock(&im->lock);
    return child ? &child->vn : NULL;
}

static int initramfs_readdir(struct vnode *vn, struct dirent *ent, off_t *off) {
    if (!vn || !ent || !off)
        return -EINVAL;
    if (vn->type != VNODE_DIR)
        return -ENOTDIR;

    struct initramfs_mount *im = vn->mount->fs_data;
    struct initramfs_node *dir = vn->fs_data;
    if (!im || !dir)
        return -EINVAL;

    spin_lock(&im->lock);
    off_t idx = 0;
    struct initramfs_node *child = NULL;
    struct list_head *pos;
    for (pos = dir->children.next; pos != &dir->children; pos = pos->next) {
        if (idx == *off) {
            child = list_entry(pos, struct initramfs_node, sibling);
            break;
        }
        idx++;
    }

    if (!child) {
        spin_unlock(&im->lock);
        return 0;
    }

    ent->d_ino = child->ino;
    ent->d_off = idx;
    ent->d_reclen = sizeof(*ent);
    if (child->vn.type == VNODE_DIR)
        ent->d_type = DT_DIR;
    else if (child->vn.type == VNODE_SYMLINK)
        ent->d_type = DT_LNK;
    else
        ent->d_type = DT_REG;
    strncpy(ent->d_name, child->name, CONFIG_NAME_MAX - 1);
    *off = idx + 1;

    spin_unlock(&im->lock);
    return 1;
}

static ssize_t initramfs_read(struct vnode *vn, void *buf, size_t len,
                              off_t off) {
    if (!vn || !buf)
        return -EINVAL;
    struct initramfs_node *node = vn->fs_data;
    if (!node)
        return -EINVAL;
    if (vn->type != VNODE_FILE && vn->type != VNODE_SYMLINK)
        return -EINVAL;
    if (!node->blob || (size_t)off >= node->size)
        return 0;
    size_t remain = node->size - (size_t)off;
    size_t tocopy = (len < remain) ? len : remain;
    memcpy(buf, (char *)node->blob->data + off, tocopy);
    return (ssize_t)tocopy;
}

static int initramfs_mkdir(struct vnode *dir, const char *name, mode_t mode) {
    if (!dir || !name || !name[0])
        return -EINVAL;
    if (dir->type != VNODE_DIR)
        return -ENOTDIR;

    struct initramfs_mount *im = dir->mount->fs_data;
    struct initramfs_node *parent = dir->fs_data;
    if (!im || !parent)
        return -EINVAL;

    spin_lock(&im->lock);
    if (initramfs_find_child(parent, name)) {
        spin_unlock(&im->lock);
        return -EEXIST;
    }

    mode_t dmode = (mode & S_IFMT) ? mode : (S_IFDIR | (mode & 0777));
    struct initramfs_meta meta = {
        .ino = 0,
        .uid = 0,
        .gid = 0,
        .nlink = 1,
        .mtime = 0,
        .rdev = 0,
    };
    struct initramfs_node *node =
        initramfs_alloc_node(im, dir->mount, parent, name, VNODE_DIR, dmode,
                             &meta);
    spin_unlock(&im->lock);

    return node ? 0 : -ENOMEM;
}

static int initramfs_close(struct vnode *vn __attribute__((unused))) {
    return 0;
}

static int initramfs_dir_poll(struct vnode *vn __attribute__((unused)),
                              uint32_t events) {
    return (int)(events & (POLLIN | POLLOUT));
}

static int initramfs_file_poll(struct vnode *vn __attribute__((unused)),
                               uint32_t events) {
    return (int)(events & (POLLIN | POLLOUT));
}

static void initramfs_free_node(struct initramfs_node *node) {
    if (!node)
        return;
    struct initramfs_node *child, *tmp;
    list_for_each_entry_safe(child, tmp, &node->children, sibling) {
        list_del(&child->sibling);
        initramfs_free_node(child);
    }
    if (node->blob)
        initramfs_blob_put(node->blob);
    kfree(node);
}

static int initramfs_mount_op(struct mount *mnt) {
    if (!initramfs_has_image || !initramfs_image || initramfs_image_size == 0)
        return -EINVAL;

    struct initramfs_mount *im = kzalloc(sizeof(*im));
    if (!im)
        return -ENOMEM;
    im->next_ino = 1;
    spin_init(&im->lock);

    im->root = kzalloc(sizeof(*im->root));
    if (!im->root) {
        kfree(im);
        return -ENOMEM;
    }

    strncpy(im->root->name, "/", CONFIG_NAME_MAX - 1);
    im->root->name[CONFIG_NAME_MAX - 1] = '\0';
    im->root->ino = im->next_ino++;
    im->root->mode = S_IFDIR | 0755;
    im->root->size = 0;
    im->root->blob = NULL;
    im->root->parent = NULL;
    INIT_LIST_HEAD(&im->root->children);
    INIT_LIST_HEAD(&im->root->sibling);
    initramfs_init_vnode(&im->root->vn, mnt, im->root, VNODE_DIR,
                         im->root->mode, &initramfs_dir_ops);

    int ret = initramfs_populate(im, mnt, initramfs_image,
                                 initramfs_image_size);
    if (ret < 0) {
        initramfs_free_node(im->root);
        kfree(im);
        return ret;
    }

    mnt->fs_data = im;
    mnt->root = &im->root->vn;
    initramfs_mounted = true;
    pr_info("initramfs: mounted\n");
    return 0;
}

static int initramfs_unmount_op(struct mount *mnt) {
    struct initramfs_mount *im = mnt->fs_data;
    if (!im)
        return 0;
    initramfs_free_node(im->root);
    kfree(im);
    initramfs_mounted = false;
    return 0;
}

static int initramfs_statfs(struct mount *mnt __attribute__((unused)),
                            struct kstatfs *st) {
    memset(st, 0, sizeof(*st));
    st->f_type = INITRAMFS_SUPER_MAGIC;
    st->f_bsize = CONFIG_PAGE_SIZE;
    st->f_frsize = CONFIG_PAGE_SIZE;
    st->f_namelen = CONFIG_NAME_MAX;
    return 0;
}

static struct vfs_ops initramfs_vfs_ops = {
    .name = "initramfs",
    .mount = initramfs_mount_op,
    .unmount = initramfs_unmount_op,
    .lookup = initramfs_lookup,
    .mkdir = initramfs_mkdir,
    .statfs = initramfs_statfs,
};

static struct fs_type initramfs_type = {
    .name = "initramfs",
    .ops = &initramfs_vfs_ops,
};

void initramfs_init(void) {
    if (vfs_register_fs(&initramfs_type) < 0)
        pr_err("initramfs: registration failed\n");
    else
        pr_info("initramfs: initialized\n");
}

void initramfs_set_image(const void *addr, size_t size) {
    initramfs_image = addr;
    initramfs_image_size = size;
    initramfs_has_image = true;
}

bool initramfs_available(void) {
    return initramfs_mounted;
}
