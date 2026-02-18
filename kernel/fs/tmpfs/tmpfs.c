/**
 * kernel/fs/tmpfs/tmpfs.c - Temporary memory filesystem
 *
 * Writable in-memory filesystem for /tmp, /run, /dev/shm.
 * Data stored as page-granularity arrays with sparse hole support.
 */

#include <kairos/config.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/time.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

#define TMPFS_SUPER_MAGIC  0x01021994
#define TMPFS_MAX_BYTES    (16 * 1024 * 1024)
#define TMPFS_MAX_INODES   4096

/* ------------------------------------------------------------------ */
/*  Data structures                                                    */
/* ------------------------------------------------------------------ */

struct tmpfs_node {
    struct vnode vn;
    char name[CONFIG_NAME_MAX];

    /* File data (VNODE_FILE) — page array, 0 = hole */
    paddr_t *pages;
    size_t pages_cap;
    size_t size;

    /* Symlink target */
    char *symlink_target;

    /* Directory tree */
    struct tmpfs_node *parent;
    struct list_head children;
    struct list_head sibling;
};

struct tmpfs_mount {
    struct tmpfs_node *root;
    ino_t next_ino;
    spinlock_t lock;
    size_t max_bytes;
    size_t used_bytes;
    size_t max_inodes;
    size_t used_inodes;
};

/* Forward declarations */
static struct vnode *tmpfs_lookup(struct vnode *dir, const char *name);
static int tmpfs_create(struct vnode *dir, const char *name, mode_t mode);
static int tmpfs_mkdir_op(struct vnode *dir, const char *name, mode_t mode);
static int tmpfs_symlink_op(struct vnode *dir, const char *name,
                            const char *target);
static int tmpfs_mknod_op(struct vnode *dir, const char *name, mode_t mode,
                          dev_t dev);
static int tmpfs_unlink_op(struct vnode *dir, const char *name);
static int tmpfs_rmdir_op(struct vnode *dir, const char *name);
static int tmpfs_rename_op(struct vnode *odir, const char *oname,
                           struct vnode *ndir, const char *nname);
static int tmpfs_chmod_op(struct vnode *vn, mode_t mode);
static int tmpfs_chown_op(struct vnode *vn, uid_t uid, gid_t gid);
static int tmpfs_utimes_op(struct vnode *vn, const struct timespec *atime,
                           const struct timespec *mtime);

static int tmpfs_readdir(struct vnode *vn, struct dirent *ent, off_t *off);
static ssize_t tmpfs_read(struct vnode *vn, void *buf, size_t len, off_t off);
static ssize_t tmpfs_write(struct vnode *vn, const void *buf, size_t len,
                           off_t off);
static int tmpfs_truncate(struct vnode *vn, off_t length);
static int tmpfs_stat(struct vnode *vn, struct stat *st);
static ssize_t tmpfs_symlink_read(struct vnode *vn, void *buf, size_t len,
                                  off_t off);
static int tmpfs_close(struct vnode *vn);
static int tmpfs_dir_poll(struct vnode *vn, uint32_t events);
static int tmpfs_file_poll(struct vnode *vn, uint32_t events);
static int tmpfs_fsync(struct vnode *vn, int datasync);
static time_t tmpfs_now(void);

/* ------------------------------------------------------------------ */
/*  File operation tables                                              */
/* ------------------------------------------------------------------ */

static struct file_ops tmpfs_dir_ops = {
    .readdir = tmpfs_readdir,
    .poll = tmpfs_dir_poll,
    .close = tmpfs_close,
};

static struct file_ops tmpfs_file_ops = {
    .read = tmpfs_read,
    .write = tmpfs_write,
    .truncate = tmpfs_truncate,
    .stat = tmpfs_stat,
    .poll = tmpfs_file_poll,
    .fsync = tmpfs_fsync,
    .close = tmpfs_close,
};

static struct file_ops tmpfs_symlink_ops = {
    .read = tmpfs_symlink_read,
    .poll = tmpfs_file_poll,
    .close = tmpfs_close,
};

/* ------------------------------------------------------------------ */
/*  Vnode helpers                                                      */
/* ------------------------------------------------------------------ */

static void tmpfs_init_vnode(struct vnode *vn, struct mount *mnt,
                             struct tmpfs_node *tn, enum vnode_type type,
                             mode_t mode, struct file_ops *ops) {
    vn->type = type;
    vn->mode = mode;
    vn->uid = 0;
    vn->gid = 0;
    vn->size = 0;
    vn->ino = 0;
    vn->nlink = (type == VNODE_DIR) ? 2 : 1;
    vn->atime = vn->mtime = vn->ctime = tmpfs_now();
    vn->rdev = 0;
    vn->ops = ops;
    vn->fs_data = tn;
    vn->mount = mnt;
    vn->refcount = 1;
    vn->parent = NULL;
    vn->name[0] = '\0';
    mutex_init(&vn->lock, "tmpfs_vn");
    poll_wait_head_init(&vn->pollers);
}

static struct tmpfs_node *tmpfs_find_child(struct tmpfs_node *dir,
                                           const char *name) {
    struct tmpfs_node *child;
    list_for_each_entry(child, &dir->children, sibling) {
        if (strcmp(child->name, name) == 0)
            return child;
    }
    return NULL;
}

static time_t tmpfs_now(void) {
    return time_now_sec();
}

static struct tmpfs_node *tmpfs_alloc_node(struct tmpfs_mount *tm,
                                           struct mount *mnt,
                                           struct tmpfs_node *parent,
                                           const char *name,
                                           enum vnode_type type,
                                           mode_t mode) {
    if (tm->used_inodes >= tm->max_inodes)
        return NULL;

    struct tmpfs_node *tn = kzalloc(sizeof(*tn));
    if (!tn)
        return NULL;

    strncpy(tn->name, name, CONFIG_NAME_MAX - 1);
    tn->name[CONFIG_NAME_MAX - 1] = '\0';
    tn->pages = NULL;
    tn->pages_cap = 0;
    tn->size = 0;
    tn->symlink_target = NULL;
    tn->parent = parent;
    INIT_LIST_HEAD(&tn->children);
    INIT_LIST_HEAD(&tn->sibling);

    struct file_ops *ops;
    if (type == VNODE_DIR)
        ops = &tmpfs_dir_ops;
    else if (type == VNODE_SYMLINK)
        ops = &tmpfs_symlink_ops;
    else
        ops = &tmpfs_file_ops;

    tmpfs_init_vnode(&tn->vn, mnt, tn, type, mode, ops);
    tn->vn.ino = tm->next_ino++;
    tm->used_inodes++;

    if (parent) {
        list_add_tail(&tn->sibling, &parent->children);
        vnode_set_parent(&tn->vn, &parent->vn, tn->name);
        parent->vn.nlink++;
    }
    return tn;
}

static void tmpfs_free_pages(struct tmpfs_mount *tm, struct tmpfs_node *tn) {
    if (!tn->pages)
        return;
    for (size_t i = 0; i < tn->pages_cap; i++) {
        if (tn->pages[i]) {
            pmm_free_page(tn->pages[i]);
            tm->used_bytes -= CONFIG_PAGE_SIZE;
            tn->pages[i] = 0;
        }
    }
    kfree(tn->pages);
    tn->pages = NULL;
    tn->pages_cap = 0;
}

static void tmpfs_free_node(struct tmpfs_mount *tm, struct tmpfs_node *tn) {
    if (!tn)
        return;
    struct tmpfs_node *child, *tmp;
    list_for_each_entry_safe(child, tmp, &tn->children, sibling) {
        list_del(&child->sibling);
        tmpfs_free_node(tm, child);
    }
    tmpfs_free_pages(tm, tn);
    if (tn->symlink_target)
        kfree(tn->symlink_target);
    tm->used_inodes--;
    kfree(tn);
}

static void tmpfs_remove_child(struct tmpfs_node *tn) {
    if (tn->parent)
        tn->parent->vn.nlink--;
    list_del(&tn->sibling);
}

/* ------------------------------------------------------------------ */
/*  File read/write                                                    */
/* ------------------------------------------------------------------ */

static ssize_t tmpfs_read(struct vnode *vn, void *buf, size_t len, off_t off) {
    struct tmpfs_node *tn = vn->fs_data;
    if (!tn)
        return -EINVAL;
    if (off < 0)
        return -EINVAL;

    mutex_lock(&vn->lock);
    if ((size_t)off >= tn->size) {
        mutex_unlock(&vn->lock);
        return 0;
    }

    size_t avail = tn->size - (size_t)off;
    if (len > avail)
        len = avail;

    size_t done = 0;
    while (done < len) {
        size_t pg_idx = ((size_t)off + done) / CONFIG_PAGE_SIZE;
        size_t pg_off = ((size_t)off + done) % CONFIG_PAGE_SIZE;
        size_t chunk = CONFIG_PAGE_SIZE - pg_off;
        if (chunk > len - done)
            chunk = len - done;

        if (pg_idx < tn->pages_cap && tn->pages[pg_idx]) {
            void *src = phys_to_virt(tn->pages[pg_idx]);
            memcpy((char *)buf + done, (char *)src + pg_off, chunk);
        } else {
            /* Hole — fill with zeros */
            memset((char *)buf + done, 0, chunk);
        }
        done += chunk;
    }

    vn->atime = tmpfs_now();
    mutex_unlock(&vn->lock);
    return (ssize_t)done;
}

static int tmpfs_ensure_pages(struct tmpfs_node *tn, size_t need_cap) {
    if (need_cap <= tn->pages_cap)
        return 0;
    size_t new_cap = tn->pages_cap ? tn->pages_cap * 2 : 4;
    if (new_cap < need_cap)
        new_cap = need_cap;
    paddr_t *np = kzalloc(new_cap * sizeof(paddr_t));
    if (!np)
        return -ENOMEM;
    if (tn->pages) {
        memcpy(np, tn->pages, tn->pages_cap * sizeof(paddr_t));
        kfree(tn->pages);
    }
    tn->pages = np;
    tn->pages_cap = new_cap;
    return 0;
}

static ssize_t tmpfs_write(struct vnode *vn, const void *buf, size_t len,
                           off_t off) {
    struct tmpfs_node *tn = vn->fs_data;
    struct tmpfs_mount *tm = vn->mount->fs_data;
    if (!tn || !tm)
        return -EINVAL;
    if (off < 0)
        return -EINVAL;

    mutex_lock(&vn->lock);

    size_t end = (size_t)off + len;
    size_t need_pages = (end + CONFIG_PAGE_SIZE - 1) / CONFIG_PAGE_SIZE;

    int ret = tmpfs_ensure_pages(tn, need_pages);
    if (ret < 0) {
        mutex_unlock(&vn->lock);
        return ret;
    }

    size_t done = 0;
    while (done < len) {
        size_t pg_idx = ((size_t)off + done) / CONFIG_PAGE_SIZE;
        size_t pg_off = ((size_t)off + done) % CONFIG_PAGE_SIZE;
        size_t chunk = CONFIG_PAGE_SIZE - pg_off;
        if (chunk > len - done)
            chunk = len - done;

        if (!tn->pages[pg_idx]) {
            if (tm->used_bytes + CONFIG_PAGE_SIZE > tm->max_bytes) {
                mutex_unlock(&vn->lock);
                return done > 0 ? (ssize_t)done : -ENOSPC;
            }
            paddr_t pa = pmm_alloc_page();
            if (!pa) {
                mutex_unlock(&vn->lock);
                return done > 0 ? (ssize_t)done : -ENOMEM;
            }
            memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);
            tn->pages[pg_idx] = pa;
            tm->used_bytes += CONFIG_PAGE_SIZE;
        }

        void *dst = phys_to_virt(tn->pages[pg_idx]);
        memcpy((char *)dst + pg_off, (const char *)buf + done, chunk);
        done += chunk;
    }

    if (end > tn->size) {
        tn->size = end;
        vn->size = end;
    }
    vn->mtime = vn->ctime = tmpfs_now();
    mutex_unlock(&vn->lock);
    return (ssize_t)done;
}

static int tmpfs_truncate(struct vnode *vn, off_t length) {
    struct tmpfs_node *tn = vn->fs_data;
    struct tmpfs_mount *tm = vn->mount->fs_data;
    if (!tn || !tm)
        return -EINVAL;
    if (length < 0)
        return -EINVAL;

    mutex_lock(&vn->lock);

    size_t new_size = (size_t)length;
    size_t old_size = tn->size;

    if (new_size < old_size && tn->pages) {
        /* Free pages beyond new size */
        size_t first_free = (new_size + CONFIG_PAGE_SIZE - 1) / CONFIG_PAGE_SIZE;
        size_t old_pages = (old_size + CONFIG_PAGE_SIZE - 1) / CONFIG_PAGE_SIZE;
        for (size_t i = first_free; i < old_pages && i < tn->pages_cap; i++) {
            if (tn->pages[i]) {
                pmm_free_page(tn->pages[i]);
                tm->used_bytes -= CONFIG_PAGE_SIZE;
                tn->pages[i] = 0;
            }
        }
        /* Zero partial page */
        if (new_size % CONFIG_PAGE_SIZE && first_free > 0) {
            size_t pg = first_free - 1;
            if (pg < tn->pages_cap && tn->pages[pg]) {
                void *p = phys_to_virt(tn->pages[pg]);
                size_t zero_off = new_size % CONFIG_PAGE_SIZE;
                memset((char *)p + zero_off, 0, CONFIG_PAGE_SIZE - zero_off);
            }
        }
    }

    tn->size = new_size;
    vn->size = new_size;
    vn->mtime = vn->ctime = tmpfs_now();
    mutex_unlock(&vn->lock);
    return 0;
}

static int tmpfs_stat(struct vnode *vn, struct stat *st) {
    struct tmpfs_node *tn = vn->fs_data;
    if (!tn)
        return -EINVAL;
    memset(st, 0, sizeof(*st));
    st->st_ino = vn->ino;
    st->st_mode = vn->mode;
    st->st_nlink = vn->nlink;
    st->st_uid = vn->uid;
    st->st_gid = vn->gid;
    st->st_size = (off_t)tn->size;
    st->st_rdev = vn->rdev;
    st->st_blksize = CONFIG_PAGE_SIZE;
    st->st_blocks = (blkcnt_t)((tn->size + 511) / 512);
    st->st_atime = vn->atime;
    st->st_mtime = vn->mtime;
    st->st_ctime = vn->ctime;
    return 0;
}

static ssize_t tmpfs_symlink_read(struct vnode *vn, void *buf, size_t len,
                                  off_t off) {
    struct tmpfs_node *tn = vn->fs_data;
    if (!tn || !tn->symlink_target)
        return -EINVAL;
    size_t tlen = strlen(tn->symlink_target);
    if ((size_t)off >= tlen)
        return 0;
    size_t avail = tlen - (size_t)off;
    if (len > avail)
        len = avail;
    memcpy(buf, tn->symlink_target + off, len);
    return (ssize_t)len;
}

static int tmpfs_close(struct vnode *vn __attribute__((unused))) {
    return 0;
}

static int tmpfs_dir_poll(struct vnode *vn __attribute__((unused)),
                          uint32_t events) {
    return (int)(events & (POLLIN | POLLOUT));
}

static int tmpfs_file_poll(struct vnode *vn __attribute__((unused)),
                           uint32_t events) {
    return (int)(events & (POLLIN | POLLOUT));
}

static int tmpfs_fsync(struct vnode *vn __attribute__((unused)),
                       int datasync __attribute__((unused))) {
    return 0; /* no-op for memory FS */
}

/* ------------------------------------------------------------------ */
/*  Directory operations                                               */
/* ------------------------------------------------------------------ */

static int tmpfs_readdir(struct vnode *vn, struct dirent *ent, off_t *off) {
    struct tmpfs_node *dir = vn->fs_data;
    struct tmpfs_mount *tm = vn->mount->fs_data;
    if (!dir || !tm)
        return -EINVAL;

    spin_lock(&tm->lock);
    off_t idx = 0;
    struct tmpfs_node *child = NULL;
    struct list_head *pos;
    for (pos = dir->children.next; pos != &dir->children; pos = pos->next) {
        if (idx == *off) {
            child = list_entry(pos, struct tmpfs_node, sibling);
            break;
        }
        idx++;
    }
    if (!child) {
        spin_unlock(&tm->lock);
        return 0;
    }

    ent->d_ino = child->vn.ino;
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
    spin_unlock(&tm->lock);
    return 1;
}

/* ------------------------------------------------------------------ */
/*  VFS operations                                                     */
/* ------------------------------------------------------------------ */

static struct vnode *tmpfs_lookup(struct vnode *dir, const char *name) {
    if (!dir || !name)
        return NULL;
    struct tmpfs_node *d = dir->fs_data;
    if (!d || dir->type != VNODE_DIR)
        return NULL;
    struct tmpfs_mount *tm = dir->mount->fs_data;
    if (!tm)
        return NULL;

    spin_lock(&tm->lock);
    struct tmpfs_node *child = tmpfs_find_child(d, name);
    if (child)
        vnode_get(&child->vn);
    spin_unlock(&tm->lock);
    return child ? &child->vn : NULL;
}

static int tmpfs_create(struct vnode *dir, const char *name, mode_t mode) {
    struct tmpfs_node *d = dir->fs_data;
    struct tmpfs_mount *tm = dir->mount->fs_data;
    if (!d || !tm)
        return -EINVAL;

    mode_t fmode = (mode & S_IFMT) ? mode : (S_IFREG | (mode & 07777));

    spin_lock(&tm->lock);
    if (tmpfs_find_child(d, name)) {
        spin_unlock(&tm->lock);
        return -EEXIST;
    }
    struct tmpfs_node *tn = tmpfs_alloc_node(tm, dir->mount, d, name,
                                             VNODE_FILE, fmode);
    spin_unlock(&tm->lock);
    return tn ? 0 : -ENOMEM;
}

static int tmpfs_mkdir_op(struct vnode *dir, const char *name, mode_t mode) {
    struct tmpfs_node *d = dir->fs_data;
    struct tmpfs_mount *tm = dir->mount->fs_data;
    if (!d || !tm)
        return -EINVAL;

    mode_t dmode = (mode & S_IFMT) ? mode : (S_IFDIR | (mode & 07777));

    spin_lock(&tm->lock);
    if (tmpfs_find_child(d, name)) {
        spin_unlock(&tm->lock);
        return -EEXIST;
    }
    struct tmpfs_node *tn = tmpfs_alloc_node(tm, dir->mount, d, name,
                                             VNODE_DIR, dmode);
    spin_unlock(&tm->lock);
    return tn ? 0 : -ENOMEM;
}

static int tmpfs_symlink_op(struct vnode *dir, const char *name,
                           const char *target) {
    struct tmpfs_node *d = dir->fs_data;
    struct tmpfs_mount *tm = dir->mount->fs_data;
    if (!d || !tm || !target)
        return -EINVAL;

    spin_lock(&tm->lock);
    if (tmpfs_find_child(d, name)) {
        spin_unlock(&tm->lock);
        return -EEXIST;
    }
    struct tmpfs_node *tn = tmpfs_alloc_node(tm, dir->mount, d, name,
                                             VNODE_SYMLINK,
                                             S_IFLNK | 0777);
    if (!tn) {
        spin_unlock(&tm->lock);
        return -ENOMEM;
    }
    size_t tlen = strlen(target);
    tn->symlink_target = kmalloc(tlen + 1);
    if (!tn->symlink_target) {
        tmpfs_remove_child(tn);
        tmpfs_free_node(tm, tn);
        spin_unlock(&tm->lock);
        return -ENOMEM;
    }
    memcpy(tn->symlink_target, target, tlen + 1);
    tn->size = tlen;
    tn->vn.size = tlen;
    spin_unlock(&tm->lock);
    return 0;
}

static int tmpfs_mknod_op(struct vnode *dir, const char *name, mode_t mode,
                          dev_t dev) {
    struct tmpfs_node *d = dir->fs_data;
    struct tmpfs_mount *tm = dir->mount->fs_data;
    if (!d || !tm)
        return -EINVAL;

    spin_lock(&tm->lock);
    if (tmpfs_find_child(d, name)) {
        spin_unlock(&tm->lock);
        return -EEXIST;
    }
    struct tmpfs_node *tn = tmpfs_alloc_node(tm, dir->mount, d, name,
                                             VNODE_FILE, mode);
    if (!tn) {
        spin_unlock(&tm->lock);
        return -ENOMEM;
    }
    tn->vn.rdev = dev;
    spin_unlock(&tm->lock);
    return 0;
}

static int tmpfs_unlink_op(struct vnode *dir, const char *name) {
    struct tmpfs_node *d = dir->fs_data;
    struct tmpfs_mount *tm = dir->mount->fs_data;
    if (!d || !tm)
        return -EINVAL;

    spin_lock(&tm->lock);
    struct tmpfs_node *child = tmpfs_find_child(d, name);
    if (!child) {
        spin_unlock(&tm->lock);
        return -ENOENT;
    }
    if (child->vn.type == VNODE_DIR) {
        spin_unlock(&tm->lock);
        return -EISDIR;
    }
    tmpfs_remove_child(child);
    tmpfs_free_node(tm, child);
    d->vn.mtime = d->vn.ctime = tmpfs_now();
    spin_unlock(&tm->lock);
    return 0;
}

static int tmpfs_rmdir_op(struct vnode *dir, const char *name) {
    struct tmpfs_node *d = dir->fs_data;
    struct tmpfs_mount *tm = dir->mount->fs_data;
    if (!d || !tm)
        return -EINVAL;

    spin_lock(&tm->lock);
    struct tmpfs_node *child = tmpfs_find_child(d, name);
    if (!child) {
        spin_unlock(&tm->lock);
        return -ENOENT;
    }
    if (child->vn.type != VNODE_DIR) {
        spin_unlock(&tm->lock);
        return -ENOTDIR;
    }
    if (!list_empty(&child->children)) {
        spin_unlock(&tm->lock);
        return -ENOTEMPTY;
    }
    tmpfs_remove_child(child);
    tmpfs_free_node(tm, child);
    d->vn.mtime = d->vn.ctime = tmpfs_now();
    spin_unlock(&tm->lock);
    return 0;
}

static int tmpfs_rename_op(struct vnode *odir, const char *oname,
                           struct vnode *ndir, const char *nname) {
    struct tmpfs_node *od = odir->fs_data;
    struct tmpfs_node *nd = ndir->fs_data;
    struct tmpfs_mount *tm = odir->mount->fs_data;
    if (!od || !nd || !tm)
        return -EINVAL;

    spin_lock(&tm->lock);
    struct tmpfs_node *src = tmpfs_find_child(od, oname);
    if (!src) {
        spin_unlock(&tm->lock);
        return -ENOENT;
    }

    struct tmpfs_node *dst = tmpfs_find_child(nd, nname);
    if (dst) {
        if (dst->vn.type == VNODE_DIR && !list_empty(&dst->children)) {
            spin_unlock(&tm->lock);
            return -ENOTEMPTY;
        }
        tmpfs_remove_child(dst);
        tmpfs_free_node(tm, dst);
    }

    /* Move src from old parent to new parent */
    list_del(&src->sibling);
    if (src->parent)
        src->parent->vn.nlink--;
    src->parent = nd;
    nd->vn.nlink++;
    list_add_tail(&src->sibling, &nd->children);
    strncpy(src->name, nname, CONFIG_NAME_MAX - 1);
    src->name[CONFIG_NAME_MAX - 1] = '\0';
    vnode_set_parent(&src->vn, &nd->vn, src->name);

    time_t now = tmpfs_now();
    od->vn.mtime = od->vn.ctime = now;
    nd->vn.mtime = nd->vn.ctime = now;
    src->vn.ctime = now;
    spin_unlock(&tm->lock);
    return 0;
}

static int tmpfs_chmod_op(struct vnode *vn, mode_t mode) {
    vn->mode = (vn->mode & S_IFMT) | (mode & 07777);
    vn->ctime = tmpfs_now();
    return 0;
}

static int tmpfs_chown_op(struct vnode *vn, uid_t uid, gid_t gid) {
    vn->uid = uid;
    vn->gid = gid;
    vn->ctime = tmpfs_now();
    return 0;
}

static int tmpfs_utimes_op(struct vnode *vn, const struct timespec *atime,
                           const struct timespec *mtime) {
    if (atime)
        vn->atime = atime->tv_sec;
    if (mtime)
        vn->mtime = mtime->tv_sec;
    vn->ctime = tmpfs_now();
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Mount / unmount / statfs                                           */
/* ------------------------------------------------------------------ */

static int tmpfs_mount_op(struct mount *mnt) {
    struct tmpfs_mount *tm = kzalloc(sizeof(*tm));
    if (!tm)
        return -ENOMEM;

    tm->next_ino = 1;
    spin_init(&tm->lock);
    tm->max_bytes = TMPFS_MAX_BYTES;
    tm->used_bytes = 0;
    tm->max_inodes = TMPFS_MAX_INODES;
    tm->used_inodes = 0;

    tm->root = kzalloc(sizeof(*tm->root));
    if (!tm->root) {
        kfree(tm);
        return -ENOMEM;
    }

    /*
     * Root node is manually initialized because tmpfs_alloc_node requires
     * a mount that isn't fully set up yet.  Same pattern as initramfs/procfs.
     */
    strncpy(tm->root->name, "/", CONFIG_NAME_MAX - 1);
    tm->root->parent = NULL;
    INIT_LIST_HEAD(&tm->root->children);
    INIT_LIST_HEAD(&tm->root->sibling);
    tmpfs_init_vnode(&tm->root->vn, mnt, tm->root, VNODE_DIR,
                     S_IFDIR | 01777, &tmpfs_dir_ops);
    tm->root->vn.ino = tm->next_ino++;
    tm->used_inodes++;

    mnt->fs_data = tm;
    mnt->root = &tm->root->vn;
    pr_info("tmpfs: mounted\n");
    return 0;
}

static int tmpfs_unmount_op(struct mount *mnt) {
    struct tmpfs_mount *tm = mnt->fs_data;
    if (!tm)
        return 0;
    tmpfs_free_node(tm, tm->root);
    kfree(tm);
    return 0;
}

static int tmpfs_statfs_op(struct mount *mnt, struct kstatfs *st) {
    struct tmpfs_mount *tm = mnt->fs_data;
    memset(st, 0, sizeof(*st));
    st->f_type = TMPFS_SUPER_MAGIC;
    st->f_bsize = CONFIG_PAGE_SIZE;
    st->f_frsize = CONFIG_PAGE_SIZE;
    st->f_blocks = tm->max_bytes / CONFIG_PAGE_SIZE;
    st->f_bfree = (tm->max_bytes - tm->used_bytes) / CONFIG_PAGE_SIZE;
    st->f_bavail = st->f_bfree;
    st->f_files = tm->max_inodes;
    st->f_ffree = tm->max_inodes - tm->used_inodes;
    st->f_namelen = CONFIG_NAME_MAX;
    return 0;
}

static struct vfs_ops tmpfs_vfs_ops = {
    .name = "tmpfs",
    .mount = tmpfs_mount_op,
    .unmount = tmpfs_unmount_op,
    .lookup = tmpfs_lookup,
    .create = tmpfs_create,
    .mkdir = tmpfs_mkdir_op,
    .symlink = tmpfs_symlink_op,
    .unlink = tmpfs_unlink_op,
    .rmdir = tmpfs_rmdir_op,
    .rename = tmpfs_rename_op,
    .mknod = tmpfs_mknod_op,
    .chmod = tmpfs_chmod_op,
    .chown = tmpfs_chown_op,
    .utimes = tmpfs_utimes_op,
    .statfs = tmpfs_statfs_op,
};

static struct fs_type tmpfs_type = {
    .name = "tmpfs",
    .ops = &tmpfs_vfs_ops,
};

void tmpfs_init(void) {
    if (vfs_register_fs(&tmpfs_type) < 0)
        pr_err("tmpfs: registration failed\n");
    else
        pr_info("tmpfs: initialized\n");
}
