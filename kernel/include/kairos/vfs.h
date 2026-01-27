/**
 * kernel/include/kairos/vfs.h - Virtual File System
 */

#ifndef _KAIROS_VFS_H
#define _KAIROS_VFS_H

#include <kairos/config.h>
#include <kairos/list.h>
#include <kairos/pollwait.h>
#include <kairos/sync.h>
#include <kairos/types.h>

enum vnode_type {
    VNODE_FILE,
    VNODE_DIR,
    VNODE_DEVICE,
    VNODE_PIPE,
    VNODE_SOCKET,
    VNODE_SYMLINK,
    VNODE_EPOLL
};

struct dirent {
    ino_t d_ino;
    off_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[CONFIG_NAME_MAX];
};

#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12

struct stat {
    dev_t st_dev, st_rdev;
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    time_t st_atime, st_mtime, st_ctime;
};

#define S_IFMT 0170000
#define S_IFREG 0100000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)

struct vnode {
    enum vnode_type type;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    uint64_t size;
    ino_t ino;
    struct file_ops *ops;
    void *fs_data;
    struct mount *mount;
    uint32_t refcount;
    struct mutex lock;
    struct poll_wait_head pollers;
};

struct file {
    struct vnode *vnode;
    off_t offset;
    uint32_t flags, refcount;
    struct mutex lock;
};

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_APPEND 02000
#define O_NONBLOCK 04000
#define O_DIRECTORY 0200000
#define F_GETFL 3
#define F_SETFL 4

struct mount {
    char *mountpoint;
    struct vfs_ops *ops;
    struct vnode *root;
    struct blkdev *dev;
    void *fs_data;
    uint32_t flags;
    struct list_head list;
};

struct vfs_ops {
    const char *name;
    int (*mount)(struct mount *mnt);
    int (*unmount)(struct mount *mnt);
    struct vnode *(*lookup)(struct vnode *dir, const char *name);
    int (*create)(struct vnode *dir, const char *name, mode_t mode);
    int (*mkdir)(struct vnode *dir, const char *name, mode_t mode);
    int (*unlink)(struct vnode *dir, const char *name);
    int (*rmdir)(struct vnode *dir, const char *name);
    int (*rename)(struct vnode *odir, const char *oname, struct vnode *ndir,
                  const char *nname);
};

struct file_ops {
    ssize_t (*read)(struct vnode *vn, void *buf, size_t len, off_t off);
    ssize_t (*write)(struct vnode *vn, const void *buf, size_t len, off_t off);
    int (*readdir)(struct vnode *vn, struct dirent *ent, off_t *off);
    int (*close)(struct vnode *vn);
    int (*stat)(struct vnode *vn, struct stat *st);
    int (*truncate)(struct vnode *vn, off_t length);
    int (*poll)(struct vnode *vn, uint32_t events);
};

struct poll_waiter;
struct poll_watch;

void vfs_init(void);
int vfs_mount(const char *src, const char *tgt, const char *type,
              uint32_t flags);
int vfs_umount(const char *tgt);
struct vnode *vfs_lookup(const char *path);
struct vnode *vfs_lookup_at(const char *cwd, const char *path);
struct vnode *vfs_lookup_parent(const char *path, char *name);
int vfs_open(const char *path, int flags, mode_t mode, struct file **fp);
int vfs_open_at(const char *cwd, const char *path, int flags, mode_t mode, struct file **fp);
int vfs_close(struct file *file);
struct file *vfs_file_alloc(void);
void vfs_file_free(struct file *file);
void vfs_dump_mounts(void);
ssize_t vfs_read(struct file *file, void *buf, size_t len);
ssize_t vfs_write(struct file *file, const void *buf, size_t len);
int vfs_poll(struct file *file, uint32_t events);
int vfs_poll_vnode(struct vnode *vn, uint32_t events);
void vfs_poll_register(struct file *file, struct poll_waiter *waiter,
                       uint32_t events);
void vfs_poll_unregister(struct poll_waiter *waiter);
void vfs_poll_watch(struct vnode *vn, struct poll_watch *watch,
                    uint32_t events);
void vfs_poll_unwatch(struct poll_watch *watch);
void vfs_poll_wake(struct vnode *vn, uint32_t events);
off_t vfs_seek(struct file *file, off_t offset, int whence);
int vfs_readdir(struct file *file, struct dirent *ent);
int vfs_stat(const char *path, struct stat *st);
int vfs_fstat(struct file *file, struct stat *st);
int vfs_mkdir(const char *path, mode_t mode);
int vfs_rmdir(const char *path);
int vfs_unlink(const char *path);
int vfs_rename(const char *old, const char *new);
int vfs_normalize_path(const char *cwd, const char *input, char *output);
void vnode_get(struct vnode *vn);
void vnode_put(struct vnode *vn);

struct fs_type {
    const char *name;
    struct vfs_ops *ops;
    struct list_head list;
};
int vfs_register_fs(struct fs_type *fs);

#endif
