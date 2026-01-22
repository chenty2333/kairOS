/**
 * kairos/vfs.h - Virtual File System
 */

#ifndef _KAIROS_VFS_H
#define _KAIROS_VFS_H

#include <kairos/types.h>
#include <kairos/list.h>
#include <kairos/spinlock.h>

/* Forward declarations */
struct blkdev;
struct process;

/*
 * VNode Types
 */
enum vnode_type {
    VNODE_FILE,
    VNODE_DIR,
    VNODE_DEVICE,
    VNODE_PIPE,
    VNODE_SOCKET,
    VNODE_SYMLINK,
};

/*
 * Directory Entry
 */
struct dirent {
    ino_t d_ino;
    off_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[CONFIG_NAME_MAX];
};

/* d_type values */
#define DT_UNKNOWN  0
#define DT_FIFO     1
#define DT_CHR      2
#define DT_DIR      4
#define DT_BLK      6
#define DT_REG      8
#define DT_LNK      10
#define DT_SOCK     12

/*
 * File Status
 */
struct stat {
    dev_t st_dev;
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    time_t st_atime;
    time_t st_mtime;
    time_t st_ctime;
};

/* st_mode bits */
#define S_IFMT      0170000     /* File type mask */
#define S_IFSOCK    0140000     /* Socket */
#define S_IFLNK     0120000     /* Symbolic link */
#define S_IFREG     0100000     /* Regular file */
#define S_IFBLK     0060000     /* Block device */
#define S_IFDIR     0040000     /* Directory */
#define S_IFCHR     0020000     /* Character device */
#define S_IFIFO     0010000     /* FIFO */

#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

/* Permission bits */
#define S_IRWXU     00700       /* Owner RWX */
#define S_IRUSR     00400       /* Owner read */
#define S_IWUSR     00200       /* Owner write */
#define S_IXUSR     00100       /* Owner execute */
#define S_IRWXG     00070       /* Group RWX */
#define S_IRWXO     00007       /* Other RWX */

/*
 * Virtual Node (VNode)
 */
struct vnode {
    enum vnode_type type;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    uint64_t size;
    ino_t ino;

    struct file_ops *ops;           /* File operations */
    void *fs_data;                  /* FS-specific data */
    struct mount *mount;            /* Which mount this belongs to */

    uint32_t refcount;
    spinlock_t lock;
};

/*
 * Open File Description
 */
struct file {
    struct vnode *vnode;
    off_t offset;                   /* Current position */
    uint32_t flags;                 /* Open flags */
    uint32_t refcount;              /* Reference count (for dup) */
    spinlock_t lock;
};

/* Open flags */
#define O_RDONLY    00
#define O_WRONLY    01
#define O_RDWR      02
#define O_CREAT     0100
#define O_EXCL      0200
#define O_TRUNC     01000
#define O_APPEND    02000
#define O_NONBLOCK  04000
#define O_DIRECTORY 0200000
#define O_CLOEXEC   02000000

/*
 * Mount Point
 */
struct mount {
    char *mountpoint;               /* Path where mounted */
    struct vfs_ops *ops;            /* FS operations */
    struct vnode *root;             /* Root vnode */
    struct blkdev *dev;             /* Block device (if any) */
    void *fs_data;                  /* FS-specific data */
    uint32_t flags;                 /* Mount flags */
    struct list_head list;          /* Global mount list */
};

/* Mount flags */
#define MS_RDONLY   (1 << 0)        /* Read-only */
#define MS_NOEXEC   (1 << 1)        /* No execution */
#define MS_NOSUID   (1 << 2)        /* Ignore setuid */

/*
 * File System Operations
 */
struct vfs_ops {
    const char *name;               /* FS name: "ext2", "fat32" */

    /* Mount/unmount */
    int (*mount)(struct mount *mnt);
    int (*unmount)(struct mount *mnt);

    /* Lookup path component in directory */
    struct vnode *(*lookup)(struct vnode *dir, const char *name);

    /* Create file/directory */
    int (*create)(struct vnode *dir, const char *name, mode_t mode);
    int (*mkdir)(struct vnode *dir, const char *name, mode_t mode);

    /* Delete file/directory */
    int (*unlink)(struct vnode *dir, const char *name);
    int (*rmdir)(struct vnode *dir, const char *name);

    /* Rename */
    int (*rename)(struct vnode *olddir, const char *oldname,
                  struct vnode *newdir, const char *newname);

    /* Symbolic link */
    int (*symlink)(struct vnode *dir, const char *name, const char *target);
    int (*readlink)(struct vnode *vn, char *buf, size_t size);

    /* Sync to disk */
    int (*sync)(struct mount *mnt);
};

/*
 * File Operations
 */
struct file_ops {
    ssize_t (*read)(struct vnode *vn, void *buf, size_t len, off_t offset);
    ssize_t (*write)(struct vnode *vn, const void *buf, size_t len, off_t offset);
    int (*readdir)(struct vnode *vn, struct dirent *ent, off_t *offset);
    int (*close)(struct vnode *vn);
    int (*truncate)(struct vnode *vn, off_t length);
    int (*stat)(struct vnode *vn, struct stat *st);
    int (*ioctl)(struct vnode *vn, unsigned long cmd, void *arg);
    int (*poll)(struct vnode *vn, int events);
};

/*
 * VFS API
 */

/* Initialize VFS */
void vfs_init(void);

/* Mount filesystem */
int vfs_mount(const char *source, const char *target,
              const char *fstype, uint32_t flags);

/* Unmount filesystem */
int vfs_umount(const char *target);

/* Path resolution */
struct vnode *vfs_lookup(const char *path);
struct vnode *vfs_lookup_parent(const char *path, char *name);

/* File operations via path */
int vfs_open(const char *path, int flags, mode_t mode, struct file **fp);
int vfs_close(struct file *file);
ssize_t vfs_read(struct file *file, void *buf, size_t len);
ssize_t vfs_write(struct file *file, const void *buf, size_t len);
off_t vfs_seek(struct file *file, off_t offset, int whence);
int vfs_stat(const char *path, struct stat *st);
int vfs_fstat(struct file *file, struct stat *st);

/* Directory operations */
int vfs_mkdir(const char *path, mode_t mode);
int vfs_rmdir(const char *path);
int vfs_readdir(struct file *file, struct dirent *ent);

/* File management */
int vfs_unlink(const char *path);
int vfs_rename(const char *oldpath, const char *newpath);

/* VNode reference counting */
void vnode_get(struct vnode *vn);
void vnode_put(struct vnode *vn);

/*
 * File System Registration
 */
struct fs_type {
    const char *name;
    struct vfs_ops *ops;
    struct list_head list;
};

int vfs_register_fs(struct fs_type *fs);
int vfs_unregister_fs(struct fs_type *fs);

#endif /* _KAIROS_VFS_H */
