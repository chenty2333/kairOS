/**
 * kernel/core/syscall/sys_fs_helpers.h - FS syscall helpers (internal)
 */

#ifndef _KAIROS_SYS_FS_HELPERS_H
#define _KAIROS_SYS_FS_HELPERS_H

#include <kairos/types.h>

struct process;
struct vnode;
struct dentry;
struct path;

struct dentry *sysfs_proc_cwd_dentry(struct process *p);
struct vnode *sysfs_proc_cwd_vnode(struct process *p);
int sysfs_copy_path(uint64_t uptr, char *kbuf, size_t klen);
int sysfs_get_base_path(int64_t dirfd, const char *path, struct path *base,
                        struct path **basep);
int sysfs_resolve_at(int64_t dirfd, const char *path, struct path *out,
                     int flags);
int sysfs_resolve_at_user(int64_t dirfd, uint64_t upath, struct path *out,
                          int flags);
ssize_t sysfs_readlink_from_vnode(struct vnode *vn, char *buf, size_t bufsz);
mode_t sysfs_apply_umask(mode_t mode);

#endif
