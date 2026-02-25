/**
 * kernel/core/syscall/sys_fs_mount.c - Mount-related syscalls
 */

#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/namei.h>
#include <kairos/process.h>
#include <kairos/printk.h>
#include <kairos/syscall.h>
#include <kairos/string.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#include "sys_fs_helpers.h"

static inline int32_t sysmount_abi_i32(uint64_t raw) {
    return (int32_t)(uint32_t)raw;
}

static inline uint32_t sysmount_mount_semantic_flags(void) {
    return (uint32_t)(MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC |
                      MS_SYNCHRONOUS | MS_DIRSYNC | MS_NOATIME |
                      MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME |
                      MS_LAZYTIME | MS_SILENT | MS_POSIXACL);
}

static inline uint32_t sysmount_mount_ctrl_flags(void) {
    return (uint32_t)(MS_BIND | MS_REC | MS_PRIVATE | MS_SLAVE |
                      MS_SHARED | MS_UNBINDABLE | MS_REMOUNT);
}

int64_t sys_chroot(uint64_t path_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (!path_ptr)
        return -EFAULT;

    char kpath[CONFIG_PATH_MAX];
    {
        int copy_ret = sysfs_copy_path(path_ptr, kpath, sizeof(kpath));
        if (copy_ret < 0)
            return copy_ret;
    }

    struct path resolved;
    path_init(&resolved);
    int ret = sysfs_resolve_at(AT_FDCWD, kpath, &resolved,
                               NAMEI_FOLLOW | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return -ENOENT;
    }
    if (resolved.dentry->vnode->type != VNODE_DIR) {
        dentry_put(resolved.dentry);
        return -ENOTDIR;
    }

    if (p->mnt_ns &&
        atomic_read(&p->mnt_ns->refcount) > 1) {
        struct mount_ns *ns = vfs_mount_ns_clone(p->mnt_ns);
        if (!ns) {
            dentry_put(resolved.dentry);
            return -ENOMEM;
        }
        vfs_mount_ns_put(p->mnt_ns);
        p->mnt_ns = ns;
    }

    if (!p->mnt_ns) {
        dentry_put(resolved.dentry);
        return -EINVAL;
    }
    ret = vfs_mount_ns_set_root(p->mnt_ns, resolved.dentry);
    if (ret < 0) {
        dentry_put(resolved.dentry);
        return ret;
    }
    if (p->cwd_dentry)
        dentry_put(p->cwd_dentry);
    if (p->cwd_vnode)
        vnode_put(p->cwd_vnode);
    p->cwd_dentry = resolved.dentry;
    dentry_get(p->cwd_dentry);
    p->cwd_vnode = resolved.dentry->vnode;
    vnode_get(p->cwd_vnode);
    strcpy(p->cwd, "/");
    dentry_put(resolved.dentry);
    return 0;
}

int64_t sys_pivot_root(uint64_t new_root_ptr, uint64_t put_old_ptr,
                       uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (!new_root_ptr || !put_old_ptr)
        return -EFAULT;

    char new_root[CONFIG_PATH_MAX];
    char put_old[CONFIG_PATH_MAX];
    {
        int copy_ret = sysfs_copy_path(new_root_ptr, new_root, sizeof(new_root));
        if (copy_ret < 0)
            return copy_ret;
    }
    {
        int copy_ret = sysfs_copy_path(put_old_ptr, put_old, sizeof(put_old));
        if (copy_ret < 0)
            return copy_ret;
    }

    struct path newp, oldp;
    path_init(&newp);
    path_init(&oldp);
    int ret = sysfs_resolve_at(AT_FDCWD, new_root, &newp,
                               NAMEI_FOLLOW | NAMEI_DIRECTORY);
    if (ret < 0) {
        pr_warn("pivot_root: resolve new_root failed (ret=%d)\n", ret);
        return ret;
    }
    ret = sysfs_resolve_at(AT_FDCWD, put_old, &oldp,
                           NAMEI_FOLLOW | NAMEI_DIRECTORY);
    if (ret < 0) {
        if (newp.dentry)
            dentry_put(newp.dentry);
        pr_warn("pivot_root: resolve put_old failed (ret=%d)\n", ret);
        return ret;
    }

    if (!newp.dentry || !oldp.dentry ||
        newp.dentry->vnode->type != VNODE_DIR ||
        oldp.dentry->vnode->type != VNODE_DIR) {
        if (newp.dentry)
            dentry_put(newp.dentry);
        if (oldp.dentry)
            dentry_put(oldp.dentry);
        pr_warn("pivot_root: new_root/put_old not dir\n");
        return -ENOTDIR;
    }

    struct mount *old_root = p->mnt_ns ? p->mnt_ns->root : NULL;
    if (!old_root) {
        dentry_put(newp.dentry);
        dentry_put(oldp.dentry);
        pr_warn("pivot_root: no mount namespace root\n");
        return -EINVAL;
    }

    struct mount *new_root_mnt = newp.dentry->mounted
                                     ? newp.dentry->mounted
                                     : newp.dentry->mnt;
    if (!new_root_mnt || !new_root_mnt->root_dentry) {
        dentry_put(newp.dentry);
        dentry_put(oldp.dentry);
        pr_warn("pivot_root: new_root mount invalid\n");
        return -EINVAL;
    }
    if (!newp.dentry->mounted &&
        newp.dentry != new_root_mnt->root_dentry) {
        dentry_put(newp.dentry);
        dentry_put(oldp.dentry);
        pr_warn("pivot_root: new_root not mount root\n");
        return -EINVAL;
    }
    if (new_root_mnt != oldp.dentry->mnt) {
        dentry_put(newp.dentry);
        dentry_put(oldp.dentry);
        pr_warn("pivot_root: new_root and put_old not same mount\n");
        return -EXDEV;
    }

    if (oldp.dentry->mounted || oldp.dentry->flags & DENTRY_MOUNTPOINT) {
        dentry_put(newp.dentry);
        dentry_put(oldp.dentry);
        pr_warn("pivot_root: put_old busy\n");
        return -EBUSY;
    }

    if (p->mnt_ns &&
        atomic_read(&p->mnt_ns->refcount) > 1) {
        struct mount_ns *ns = vfs_mount_ns_clone(p->mnt_ns);
        if (!ns) {
            dentry_put(newp.dentry);
            dentry_put(oldp.dentry);
            return -ENOMEM;
        }
        vfs_mount_ns_put(p->mnt_ns);
        p->mnt_ns = ns;
    }
    if (!p->mnt_ns) {
        dentry_put(newp.dentry);
        dentry_put(oldp.dentry);
        pr_warn("pivot_root: mount namespace missing\n");
        return -EINVAL;
    }

    char relpath[CONFIG_PATH_MAX];
    if (vfs_build_relpath(new_root_mnt->root_dentry, oldp.dentry,
                          relpath, sizeof(relpath)) < 0) {
        dentry_put(newp.dentry);
        dentry_put(oldp.dentry);
        pr_warn("pivot_root: put_old not under new_root\n");
        return -EINVAL;
    }

    vfs_mount_global_lock();
    if (new_root_mnt->mountpoint_dentry) {
        new_root_mnt->mountpoint_dentry->mounted = NULL;
        new_root_mnt->mountpoint_dentry->flags &= ~DENTRY_MOUNTPOINT;
        dentry_put(new_root_mnt->mountpoint_dentry);
    }
    new_root_mnt->parent = NULL;
    new_root_mnt->mountpoint_dentry = NULL;

    old_root->parent = new_root_mnt;
    dentry_get(oldp.dentry);
    old_root->mountpoint_dentry = oldp.dentry;
    oldp.dentry->mounted = old_root;
    oldp.dentry->flags |= DENTRY_MOUNTPOINT;

    ret = vfs_mount_ns_set_root(p->mnt_ns, new_root_mnt->root_dentry);
    vfs_mount_global_unlock();
    if (ret < 0) {
        dentry_put(newp.dentry);
        dentry_put(oldp.dentry);
        pr_warn("pivot_root: set root failed (ret=%d)\n", ret);
        return ret;
    }
    if (p->cwd_dentry)
        dentry_put(p->cwd_dentry);
    if (p->cwd_vnode)
        vnode_put(p->cwd_vnode);
    p->cwd_dentry = new_root_mnt->root_dentry;
    dentry_get(p->cwd_dentry);
    p->cwd_vnode = p->cwd_dentry->vnode;
    vnode_get(p->cwd_vnode);
    strcpy(p->cwd, "/");

    dentry_put(newp.dentry);
    dentry_put(oldp.dentry);
    return 0;
}

int64_t sys_umask(uint64_t mask, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    mode_t old = p->umask;
    p->umask = (mode_t)((uint32_t)mask & 0777U);
    return (int64_t)old;
}

int64_t sys_umount2(uint64_t target_ptr, uint64_t flags, uint64_t a2,
                    uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    uint32_t uflags = (uint32_t)sysmount_abi_i32(flags);
    uint32_t supported = MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW;
    int resolve_flags = NAMEI_DIRECTORY;
    if (!target_ptr)
        return -EFAULT;
    if (uflags & ~supported)
        return -EINVAL;
    if (uflags & UMOUNT_NOFOLLOW)
        resolve_flags |= NAMEI_NOFOLLOW;
    else
        resolve_flags |= NAMEI_FOLLOW;
    {
        int copy_ret = sysfs_copy_path(target_ptr, kpath, sizeof(kpath));
        if (copy_ret < 0)
            return copy_ret;
    }
    struct path tpath;
    path_init(&tpath);
    int ret = sysfs_resolve_at(AT_FDCWD, kpath, &tpath, resolve_flags);
    if (ret < 0)
        return ret;
    char full[CONFIG_PATH_MAX];
    if (vfs_build_path_dentry(tpath.dentry, full, sizeof(full)) < 0) {
        dentry_put(tpath.dentry);
        return -ENAMETOOLONG;
    }
    dentry_put(tpath.dentry);
    uint32_t vfs_flags = 0;
    if (uflags & MNT_DETACH)
        vfs_flags |= VFS_UMOUNT_DETACH;
    if (uflags & MNT_FORCE)
        vfs_flags |= VFS_UMOUNT_FORCE;
    if (uflags & MNT_EXPIRE)
        vfs_flags |= VFS_UMOUNT_EXPIRE;
    return vfs_umount2(full, vfs_flags);
}

static int set_mount_propagation(struct mount *mnt, uint32_t flags) {
    if (!mnt)
        return -EINVAL;
    bool recursive = (flags & MS_REC) != 0;
    uint32_t prop_mask = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;
    uint32_t prop = flags & prop_mask;
    if (!prop || (prop & (prop - 1)))
        return -EINVAL;

    enum mount_prop mode = MOUNT_PRIVATE;
    if (prop == MS_SHARED)
        mode = MOUNT_SHARED;
    else if (prop == MS_PRIVATE)
        mode = MOUNT_PRIVATE;
    else if (prop == MS_SLAVE)
        mode = MOUNT_SLAVE;
    else if (prop == MS_UNBINDABLE)
        mode = MOUNT_UNBINDABLE;
    else
        return -EINVAL;

    return vfs_mount_set_propagation(mnt, mode, recursive);
}

int64_t sys_mount(uint64_t source_ptr, uint64_t target_ptr, uint64_t fstype_ptr,
                  uint64_t flags, uint64_t data, uint64_t a5) {
    (void)data; (void)a5;
    uint64_t allowed = (uint64_t)(sysmount_mount_semantic_flags() |
                                  sysmount_mount_ctrl_flags());
    if (flags & ~allowed)
        return -EINVAL;
    uint32_t uflags = (uint32_t)flags;
    char source[CONFIG_PATH_MAX];
    char target[CONFIG_PATH_MAX];
    char fstype[CONFIG_NAME_MAX];

    if (!target_ptr)
        return -EFAULT;
    {
        int copy_ret = sysfs_copy_path(target_ptr, target, sizeof(target));
        if (copy_ret < 0)
            return copy_ret;
    }
    if (source_ptr) {
        int copy_ret = sysfs_copy_path(source_ptr, source, sizeof(source));
        if (copy_ret < 0)
            return copy_ret;
    }
    if (fstype_ptr) {
        int copy_ret = sysfs_copy_path(fstype_ptr, fstype, sizeof(fstype));
        if (copy_ret < 0)
            return copy_ret;
    }

    struct path tpath;
    path_init(&tpath);
    int ret = sysfs_resolve_at(AT_FDCWD, target, &tpath,
                               NAMEI_FOLLOW | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;

    uint32_t prop_mask = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;
    uint32_t remount_mask = MS_REMOUNT;
    uint32_t semantic_mask = sysmount_mount_semantic_flags();
    if (uflags & prop_mask) {
        if (uflags & ~(prop_mask | MS_REC)) {
            dentry_put(tpath.dentry);
            return -EINVAL;
        }
        struct mount *mnt = tpath.dentry->mounted
                                ? tpath.dentry->mounted
                                : tpath.dentry->mnt;
        vfs_mount_global_lock();
        ret = set_mount_propagation(mnt, uflags);
        vfs_mount_global_unlock();
        dentry_put(tpath.dentry);
        return ret;
    }

    if (uflags & remount_mask) {
        if (uflags & (MS_BIND | MS_REC)) {
            dentry_put(tpath.dentry);
            return -EINVAL;
        }
        struct mount *mnt = tpath.dentry->mounted
                                ? tpath.dentry->mounted
                                : tpath.dentry->mnt;
        if (!mnt) {
            dentry_put(tpath.dentry);
            return -EINVAL;
        }
        vfs_mount_global_lock();
        mnt->flags = uflags & semantic_mask;
        vfs_mount_global_unlock();
        dentry_put(tpath.dentry);
        return 0;
    }

    if (uflags & MS_BIND) {
        if (uflags & ~(MS_BIND | MS_REC | semantic_mask)) {
            dentry_put(tpath.dentry);
            return -EINVAL;
        }
        if (!source_ptr) {
            dentry_put(tpath.dentry);
            return -EINVAL;
        }
        struct path spath;
        path_init(&spath);
        ret = sysfs_resolve_at(AT_FDCWD, source, &spath,
                               NAMEI_FOLLOW | NAMEI_DIRECTORY);
        if (ret < 0)
            goto out_tpath;
        vfs_mount_global_lock();
        ret = vfs_bind_mount(spath.dentry, tpath.dentry, uflags, true);
        vfs_mount_global_unlock();
        dentry_put(spath.dentry);
        dentry_put(tpath.dentry);
        return ret;
    }

    if (!fstype_ptr)
        ret = -EINVAL;
    if (ret == 0) {
        char target_full[CONFIG_PATH_MAX];
        if (vfs_build_path_dentry(tpath.dentry, target_full,
                                  sizeof(target_full)) < 0) {
            ret = -ENAMETOOLONG;
        } else {
            const char *src_use = source_ptr ? source : NULL;
            char source_full[CONFIG_PATH_MAX];
            if (source_ptr && source[0] != '/') {
                struct path spath;
                path_init(&spath);
                int sret = sysfs_resolve_at(AT_FDCWD, source, &spath,
                                            NAMEI_FOLLOW);
                if (sret < 0) {
                    dentry_put(tpath.dentry);
                    return sret;
                }
                if (vfs_build_path_dentry(spath.dentry, source_full,
                                          sizeof(source_full)) < 0) {
                    dentry_put(spath.dentry);
                    dentry_put(tpath.dentry);
                    return -ENAMETOOLONG;
                }
                dentry_put(spath.dentry);
                src_use = source_full;
            }
            ret = vfs_mount(src_use, target_full, fstype, uflags & semantic_mask);
        }
    }
out_tpath:
    dentry_put(tpath.dentry);
    return ret;
}
