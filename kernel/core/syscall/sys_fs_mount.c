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

int64_t sys_chroot(uint64_t path_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (!path_ptr)
        return -EFAULT;

    char kpath[CONFIG_PATH_MAX];
    if (strncpy_from_user(kpath, (const char *)path_ptr, sizeof(kpath)) < 0)
        return -EFAULT;

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
        __atomic_load_n(&p->mnt_ns->refcount, __ATOMIC_RELAXED) > 1) {
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
    if (strncpy_from_user(new_root, (const char *)new_root_ptr,
                          sizeof(new_root)) < 0)
        return -EFAULT;
    if (strncpy_from_user(put_old, (const char *)put_old_ptr,
                          sizeof(put_old)) < 0)
        return -EFAULT;

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
        __atomic_load_n(&p->mnt_ns->refcount, __ATOMIC_RELAXED) > 1) {
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
    p->umask = (mode_t)mask & 0777;
    return (int64_t)old;
}

int64_t sys_umount2(uint64_t target_ptr, uint64_t flags, uint64_t a2,
                    uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    char kpath[CONFIG_PATH_MAX];
    if (!target_ptr)
        return -EFAULT;
    if (flags != 0)
        return -EINVAL;
    if (strncpy_from_user(kpath, (const char *)target_ptr, sizeof(kpath)) < 0)
        return -EFAULT;
    struct path tpath;
    path_init(&tpath);
    int ret = sysfs_resolve_at(AT_FDCWD, kpath, &tpath,
                               NAMEI_FOLLOW | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;
    char full[CONFIG_PATH_MAX];
    if (vfs_build_path_dentry(tpath.dentry, full, sizeof(full)) < 0) {
        dentry_put(tpath.dentry);
        return -ENAMETOOLONG;
    }
    dentry_put(tpath.dentry);
    return vfs_umount(full);
}

static int set_mount_propagation(struct mount *mnt, uint64_t flags) {
    if (!mnt)
        return -EINVAL;
    if (flags & MS_SHARED)
        return vfs_mount_set_shared(mnt);
    if (flags & MS_PRIVATE) {
        vfs_mount_set_private(mnt);
        return 0;
    }
    if (flags & MS_SLAVE)
        return vfs_mount_set_slave(mnt);
    if (flags & MS_UNBINDABLE) {
        vfs_mount_set_private(mnt);
        return 0;
    }
    return -EINVAL;
}

int64_t sys_mount(uint64_t source_ptr, uint64_t target_ptr, uint64_t fstype_ptr,
                  uint64_t flags, uint64_t data, uint64_t a5) {
    (void)data; (void)a5;
    uint64_t allowed = MS_BIND | MS_REC | MS_PRIVATE | MS_SLAVE |
                       MS_SHARED | MS_UNBINDABLE;
    if (flags & ~allowed)
        return -EINVAL;
    char source[CONFIG_PATH_MAX];
    char target[CONFIG_PATH_MAX];
    char fstype[CONFIG_NAME_MAX];

    if (!target_ptr)
        return -EFAULT;
    if (strncpy_from_user(target, (const char *)target_ptr, sizeof(target)) < 0)
        return -EFAULT;
    if (source_ptr &&
        strncpy_from_user(source, (const char *)source_ptr, sizeof(source)) < 0)
        return -EFAULT;
    if (fstype_ptr &&
        strncpy_from_user(fstype, (const char *)fstype_ptr, sizeof(fstype)) < 0)
        return -EFAULT;

    struct path tpath;
    path_init(&tpath);
    int ret = sysfs_resolve_at(AT_FDCWD, target, &tpath,
                               NAMEI_FOLLOW | NAMEI_DIRECTORY);
    if (ret < 0)
        return ret;

    uint64_t prop_mask = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;
    if (flags & prop_mask) {
        struct mount *mnt = tpath.dentry->mounted
                                ? tpath.dentry->mounted
                                : tpath.dentry->mnt;
        vfs_mount_global_lock();
        ret = set_mount_propagation(mnt, flags);
        vfs_mount_global_unlock();
        dentry_put(tpath.dentry);
        return ret;
    }

    if (flags & MS_BIND) {
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
        ret = vfs_bind_mount(spath.dentry, tpath.dentry, (uint32_t)flags, true);
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
            ret = vfs_mount(src_use, target_full, fstype, (uint32_t)flags);
        }
    }
out_tpath:
    dentry_put(tpath.dentry);
    return ret;
}
