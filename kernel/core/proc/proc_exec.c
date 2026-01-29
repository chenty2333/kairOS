/**
 * kernel/core/proc/proc_exec.c - Exec and process spawning
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/elf.h>
#include <kairos/mm.h>
#include <kairos/namei.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#include "proc_internal.h"

static void proc_free_strv(char **vec, int count) {
    if (!vec) {
        return;
    }
    for (int i = 0; i < count; i++) {
        if (vec[i]) {
            kfree(vec[i]);
        }
    }
    kfree(vec);
}

int proc_exec(const char *path, char *const argv[], char *const envp[]) {
    enum { EXEC_ARG_MAX = 64, EXEC_ENV_MAX = 64 };
    char **kargv = NULL;
    char **kenvp = NULL;
    int argc = 0;
    int envc = 0;
    struct vnode *vn;
    struct path resolved;
    struct mm_struct *old_mm, *new_mm;
    vaddr_t entry, sp;
    size_t size;
    int ret = 0;

    if (argv) {
        kargv = kmalloc((EXEC_ARG_MAX + 1) * sizeof(char *));
        if (!kargv)
            return -ENOMEM;
        for (int i = 0; i < EXEC_ARG_MAX; i++) {
            const char *uarg = NULL;
            if (copy_from_user(&uarg, &argv[i], sizeof(uarg)) < 0) {
                ret = -EFAULT;
                goto out;
            }
            if (!uarg)
                break;
            kargv[i] = kmalloc(CONFIG_PATH_MAX);
            if (!kargv[i]) {
                ret = -ENOMEM;
                goto out;
            }
            argc = i + 1;
            long len = strncpy_from_user(kargv[i], uarg, CONFIG_PATH_MAX);
            if (len < 0) {
                ret = (int)len;
                goto out;
            }
            if (len >= CONFIG_PATH_MAX - 1) {
                ret = -E2BIG;
                goto out;
            }
        }
        if (argc >= EXEC_ARG_MAX) {
            ret = -E2BIG;
            goto out;
        }
        kargv[argc] = NULL;
    }

    if (envp) {
        kenvp = kmalloc((EXEC_ENV_MAX + 1) * sizeof(char *));
        if (!kenvp) {
            ret = -ENOMEM;
            goto out;
        }
        for (int i = 0; i < EXEC_ENV_MAX; i++) {
            const char *uenv = NULL;
            if (copy_from_user(&uenv, &envp[i], sizeof(uenv)) < 0) {
                ret = -EFAULT;
                goto out;
            }
            if (!uenv)
                break;
            kenvp[i] = kmalloc(CONFIG_PATH_MAX);
            if (!kenvp[i]) {
                ret = -ENOMEM;
                goto out;
            }
            envc = i + 1;
            long len = strncpy_from_user(kenvp[i], uenv, CONFIG_PATH_MAX);
            if (len < 0) {
                ret = (int)len;
                goto out;
            }
            if (len >= CONFIG_PATH_MAX - 1) {
                ret = -E2BIG;
                goto out;
            }
        }
        if (envc >= EXEC_ENV_MAX) {
            ret = -E2BIG;
            goto out;
        }
        kenvp[envc] = NULL;
    }

    path_init(&resolved);
    ret = vfs_namei(path, &resolved, NAMEI_FOLLOW);
    if (ret < 0)
        goto out;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        ret = -ENOENT;
        goto out;
    }
    vn = resolved.dentry->vnode;
    if (vn->type != VNODE_FILE) {
        dentry_put(resolved.dentry);
        ret = -EACCES;
        goto out;
    }

    size = vn->size;
    if (size < sizeof(Elf64_Ehdr)) {
        dentry_put(resolved.dentry);
        ret = -ENOEXEC;
        goto out;
    }

    if (!(new_mm = mm_create())) {
        dentry_put(resolved.dentry);
        ret = -ENOMEM;
        goto out;
    }
    struct elf_auxv_info aux;
    if (elf_load_vnode(new_mm, vn, size, &entry, &aux) < 0 ||
        elf_setup_stack(new_mm, kargv, kenvp, &sp, &aux) < 0) {
        mm_destroy(new_mm);
        dentry_put(resolved.dentry);
        ret = -ENOEXEC;
        goto out;
    }
    dentry_put(resolved.dentry);

    struct process *curr = proc_current();
    old_mm = curr->mm;
    curr->mm = new_mm;
    arch_mmu_switch(new_mm->pgdir);
    if (old_mm)
        mm_destroy(old_mm);
    fd_close_cloexec(curr);

    const char *name = strrchr(path, '/');
    strncpy(curr->name, name ? name + 1 : path, sizeof(curr->name) - 1);

    struct trap_frame *tf = get_current_trapframe();
    if (tf) {
        tf->sepc = entry;
        tf->tf_sp = sp;
        tf->tf_a0 = 0;
    }
    if (curr->vfork_parent) {
        __atomic_store_n(&curr->vfork_done, true, __ATOMIC_RELEASE);
        wait_queue_wakeup_all(&curr->vfork_wait);
        curr->vfork_parent = NULL;
    }
    ret = 0;
    goto out;

out:
    proc_free_strv(kargv, argc);
    proc_free_strv(kenvp, envc);
    return ret;
}

struct process *proc_spawn_from_vfs(const char *path,
                                    struct process *parent) {
    struct path resolved;
    path_init(&resolved);
    int ret = vfs_namei(path, &resolved, NAMEI_FOLLOW);
    if (ret < 0)
        return NULL;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        return NULL;
    }
    struct vnode *vn = resolved.dentry->vnode;
    if (vn->type != VNODE_FILE) {
        dentry_put(resolved.dentry);
        return NULL;
    }

    size_t size = vn->size;
    if (size == 0 || size > 2 * 1024 * 1024) {
        dentry_put(resolved.dentry);
        return NULL;
    }

    void *elf_data = kmalloc(size);
    if (!elf_data) {
        dentry_put(resolved.dentry);
        return NULL;
    }

    struct file tmp_file;
    memset(&tmp_file, 0, sizeof(tmp_file));
    tmp_file.vnode = vn;
    tmp_file.offset = 0;
    mutex_init(&tmp_file.lock, "tmp_spawn");
    if (vfs_read(&tmp_file, elf_data, size) < (ssize_t)size) {
        kfree(elf_data);
        dentry_put(resolved.dentry);
        return NULL;
    }
    dentry_put(resolved.dentry);

    const char *name = strrchr(path, '/');
    struct process *p = proc_create(name ? name + 1 : path, elf_data, size);
    kfree(elf_data);
    if (!p)
        return NULL;

    if (parent)
        proc_adopt_child(parent, p);
    else
        strcpy(p->cwd, "/");

    return p;
}
