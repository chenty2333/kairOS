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

static uint64_t proc_interp_bias_seed(const char *path) {
    uint64_t seed = arch_timer_get_ticks();
    struct process *curr = proc_current();
    if (curr) {
        seed ^= ((uint64_t)(uint32_t)curr->pid << 32);
        seed ^= (uint64_t)(uint32_t)curr->tgid;
    }
    if (path) {
        const unsigned char *p = (const unsigned char *)path;
        while (*p) {
            seed = (seed * 11400714819323198485ULL) ^ (uint64_t)(*p++);
        }
    }
    return seed;
}

static int proc_load_interp_bias(struct mm_struct *mm, struct vnode *vn,
                                 size_t size, const char *exec_path,
                                 vaddr_t *entry_out,
                                 struct elf_auxv_info *aux_out) {
    vaddr_t base = ALIGN_DOWN((vaddr_t)CONFIG_ELF_INTERP_LOAD_BIAS_BASE,
                              CONFIG_PAGE_SIZE);
    uint64_t stride = CONFIG_ELF_INTERP_LOAD_BIAS_STRIDE;
    uint64_t slots = CONFIG_ELF_INTERP_LOAD_BIAS_SLOTS;

    if (stride < CONFIG_PAGE_SIZE)
        stride = CONFIG_PAGE_SIZE;
    stride = ALIGN_UP(stride, CONFIG_PAGE_SIZE);
    if (slots == 0)
        slots = 1;

    uint64_t seed = proc_interp_bias_seed(exec_path);
    int last_err = -ENOEXEC;

    for (uint64_t i = 0; i < slots; i++) {
        uint64_t slot = (seed + i) % slots;
        if (slot > ((~(uint64_t)0) - (uint64_t)base) / stride)
            continue;
        vaddr_t bias = base + (vaddr_t)(slot * stride);
        int ret = elf_load_vnode_bias(mm, vn, size, bias, entry_out, aux_out);
        if (ret == 0)
            return 0;
        last_err = ret;
        if (ret != -EEXIST)
            break;
    }

    if (slots > 1) {
        int ret = elf_load_vnode_bias(mm, vn, size, base, entry_out, aux_out);
        if (ret == 0)
            return 0;
        last_err = ret;
    }

    return last_err;
}

int proc_exec_resolve(const char *path, char *const argv[], char *const envp[],
                      int namei_flags) {
    enum { EXEC_ARG_MAX = 64, EXEC_ENV_MAX = 64 };
    char **kargv = NULL;
    char **kenvp = NULL;
    int argc = 0;
    int envc = 0;
    struct vnode *vn;
    struct path resolved;
    struct path interp_resolved;
    struct mm_struct *old_mm, *new_mm;
    vaddr_t entry, sp;
    vaddr_t interp_entry = 0;
    size_t size;
    int ret = 0;
    struct elf_auxv_info aux = {0};
    struct elf_auxv_info interp_aux = {0};
    char interp_path[CONFIG_PATH_MAX];
    bool has_interp = false;

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

    int resolve_flags = namei_flags;
    if ((resolve_flags & NAMEI_NOFOLLOW) == 0)
        resolve_flags |= NAMEI_FOLLOW;

    path_init(&resolved);
    ret = vfs_namei(path, &resolved, resolve_flags);
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

    ret = elf_read_interp_vnode(vn, size, interp_path, sizeof(interp_path));
    if (ret == 0) {
        has_interp = true;
    } else if (ret != -ENOENT) {
        dentry_put(resolved.dentry);
        goto out;
    }

    if (!(new_mm = mm_create())) {
        dentry_put(resolved.dentry);
        ret = -ENOMEM;
        goto out;
    }
    ret = elf_load_vnode(new_mm, vn, size, &entry, &aux);
    dentry_put(resolved.dentry);
    if (ret < 0) {
        mm_destroy(new_mm);
        ret = -ENOEXEC;
        goto out;
    }
    aux.base = 0;

    if (has_interp) {
        path_init(&interp_resolved);
        ret = vfs_namei(interp_path, &interp_resolved, NAMEI_FOLLOW);
        if (ret < 0 || !interp_resolved.dentry ||
            !interp_resolved.dentry->vnode ||
            interp_resolved.dentry->vnode->type != VNODE_FILE) {
            if (ret >= 0 && interp_resolved.dentry)
                dentry_put(interp_resolved.dentry);
            mm_destroy(new_mm);
            ret = -ENOEXEC;
            goto out;
        }
        struct vnode *ivn = interp_resolved.dentry->vnode;
        size_t interp_size = ivn->size;
        ret = proc_load_interp_bias(new_mm, ivn, interp_size, path,
                                    &interp_entry, &interp_aux);
        dentry_put(interp_resolved.dentry);
        if (ret < 0) {
            mm_destroy(new_mm);
            ret = -ENOEXEC;
            goto out;
        }
        aux.base = interp_aux.base;
        entry = interp_entry;
    }

    if (elf_setup_stack(new_mm, kargv, kenvp, &sp, &aux) < 0) {
        mm_destroy(new_mm);
        ret = -ENOEXEC;
        goto out;
    }

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
        complete_all(&curr->vfork_completion);
        curr->vfork_parent = NULL;
    }
    ret = 0;
    goto out;

out:
    proc_free_strv(kargv, argc);
    proc_free_strv(kenvp, envc);
    return ret;
}

int proc_exec(const char *path, char *const argv[], char *const envp[]) {
    return proc_exec_resolve(path, argv, envp, NAMEI_FOLLOW);
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
