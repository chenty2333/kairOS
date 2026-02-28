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

static const char *proc_exec_errno_name(int err) {
    int e = (err < 0) ? -err : err;
    switch (e) {
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case EIO: return "EIO";
    case E2BIG: return "E2BIG";
    case ENOEXEC: return "ENOEXEC";
    case ENOMEM: return "ENOMEM";
    case EACCES: return "EACCES";
    case EFAULT: return "EFAULT";
    case EBUSY: return "EBUSY";
    case EEXIST: return "EEXIST";
    case ENODEV: return "ENODEV";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    case EINVAL: return "EINVAL";
    case ENFILE: return "ENFILE";
    case EMFILE: return "EMFILE";
    case EFBIG: return "EFBIG";
    case ENOSPC: return "ENOSPC";
    case ESPIPE: return "ESPIPE";
    case EROFS: return "EROFS";
    case ENOSYS: return "ENOSYS";
    case ELOOP: return "ELOOP";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    default: return "EUNKNOWN";
    }
}

static const char *proc_exec_fail_reason(const char *stage, int err) {
    int e = (err < 0) ? -err : err;

    if (stage && strcmp(stage, "resolve_interp") == 0 && e == ENOENT)
        return "missing_interp";
    if (stage && strcmp(stage, "resolve_interp_type") == 0)
        return "invalid_interp_path";
    if (stage && strcmp(stage, "load_main_elf") == 0 && e == ENOEXEC)
        return "invalid_elf";
    if (stage && strcmp(stage, "load_interp_elf") == 0 && e == ENOEXEC)
        return "invalid_interp_elf";
    if (stage && strcmp(stage, "setup_stack") == 0 && e == E2BIG)
        return "argv_env_too_large";

    switch (e) {
    case EACCES: return "permission_denied";
    case ENOENT: return "path_not_found";
    case ENOEXEC: return "invalid_executable";
    case ENOMEM: return "out_of_memory";
    case EIO: return "io_error";
    case EFAULT: return "bad_user_pointer";
    case ENAMETOOLONG: return "path_too_long";
    default: return "exec_failed";
    }
}

static bool proc_exec_should_log_failure(const char *stage, int err) {
    if (err >= 0)
        return false;
    if (stage && strcmp(stage, "resolve_exec") == 0 && err == -ENOENT)
        return false;
    if (stage && strcmp(stage, "resolve_exec_dentry") == 0 && err == -ENOENT)
        return false;
    return true;
}

static void proc_exec_log_failure(const char *stage, const char *path,
                                  const char *interp_path, int err) {
    if (!proc_exec_should_log_failure(stage, err))
        return;
    struct process *curr = proc_current();
    pr_warn("exec: fail reason=%s stage=%s pid=%d comm=%s path=%s interp=%s errno=%d(%s)\n",
            proc_exec_fail_reason(stage, err), stage ? stage : "unknown",
            curr ? curr->pid : -1,
            (curr && curr->name[0]) ? curr->name : "?",
            path ? path : "?",
            interp_path ? interp_path : "-",
            -err, proc_exec_errno_name(err));
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
    char interp_path[CONFIG_PATH_MAX] = {0};
    bool has_interp = false;
    const char *fail_stage = "init";

    struct process *curr = proc_current();
    struct trap_frame *exec_tf = curr ? (struct trap_frame *)curr->active_tf : NULL;
    if (!curr) {
        ret = -EINVAL;
        goto out;
    }

    if (argv) {
        fail_stage = "copy_argv";
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
            if (len >= CONFIG_PATH_MAX) {
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
        fail_stage = "copy_envp";
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
            if (len >= CONFIG_PATH_MAX) {
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
    fail_stage = "resolve_exec";
    ret = vfs_namei(path, &resolved, resolve_flags);
    if (ret < 0)
        goto out;
    if (!resolved.dentry || !resolved.dentry->vnode) {
        fail_stage = "resolve_exec_dentry";
        if (resolved.dentry)
            dentry_put(resolved.dentry);
        ret = -ENOENT;
        goto out;
    }
    vn = resolved.dentry->vnode;
    if (vn->type != VNODE_FILE) {
        fail_stage = "resolve_exec_type";
        dentry_put(resolved.dentry);
        ret = -EACCES;
        goto out;
    }

    size = vn->size;
    if (size < sizeof(Elf64_Ehdr)) {
        fail_stage = "check_exec_size";
        dentry_put(resolved.dentry);
        ret = -ENOEXEC;
        goto out;
    }

    fail_stage = "read_interp";
    ret = elf_read_interp_vnode(vn, size, interp_path, sizeof(interp_path));
    if (ret == 0) {
        has_interp = true;
    } else if (ret != -ENOENT) {
        dentry_put(resolved.dentry);
        goto out;
    }

    fail_stage = "create_mm";
    if (!(new_mm = mm_create())) {
        dentry_put(resolved.dentry);
        ret = -ENOMEM;
        goto out;
    }
    fail_stage = "load_main_elf";
    ret = elf_load_vnode(new_mm, vn, size, &entry, &aux);
    dentry_put(resolved.dentry);
    if (ret < 0) {
        mm_destroy(new_mm);
        goto out;
    }
    aux.base = 0;

    if (has_interp) {
        path_init(&interp_resolved);
        fail_stage = "resolve_interp";
        ret = vfs_namei(interp_path, &interp_resolved, NAMEI_FOLLOW);
        if (ret < 0) {
            mm_destroy(new_mm);
            goto out;
        }
        if (!interp_resolved.dentry || !interp_resolved.dentry->vnode) {
            if (interp_resolved.dentry)
                dentry_put(interp_resolved.dentry);
            mm_destroy(new_mm);
            ret = -ENOENT;
            goto out;
        }
        if (interp_resolved.dentry->vnode->type != VNODE_FILE) {
            fail_stage = "resolve_interp_type";
            dentry_put(interp_resolved.dentry);
            mm_destroy(new_mm);
            ret = -EACCES;
            goto out;
        }
        struct vnode *ivn = interp_resolved.dentry->vnode;
        size_t interp_size = ivn->size;
        fail_stage = "load_interp_elf";
        ret = proc_load_interp_bias(new_mm, ivn, interp_size, path,
                                    &interp_entry, &interp_aux);
        dentry_put(interp_resolved.dentry);
        if (ret < 0) {
            mm_destroy(new_mm);
            goto out;
        }
        aux.base = interp_aux.base;
        entry = interp_entry;
    }

    fail_stage = "setup_stack";
    ret = elf_setup_stack(new_mm, kargv, kenvp, &sp, &aux);
    if (ret < 0) {
        mm_destroy(new_mm);
        goto out;
    }

    old_mm = curr->mm;
    curr->mm = new_mm;
    arch_mmu_switch(new_mm->pgdir);
    if (old_mm)
        mm_destroy(old_mm);
    fd_close_cloexec(curr);

    const char *name = strrchr(path, '/');
    strncpy(curr->name, name ? name + 1 : path, sizeof(curr->name) - 1);

    struct trap_frame *tf = exec_tf ? exec_tf : get_current_trapframe();
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
    if (ret < 0)
        proc_exec_log_failure(fail_stage, path, has_interp ? interp_path : NULL, ret);
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
