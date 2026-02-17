/**
 * kernel/core/proc/proc_fork.c - Fork and clone helpers
 */

#include <kairos/arch.h>
#include <kairos/clone.h>
#include <kairos/config.h>
#include <kairos/dentry.h>
#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#include "proc_internal.h"

struct process *proc_fork_ex(const struct proc_fork_opts *opts) {
    struct process *parent = proc_current(), *child;
    if (!parent || !parent->mm || !(child = proc_alloc()))
        return NULL;

    strcpy(child->name, parent->name);
    child->uid = parent->uid;
    child->gid = parent->gid;
    child->pgid = parent->pgid;
    child->sid = parent->sid;
    child->umask = parent->umask;
    child->tid_address = parent->tid_address;
    child->tid_set_address = 0;
    child->robust_list = parent->robust_list;
    child->robust_len = parent->robust_len;
    child->itimer_real = parent->itimer_real;
    child->sigaltstack = parent->sigaltstack;
    memcpy(child->rlimits, parent->rlimits, sizeof(child->rlimits));
    child->parent = parent;
    child->ppid = parent->pid;
    sched_fork(child, parent);
    child->vfork_parent = NULL;
    child->vfork_done = true;

    if (opts) {
        if (opts->tid_set_address)
            child->tid_set_address = opts->tid_set_address;
        if (opts->tid_clear_address)
            child->tid_address = opts->tid_clear_address;
        if (opts->vfork_parent) {
            child->vfork_parent = opts->vfork_parent;
            child->vfork_done = false;
        }
    }

    spin_lock(&proc_table_lock);
    list_add(&child->sibling, &parent->children);
    spin_unlock(&proc_table_lock);

    memcpy(child->cwd, parent->cwd, CONFIG_PATH_MAX);
    child->cwd_vnode = parent->cwd_vnode;
    if (child->cwd_vnode)
        vnode_get(child->cwd_vnode);
    child->cwd_dentry = parent->cwd_dentry;
    if (child->cwd_dentry)
        dentry_get(child->cwd_dentry);
    if (child->mnt_ns) {
        vfs_mount_ns_put(child->mnt_ns);
        child->mnt_ns = NULL;
    }
    child->mnt_ns = parent->mnt_ns;
    if (child->mnt_ns)
        vfs_mount_ns_get_from(child->mnt_ns);
    child->syscall_abi = parent->syscall_abi;

    uint64_t clone_flags = opts ? opts->clone_flags : 0;

    /* File descriptor table: share or copy */
    if (clone_flags & CLONE_FILES) {
        fdtable_get(parent->fdtable);
        child->fdtable = parent->fdtable;
    } else {
        child->fdtable = fdtable_copy(parent->fdtable);
        if (!child->fdtable) {
            proc_free(child);
            return NULL;
        }
    }

    /* Signal handlers: share or copy */
    if (clone_flags & CLONE_SIGHAND) {
        sighand_get(parent->sighand);
        child->sighand = parent->sighand;
    } else if (parent->sighand) {
        child->sighand = sighand_copy(parent->sighand);
        if (!child->sighand) {
            proc_free(child);
            return NULL;
        }
    }

    /* Thread group */
    if (clone_flags & CLONE_THREAD) {
        child->tgid = parent->tgid;
        child->group_leader = parent->group_leader;
        spin_lock(&proc_table_lock);
        list_add_tail(&child->thread_group, &parent->group_leader->thread_group);
        spin_unlock(&proc_table_lock);
    }

    /* Address space: share or clone */
    if (clone_flags & CLONE_VM) {
        child->mm = parent->mm;
        mm_get(parent->mm);
    } else {
        if (!(child->mm = mm_clone(parent->mm))) {
            proc_free(child);
            return NULL;
        }
    }

    /* TLS */
    if ((clone_flags & CLONE_SETTLS) && opts) {
        arch_set_tls(child->context, opts->tls);
    }

    struct trap_frame *tf = get_current_trapframe();
    if (tf) {
        arch_setup_fork_child(child->context, tf);
        if (opts && opts->child_stack)
            arch_context_set_user_sp(child->context, opts->child_stack);
    } else {
        arch_context_clone(child->context, parent->context);
    }

    child->state = PROC_RUNNABLE;
    sched_enqueue(child);
    return child;
}

struct process *proc_fork(void) {
    return proc_fork_ex(NULL);
}

void proc_fork_child_setup(void) {
    struct process *p = proc_current();
    if (!p)
        return;
    if (p->tid_set_address) {
        pid_t tid = p->pid;
        copy_to_user((void *)p->tid_set_address, &tid, sizeof(tid));
        p->tid_set_address = 0;
    }
}
