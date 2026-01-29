/**
 * kernel/core/proc/proc_init.c - init process startup
 */

#include <kairos/config.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>

#include "proc_internal.h"

#if CONFIG_EMBEDDED_INIT && defined(ARCH_riscv64)
#include "user_init_blob.h"
#endif

static int init_thread(void *arg __attribute__((unused))) {
    struct process *parent = proc_current();
    const char *init_paths[] = {"/init", "/sbin/init", "/bin/init"};
    struct process *child = NULL;

#if CONFIG_EMBEDDED_INIT && defined(ARCH_riscv64)
    if (user_init_elf_size > 0) {
        child = proc_create("init", user_init_elf, user_init_elf_size);
        if (child) {
            proc_adopt_child(parent, child);
            pr_info("init: started embedded init (pid %d)\n", child->pid);
            sched_enqueue(child);
        }
    }
#endif

    if (!child) {
        for (size_t i = 0; i < ARRAY_SIZE(init_paths); i++) {
            child = proc_spawn_from_vfs(init_paths[i], parent);
            if (child) {
                pr_info("init: started %s (pid %d)\n", init_paths[i], child->pid);
                sched_enqueue(child);
                break;
            }
        }
    }

    if (!child) {
        pr_warn("init: no user init found, running built-in user test\n");
        run_user_test();
    }

    while (1) {
        int status;
        pid_t pid = proc_wait(-1, &status, 0);
        if (pid < 0) {
            proc_yield();
            continue;
        }
        pr_info("init: reaped pid %d (status %d)\n", pid, status);
    }
}

struct process *proc_start_init(void) {
    struct process *p = kthread_create(init_thread, NULL, "init");
    if (!p)
        return NULL;
    reaper_proc = p;
    sched_enqueue(p);
    return p;
}
