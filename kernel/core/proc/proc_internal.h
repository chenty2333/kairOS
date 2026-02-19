/**
 * kernel/core/proc/proc_internal.h - Process internals
 */

#ifndef _KAIROS_PROC_INTERNAL_H
#define _KAIROS_PROC_INTERNAL_H

#include <kairos/process.h>

extern struct process proc_table[CONFIG_MAX_PROCESSES];
extern spinlock_t proc_table_lock;
extern bool proc_table_irq_flags;
extern pid_t next_pid;
extern struct process *reaper_proc;

struct process *proc_alloc(void);
void proc_free(struct process *p);
void proc_adopt_child(struct process *parent, struct process *child);
struct process *proc_spawn_from_vfs(const char *path,
                                    struct process *parent);

#endif
