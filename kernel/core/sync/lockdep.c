/**
 * kernel/core/sync/lockdep.c - Lightweight lock dependency checker
 */

#include <kairos/config.h>

#if CONFIG_LOCKDEP

#include <kairos/lockdep.h>
#include <kairos/spinlock.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/sched.h>

#define DEP_ROW_BYTES ((LOCKDEP_MAX_CLASSES + 7) / 8)
static uint8_t dep_matrix[LOCKDEP_MAX_CLASSES][DEP_ROW_BYTES];

static int next_class_id;
static spinlock_t lockdep_lock = SPINLOCK_INIT;

static int held_stacks[CONFIG_MAX_CPUS][LOCKDEP_HELD_MAX];
static int held_depth[CONFIG_MAX_CPUS];

static int class_ensure(struct lock_class_key *key) {
    if (key->id != 0)
        return key->id;
    spin_lock(&lockdep_lock);
    if (key->id == 0) {
        next_class_id++;
        if (next_class_id >= LOCKDEP_MAX_CLASSES) {
            spin_unlock(&lockdep_lock);
            return -1;
        }
        key->id = next_class_id;
    }
    spin_unlock(&lockdep_lock);
    return key->id;
}

static inline void dep_set(int from, int to) {
    /* Racy RMW across CPUs — acceptable for debug-only heuristic.
     * Worst case: a dependency edge is silently dropped. */
    dep_matrix[from][to / 8] |= (uint8_t)(1 << (to % 8));
}

static inline bool dep_test(int from, int to) {
    return (dep_matrix[from][to / 8] & (1 << (to % 8))) != 0;
}

void lockdep_acquire(struct lock_class_key *key, const char *name) {
    int cpu = arch_cpu_id();
    int id = class_ensure(key);
    if (id < 0)
        return;
    int depth = held_depth[cpu];

    for (int i = 0; i < depth; i++) {
        int held_id = held_stacks[cpu][i];
        if (dep_test(id, held_id)) {
            printk("[LOCKDEP] possible deadlock: '%s' (class %d) "
                   "vs held class %d on CPU %d\n",
                   name ? name : "?", id, held_id, cpu);
        }
        dep_set(held_id, id);
    }

    if (depth < LOCKDEP_HELD_MAX) {
        held_stacks[cpu][depth] = id;
        held_depth[cpu] = depth + 1;
    }
}

void lockdep_release(struct lock_class_key *key) {
    int cpu = arch_cpu_id();
    int id = class_ensure(key);
    if (id < 0)
        return;
    int depth = held_depth[cpu];

    for (int i = depth - 1; i >= 0; i--) {
        if (held_stacks[cpu][i] == id) {
            for (int j = i; j < depth - 1; j++)
                held_stacks[cpu][j] = held_stacks[cpu][j + 1];
            held_depth[cpu] = depth - 1;
            return;
        }
    }
}

#endif
