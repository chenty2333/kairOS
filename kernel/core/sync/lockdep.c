/**
 * kernel/core/sync/lockdep.c - Lightweight lock dependency checker
 *
 * Tracks lock acquisition order across all CPUs and warns when a potential
 * AB-BA deadlock pattern is detected.
 *
 * Data structures:
 *   - dep_matrix[i][j/8] & (1<<(j%8)): "class i was held when class j acquired"
 *   - Per-CPU held stack (max LOCKDEP_HELD_MAX entries)
 */

#include <kairos/config.h>

#if CONFIG_LOCKDEP

#include <kairos/lockdep.h>
#include <kairos/spinlock.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/sched.h>

/* Dependency bit-matrix: dep[i][j/8] bit (j%8) = "i held when j acquired" */
#define DEP_ROW_BYTES ((LOCKDEP_MAX_CLASSES + 7) / 8)
static uint8_t dep_matrix[LOCKDEP_MAX_CLASSES][DEP_ROW_BYTES];

/* Class registry */
static int next_class_id;  /* 0 = unassigned sentinel */
static spinlock_t lockdep_lock = SPINLOCK_INIT;

/* Per-CPU held-lock stack */
struct held_entry {
    int class_id;
};
static struct held_entry held_stacks[CONFIG_MAX_CPUS][LOCKDEP_HELD_MAX];
static int held_depth[CONFIG_MAX_CPUS];

static int class_ensure(struct lock_class_key *key) {
    if (key->id != 0)
        return key->id;
    spin_lock(&lockdep_lock);
    if (key->id == 0) {
        next_class_id++;
        if (next_class_id >= LOCKDEP_MAX_CLASSES)
            next_class_id = LOCKDEP_MAX_CLASSES - 1;
        key->id = next_class_id;
    }
    spin_unlock(&lockdep_lock);
    return key->id;
}

static inline void dep_set(int from, int to) {
    dep_matrix[from][to / 8] |= (uint8_t)(1 << (to % 8));
}

static inline bool dep_test(int from, int to) {
    return (dep_matrix[from][to / 8] & (1 << (to % 8))) != 0;
}

void lockdep_acquire(struct lock_class_key *key, const char *name) {
    int cpu = arch_cpu_id();
    int id = class_ensure(key);
    int depth = held_depth[cpu];

    /* Check for order inversion: for each held lock h, if we've ever
     * seen 'id held when h acquired', that's an AB-BA pattern. */
    for (int i = 0; i < depth; i++) {
        int held_id = held_stacks[cpu][i].class_id;
        if (dep_test(id, held_id)) {
            printk("[LOCKDEP] possible deadlock: lock '%s' (class %d) "
                   "vs held class %d on CPU %d\n",
                   name ? name : "?", id, held_id, cpu);
        }
        /* Record: held_id was held when id was acquired */
        dep_set(held_id, id);
    }

    /* Push onto held stack */
    if (depth < LOCKDEP_HELD_MAX) {
        held_stacks[cpu][depth].class_id = id;
        held_depth[cpu] = depth + 1;
    }
}

void lockdep_release(struct lock_class_key *key) {
    int cpu = arch_cpu_id();
    int id = class_ensure(key);
    int depth = held_depth[cpu];

    /* Pop from held stack (search from top) */
    for (int i = depth - 1; i >= 0; i--) {
        if (held_stacks[cpu][i].class_id == id) {
            /* Shift remaining entries down */
            for (int j = i; j < depth - 1; j++)
                held_stacks[cpu][j] = held_stacks[cpu][j + 1];
            held_depth[cpu] = depth - 1;
            return;
        }
    }
}

#endif /* CONFIG_LOCKDEP */
