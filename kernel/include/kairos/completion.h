/**
 * kernel/include/kairos/completion.h - One-shot event synchronization
 *
 * Used for driver init handshakes, thread exit notification, etc.
 * Waiters sleep until complete_one() or complete_all() is called.
 */

#ifndef _KAIROS_COMPLETION_H
#define _KAIROS_COMPLETION_H

#include <kairos/spinlock.h>
#include <kairos/types.h>
#include <kairos/wait.h>

struct completion {
    uint32_t done;
    spinlock_t lock;
    struct wait_queue wq;
};

#define COMPLETION_INIT { .done = 0, .lock = SPINLOCK_INIT, }

void completion_init(struct completion *c);
void wait_for_completion(struct completion *c);
int  wait_for_completion_interruptible(struct completion *c);
int  wait_for_completion_timeout(struct completion *c, uint64_t ticks);
void complete_one(struct completion *c);
void complete_all(struct completion *c);
void reinit_completion(struct completion *c);

#endif /* _KAIROS_COMPLETION_H */
