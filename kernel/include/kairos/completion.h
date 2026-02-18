/**
 * kernel/include/kairos/completion.h - One-shot event synchronization
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

void completion_init(struct completion *c);
void wait_for_completion(struct completion *c);
int  wait_for_completion_interruptible(struct completion *c);
int  wait_for_completion_timeout(struct completion *c, uint64_t ticks);
void complete_one(struct completion *c);
void complete_all(struct completion *c);
void reinit_completion(struct completion *c);

#endif
