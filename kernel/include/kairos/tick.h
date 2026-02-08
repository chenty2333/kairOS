/**
 * kernel/include/kairos/tick.h - Core tick policy interface
 */

#ifndef _KAIROS_TICK_H
#define _KAIROS_TICK_H

#include <kairos/types.h>

struct trap_frame;

void tick_policy_init(void);
void tick_policy_on_timer_irq(struct trap_frame *tf, bool from_user);
uint64_t tick_policy_get_ticks(void);

#endif
