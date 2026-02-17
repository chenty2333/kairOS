/**
 * kernel/include/kairos/tick.h - Core tick policy interface
 */

#ifndef _KAIROS_TICK_H
#define _KAIROS_TICK_H

#include <kairos/types.h>

struct trap_core_event;

void tick_policy_init(int timekeeper_cpu);
void tick_policy_on_timer_irq(const struct trap_core_event *ev);
uint64_t tick_policy_get_ticks(void);

#endif
