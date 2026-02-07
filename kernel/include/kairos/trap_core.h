/**
 * kernel/include/kairos/trap_core.h - Core trap boundary interface
 */

#ifndef _KAIROS_TRAP_CORE_H
#define _KAIROS_TRAP_CORE_H

#include <kairos/types.h>

struct trap_frame;

enum trap_core_event_type {
    TRAP_CORE_EVENT_SYSCALL = 0,
    TRAP_CORE_EVENT_PAGE_FAULT,
    TRAP_CORE_EVENT_BREAKPOINT,
    TRAP_CORE_EVENT_ILLEGAL_INST,
    TRAP_CORE_EVENT_TIMER,
    TRAP_CORE_EVENT_EXT_IRQ,
    TRAP_CORE_EVENT_IPI,
    TRAP_CORE_EVENT_ARCH_OTHER
};

struct trap_core_event {
    enum trap_core_event_type type;
    struct trap_frame *tf;
    bool from_user;
    uint64_t code;
    uint64_t fault_addr;
};

struct trap_core_ops {
    int (*handle_event)(const struct trap_core_event *ev);
    bool (*should_deliver_signals)(const struct trap_core_event *ev);
};

void trap_core_dispatch(const struct trap_core_event *ev,
                        const struct trap_core_ops *ops);

#endif /* _KAIROS_TRAP_CORE_H */
