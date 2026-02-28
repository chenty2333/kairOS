#ifndef _KAIROS_FAULT_INJECT_H
#define _KAIROS_FAULT_INJECT_H

#include <kairos/types.h>

enum fault_inject_point {
    FAULT_INJECT_POINT_KMALLOC = 0,
    FAULT_INJECT_POINT_COPY_FROM_USER = 1,
    FAULT_INJECT_POINT_COPY_TO_USER = 2,
    FAULT_INJECT_POINT_IPC_CHANNEL_SEND = 3,
    FAULT_INJECT_POINT_IPC_CHANNEL_RECV = 4,
    FAULT_INJECT_POINT_IPC_CHANNEL_CLOSE = 5,
    FAULT_INJECT_POINT_POLLWAIT_BLOCK = 6,
    FAULT_INJECT_POINT_POLLWAIT_WAKE = 7,
    FAULT_INJECT_POINT_MAX,
};

void fault_inject_reset(void);
void fault_inject_set_seed(uint64_t seed);
void fault_inject_enable(bool enabled);
bool fault_inject_enabled(void);
void fault_inject_scope_enter(void);
void fault_inject_scope_exit(void);
void fault_inject_set_rate_permille(enum fault_inject_point point,
                                    uint32_t permille);
void fault_inject_set_warmup_hits(enum fault_inject_point point,
                                  uint64_t warmup_hits);
void fault_inject_set_fail_budget(enum fault_inject_point point,
                                  uint64_t fail_budget);
bool fault_inject_should_fail(enum fault_inject_point point);
uint64_t fault_inject_hits(enum fault_inject_point point);
uint64_t fault_inject_failures(enum fault_inject_point point);
const char *fault_inject_point_name(enum fault_inject_point point);

#endif /* _KAIROS_FAULT_INJECT_H */
