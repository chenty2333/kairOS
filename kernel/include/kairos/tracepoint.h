/**
 * kernel/include/kairos/tracepoint.h - Lightweight tracepoint ring buffers
 */

#ifndef _KAIROS_TRACEPOINT_H
#define _KAIROS_TRACEPOINT_H

#include <kairos/config.h>
#include <kairos/types.h>

#ifndef CONFIG_TRACEPOINTS
#define CONFIG_TRACEPOINTS 1
#endif

#ifndef CONFIG_TRACEPOINT_PER_CPU
#define CONFIG_TRACEPOINT_PER_CPU 256
#endif

enum tracepoint_event {
    TRACE_WAIT_BLOCK = 1,
    TRACE_WAIT_WAKE = 2,
    TRACE_IO_COPY_RANGE_FAST = 3,
    TRACE_IO_COPY_RANGE_FALLBACK = 4,
    TRACE_SOCKET_INLINE_BUF = 5,
    TRACE_SOCKET_HEAP_BUF = 6,
    TRACE_WAIT_EPOLL = 7,
    TRACE_WAIT_FD_EVENT = 8,
};

struct tracepoint_entry {
    uint64_t ticks;
    uint32_t seq;
    uint16_t cpu;
    uint16_t event;
    int32_t pid;
    uint32_t flags;
    uint64_t arg0;
    uint64_t arg1;
};

void tracepoint_emit(enum tracepoint_event event, uint32_t flags,
                     uint64_t arg0, uint64_t arg1);
size_t tracepoint_snapshot_cpu(int cpu, struct tracepoint_entry *out,
                               size_t max_entries);
void tracepoint_reset_all(void);
void tracepoint_sysfs_init(void);

#endif
