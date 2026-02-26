/**
 * kernel/core/sched/tracepoint.c - Lightweight tracepoint ring buffers
 */

#include <kairos/arch.h>
#include <kairos/atomic.h>
#include <kairos/config.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/tracepoint.h>

struct tracepoint_cpu_buf {
    atomic_t head;
    struct tracepoint_entry entries[CONFIG_TRACEPOINT_PER_CPU];
};

static struct tracepoint_cpu_buf tracepoint_bufs[CONFIG_MAX_CPUS];

void tracepoint_emit(enum tracepoint_event event, uint32_t flags,
                     uint64_t arg0, uint64_t arg1) {
#if CONFIG_TRACEPOINTS
    int cpu = arch_cpu_id();
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        cpu = 0;

    struct tracepoint_cpu_buf *buf = &tracepoint_bufs[cpu];
    uint32_t seq = atomic_add_return(&buf->head, 1);
    uint32_t idx = (seq - 1) % CONFIG_TRACEPOINT_PER_CPU;

    struct process *curr = proc_current();
    struct tracepoint_entry *entry = &buf->entries[idx];
    entry->ticks = arch_timer_get_ticks();
    entry->seq = seq;
    entry->cpu = (uint16_t)cpu;
    entry->event = (uint16_t)event;
    entry->pid = curr ? curr->pid : -1;
    entry->flags = flags;
    entry->arg0 = arg0;
    entry->arg1 = arg1;
#else
    (void)event;
    (void)flags;
    (void)arg0;
    (void)arg1;
#endif
}

size_t tracepoint_snapshot_cpu(int cpu, struct tracepoint_entry *out,
                               size_t max_entries) {
#if CONFIG_TRACEPOINTS
    if (!out || max_entries == 0)
        return 0;
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        return 0;

    const struct tracepoint_cpu_buf *buf = &tracepoint_bufs[cpu];
    uint32_t head = atomic_read(&buf->head);
    size_t available = head < CONFIG_TRACEPOINT_PER_CPU ? (size_t)head
                                                        : CONFIG_TRACEPOINT_PER_CPU;
    if (available > max_entries)
        available = max_entries;
    if (available == 0)
        return 0;

    uint32_t start = (head >= available)
                         ? (head - (uint32_t)available)
                         : 0;
    for (size_t i = 0; i < available; i++) {
        uint32_t pos = (start + (uint32_t)i) % CONFIG_TRACEPOINT_PER_CPU;
        out[i] = buf->entries[pos];
    }
    return available;
#else
    (void)cpu;
    (void)out;
    (void)max_entries;
    return 0;
#endif
}

void tracepoint_reset_all(void) {
#if CONFIG_TRACEPOINTS
    memset(tracepoint_bufs, 0, sizeof(tracepoint_bufs));
#endif
}
