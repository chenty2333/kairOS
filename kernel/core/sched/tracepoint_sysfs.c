/**
 * kernel/core/sched/tracepoint_sysfs.c - Sysfs export for tracepoint rings
 */

#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/pollwait.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/sysfs.h>
#include <kairos/tracepoint.h>

__attribute__((weak)) struct sysfs_node *sysfs_kernel_dir(void) {
    return sysfs_root();
}

static struct sysfs_node *tracepoint_sysfs_dir;

static const char *tracepoint_event_name(uint16_t event) {
    switch (event) {
    case TRACE_WAIT_BLOCK:
        return "wait_block";
    case TRACE_WAIT_WAKE:
        return "wait_wake";
    case TRACE_IO_COPY_RANGE_FAST:
        return "io_copy_range_fast";
    case TRACE_IO_COPY_RANGE_FALLBACK:
        return "io_copy_range_fallback";
    case TRACE_SOCKET_INLINE_BUF:
        return "socket_inline_buf";
    case TRACE_SOCKET_HEAP_BUF:
        return "socket_heap_buf";
    case TRACE_WAIT_EPOLL:
        return "wait_epoll";
    case TRACE_WAIT_FD_EVENT:
        return "wait_fd_event";
    default:
        return "unknown";
    }
}

static bool tracepoint_wait_event_legacy(uint16_t event) {
    return event == TRACE_WAIT_BLOCK || event == TRACE_WAIT_WAKE;
}

static bool tracepoint_wait_event_core(uint16_t event) {
    return event == TRACE_WAIT_BLOCK || event == TRACE_WAIT_WAKE ||
           event == TRACE_WAIT_EPOLL || event == TRACE_WAIT_FD_EVENT;
}

static ssize_t tracepoint_wait_events_show_filtered(char *buf, size_t bufsz,
                                                    bool (*match)(uint16_t)) {
    if (!buf || bufsz == 0)
        return -EINVAL;

#if !CONFIG_TRACEPOINTS
    int n = snprintf(buf, bufsz, "# tracepoints disabled\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return n;
#else
    size_t off = 0;
    int n = snprintf(buf + off, bufsz - off,
                     "# ticks cpu seq pid event flags arg0 arg1\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz - off)
        return (ssize_t)bufsz;
    off += (size_t)n;

    struct tracepoint_entry *entries =
        kmalloc(sizeof(*entries) * CONFIG_TRACEPOINT_PER_CPU);
    if (!entries)
        return -ENOMEM;

    for (int cpu = 0; cpu < CONFIG_MAX_CPUS; cpu++) {
        size_t nr = tracepoint_snapshot_cpu(cpu, entries,
                                            CONFIG_TRACEPOINT_PER_CPU);
        for (size_t i = 0; i < nr; i++) {
            struct tracepoint_entry *ent = &entries[i];
            if (ent->seq == 0)
                continue;
            if (!match(ent->event))
                continue;

            n = snprintf(buf + off, bufsz - off,
                         "%llu %u %u %d %s 0x%08x 0x%llx 0x%llx\n",
                         (unsigned long long)ent->ticks, (unsigned int)ent->cpu,
                         (unsigned int)ent->seq, ent->pid,
                         tracepoint_event_name(ent->event),
                         (unsigned int)ent->flags,
                         (unsigned long long)ent->arg0,
                         (unsigned long long)ent->arg1);
            if (n < 0) {
                kfree(entries);
                return -EINVAL;
            }
            if ((size_t)n >= bufsz - off) {
                kfree(entries);
                return (ssize_t)bufsz;
            }
            off += (size_t)n;
        }
    }

    kfree(entries);
    return (ssize_t)off;
#endif
}

static ssize_t tracepoint_wait_events_show(void *priv __attribute__((unused)),
                                           char *buf, size_t bufsz) {
    return tracepoint_wait_events_show_filtered(buf, bufsz,
                                                tracepoint_wait_event_legacy);
}

static ssize_t
tracepoint_wait_core_events_show(void *priv __attribute__((unused)), char *buf,
                                 size_t bufsz) {
    return tracepoint_wait_events_show_filtered(buf, bufsz,
                                                tracepoint_wait_event_core);
}

static ssize_t tracepoint_wait_core_stats_show(void *priv __attribute__((unused)),
                                               char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t off = 0;
    int n = snprintf(buf + off, bufsz - off, "# name value\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz - off)
        return (ssize_t)bufsz;
    off += (size_t)n;

    uint64_t stats[POLL_WAIT_STAT_COUNT] = {0};
    poll_wait_stats_snapshot(stats);
    for (uint32_t i = 0; i < POLL_WAIT_STAT_COUNT; i++) {
        n = snprintf(buf + off, bufsz - off, "%s %llu\n",
                     poll_wait_stat_name((enum poll_wait_stat)i),
                     (unsigned long long)stats[i]);
        if (n < 0)
            return -EINVAL;
        if ((size_t)n >= bufsz - off)
            return (ssize_t)bufsz;
        off += (size_t)n;
    }

    return (ssize_t)off;
}

static ssize_t tracepoint_reset_store(void *priv __attribute__((unused)),
                                      const char *buf __attribute__((unused)),
                                      size_t len) {
    tracepoint_reset_all();
    poll_wait_stats_reset();
    return (ssize_t)len;
}

static const struct sysfs_attribute tracepoint_sysfs_attrs[] = {
    {
        .name = "wait_events",
        .mode = 0444,
        .show = tracepoint_wait_events_show,
        .store = NULL,
        .priv = NULL,
    },
    {
        .name = "wait_core_events",
        .mode = 0444,
        .show = tracepoint_wait_core_events_show,
        .store = NULL,
        .priv = NULL,
    },
    {
        .name = "wait_core_stats",
        .mode = 0444,
        .show = tracepoint_wait_core_stats_show,
        .store = NULL,
        .priv = NULL,
    },
    {
        .name = "reset",
        .mode = 0200,
        .show = NULL,
        .store = tracepoint_reset_store,
        .priv = NULL,
    },
};

void tracepoint_sysfs_init(void) {
    if (tracepoint_sysfs_dir)
        return;

    struct sysfs_node *kernel_dir = sysfs_kernel_dir();
    if (!kernel_dir) {
        pr_warn("tracepoint: sysfs kernel dir unavailable\n");
        return;
    }

    tracepoint_sysfs_dir = sysfs_mkdir(kernel_dir, "tracepoint");
    if (!tracepoint_sysfs_dir) {
        pr_warn("tracepoint: sysfs mkdir /sys/kernel/tracepoint failed\n");
        return;
    }

    int ret = sysfs_create_files(tracepoint_sysfs_dir, tracepoint_sysfs_attrs,
                                 sizeof(tracepoint_sysfs_attrs) /
                                     sizeof(tracepoint_sysfs_attrs[0]));
    if (ret < 0) {
        pr_warn("tracepoint: sysfs attribute creation failed (ret=%d)\n", ret);
        sysfs_rmdir(tracepoint_sysfs_dir);
        tracepoint_sysfs_dir = NULL;
        return;
    }
}
