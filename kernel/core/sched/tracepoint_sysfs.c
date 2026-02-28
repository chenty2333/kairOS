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
    case TRACE_WAIT_FUTEX:
        return "wait_futex";
    case TRACE_IPC_CHANNEL:
        return "ipc_channel";
    case TRACE_IPC_CAP:
        return "ipc_cap";
    default:
        return "unknown";
    }
}

static bool tracepoint_wait_event_legacy(uint16_t event) {
    return event == TRACE_WAIT_BLOCK || event == TRACE_WAIT_WAKE;
}

static bool tracepoint_wait_event_core(uint16_t event) {
    return event == TRACE_WAIT_BLOCK || event == TRACE_WAIT_WAKE ||
           event == TRACE_WAIT_EPOLL || event == TRACE_WAIT_FD_EVENT ||
           event == TRACE_WAIT_FUTEX;
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

static ssize_t tracepoint_ipc_events_show(void *priv __attribute__((unused)),
                                          char *buf, size_t bufsz) {
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
    int n = snprintf(
        buf + off, bufsz - off,
        "# schema=trace_ipc_channel_v1\n"
        "# ticks cpu seq pid event flags version op wake self_state peer_state "
        "self_id peer_id arg1\n");
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
            if (ent->seq == 0 || ent->event != TRACE_IPC_CHANNEL)
                continue;

            uint32_t flags = ent->flags;
            uint32_t version = trace_ipc_channel_flags_version(flags);
            enum trace_ipc_channel_op op = TRACE_IPC_CH_OP_SEND_EPIPE;
            enum trace_ipc_channel_wake wake = TRACE_IPC_CH_WAKE_NONE;
            enum trace_ipc_channel_endpoint_state self_state =
                TRACE_IPC_CH_STATE_UNKNOWN;
            enum trace_ipc_channel_endpoint_state peer_state =
                TRACE_IPC_CH_STATE_UNKNOWN;
            if (version == TRACE_IPC_CH_FLAG_VERSION_V1) {
                op = trace_ipc_channel_flags_op(flags);
                wake = trace_ipc_channel_flags_wake(flags);
                self_state = trace_ipc_channel_flags_self_state(flags);
                peer_state = trace_ipc_channel_flags_peer_state(flags);
            } else {
                op = (enum trace_ipc_channel_op)(flags & 0xffU);
            }

            const char *op_name = "unknown";
            switch (op) {
            case TRACE_IPC_CH_OP_SEND_EPIPE:
                op_name = "send_epipe";
                break;
            case TRACE_IPC_CH_OP_RECV_EOF:
                op_name = "recv_eof";
                break;
            case TRACE_IPC_CH_OP_CLOSE_LOCAL:
                op_name = "close_local";
                break;
            case TRACE_IPC_CH_OP_CLOSE_PEER:
                op_name = "close_peer";
                break;
            default:
                break;
            }

            const char *wake_name = "unknown";
            switch (wake) {
            case TRACE_IPC_CH_WAKE_NONE:
                wake_name = "none";
                break;
            case TRACE_IPC_CH_WAKE_DATA:
                wake_name = "data";
                break;
            case TRACE_IPC_CH_WAKE_HUP:
                wake_name = "hup";
                break;
            case TRACE_IPC_CH_WAKE_CLOSE:
                wake_name = "close";
                break;
            case TRACE_IPC_CH_WAKE_SIGNAL:
                wake_name = "signal";
                break;
            case TRACE_IPC_CH_WAKE_TIMEOUT:
                wake_name = "timeout";
                break;
            default:
                break;
            }

            const char *self_state_name = "unknown";
            switch (self_state) {
            case TRACE_IPC_CH_STATE_OPEN:
                self_state_name = "open";
                break;
            case TRACE_IPC_CH_STATE_CLOSING:
                self_state_name = "closing";
                break;
            case TRACE_IPC_CH_STATE_CLOSED:
                self_state_name = "closed";
                break;
            default:
                break;
            }

            const char *peer_state_name = "unknown";
            switch (peer_state) {
            case TRACE_IPC_CH_STATE_OPEN:
                peer_state_name = "open";
                break;
            case TRACE_IPC_CH_STATE_CLOSING:
                peer_state_name = "closing";
                break;
            case TRACE_IPC_CH_STATE_CLOSED:
                peer_state_name = "closed";
                break;
            default:
                break;
            }

            uint32_t self_id = (uint32_t)(ent->arg0 >> 32);
            uint32_t peer_id = (uint32_t)(ent->arg0 & 0xffffffffULL);
            n = snprintf(buf + off, bufsz - off,
                         "%llu %u %u %d %s 0x%08x %u %s %s %s %s %u %u 0x%llx\n",
                         (unsigned long long)ent->ticks, (unsigned int)ent->cpu,
                         (unsigned int)ent->seq, ent->pid,
                         tracepoint_event_name(ent->event), flags,
                         (unsigned int)version, op_name, wake_name,
                         self_state_name, peer_state_name, self_id, peer_id,
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

static ssize_t tracepoint_ipc_cap_events_show(void *priv __attribute__((unused)),
                                              char *buf, size_t bufsz) {
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
    int n = snprintf(
        buf + off, bufsz - off,
        "# schema=trace_ipc_cap_v1\n"
        "# ticks cpu seq pid event flags version op cap_id arg1\n");
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
            if (ent->seq == 0 || ent->event != TRACE_IPC_CAP)
                continue;

            uint32_t flags = ent->flags;
            uint32_t version = trace_ipc_cap_flags_version(flags);
            enum trace_ipc_cap_op op = TRACE_IPC_CAP_OP_REVOKE_MARKED;
            if (version == TRACE_IPC_CAP_FLAG_VERSION_V1)
                op = trace_ipc_cap_flags_op(flags);
            else
                op = (enum trace_ipc_cap_op)(flags & 0xffU);

            const char *op_name = "unknown";
            switch (op) {
            case TRACE_IPC_CAP_OP_REVOKE_MARKED:
                op_name = "revoke_marked";
                break;
            case TRACE_IPC_CAP_OP_BIND_REJECTED_REVOKED:
                op_name = "bind_rejected_revoked";
                break;
            case TRACE_IPC_CAP_OP_COMMIT_EAGAIN:
                op_name = "commit_eagain";
                break;
            case TRACE_IPC_CAP_OP_TRYGET_FAILED:
                op_name = "tryget_failed";
                break;
            default:
                break;
            }

            n = snprintf(buf + off, bufsz - off,
                         "%llu %u %u %d %s 0x%08x %u %s 0x%llx 0x%llx\n",
                         (unsigned long long)ent->ticks, (unsigned int)ent->cpu,
                         (unsigned int)ent->seq, ent->pid,
                         tracepoint_event_name(ent->event), flags,
                         (unsigned int)version, op_name,
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
        .name = "ipc_events",
        .mode = 0444,
        .show = tracepoint_ipc_events_show,
        .store = NULL,
        .priv = NULL,
    },
    {
        .name = "ipc_cap_events",
        .mode = 0444,
        .show = tracepoint_ipc_cap_events_show,
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
