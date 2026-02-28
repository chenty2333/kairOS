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
    TRACE_WAIT_FUTEX = 9,
    TRACE_IPC_CHANNEL = 10,
    TRACE_IPC_CAP = 11,
};

enum trace_ipc_channel_op {
    TRACE_IPC_CH_OP_SEND_EPIPE = 1,
    TRACE_IPC_CH_OP_RECV_EOF = 2,
    TRACE_IPC_CH_OP_CLOSE_LOCAL = 3,
    TRACE_IPC_CH_OP_CLOSE_PEER = 4,
};

enum trace_ipc_channel_wake {
    TRACE_IPC_CH_WAKE_NONE = 0,
    TRACE_IPC_CH_WAKE_DATA = 1,
    TRACE_IPC_CH_WAKE_HUP = 2,
    TRACE_IPC_CH_WAKE_CLOSE = 3,
    TRACE_IPC_CH_WAKE_SIGNAL = 4,
    TRACE_IPC_CH_WAKE_TIMEOUT = 5,
};

enum trace_ipc_channel_endpoint_state {
    TRACE_IPC_CH_STATE_UNKNOWN = 0,
    TRACE_IPC_CH_STATE_OPEN = 1,
    TRACE_IPC_CH_STATE_CLOSING = 2,
    TRACE_IPC_CH_STATE_CLOSED = 3,
};

enum trace_ipc_cap_op {
    TRACE_IPC_CAP_OP_REVOKE_MARKED = 1,
    TRACE_IPC_CAP_OP_BIND_REJECTED_REVOKED = 2,
    TRACE_IPC_CAP_OP_COMMIT_EAGAIN = 3,
    TRACE_IPC_CAP_OP_TRYGET_FAILED = 4,
};

#define TRACE_IPC_CH_FLAG_OP_SHIFT          0U
#define TRACE_IPC_CH_FLAG_OP_MASK           0x000000ffU
#define TRACE_IPC_CH_FLAG_WAKE_SHIFT        8U
#define TRACE_IPC_CH_FLAG_WAKE_MASK         0x00000f00U
#define TRACE_IPC_CH_FLAG_SELF_STATE_SHIFT  12U
#define TRACE_IPC_CH_FLAG_SELF_STATE_MASK   0x0000f000U
#define TRACE_IPC_CH_FLAG_PEER_STATE_SHIFT  16U
#define TRACE_IPC_CH_FLAG_PEER_STATE_MASK   0x000f0000U
#define TRACE_IPC_CH_FLAG_VERSION_SHIFT     28U
#define TRACE_IPC_CH_FLAG_VERSION_MASK      0xf0000000U
#define TRACE_IPC_CH_FLAG_VERSION_V1        1U

#define TRACE_IPC_CAP_FLAG_OP_SHIFT      0U
#define TRACE_IPC_CAP_FLAG_OP_MASK       0x000000ffU
#define TRACE_IPC_CAP_FLAG_VERSION_SHIFT 28U
#define TRACE_IPC_CAP_FLAG_VERSION_MASK  0xf0000000U
#define TRACE_IPC_CAP_FLAG_VERSION_V1    1U

static inline uint32_t
trace_ipc_channel_flags_build(enum trace_ipc_channel_op op,
                              enum trace_ipc_channel_wake wake,
                              enum trace_ipc_channel_endpoint_state self_state,
                              enum trace_ipc_channel_endpoint_state peer_state) {
    return (((uint32_t)op << TRACE_IPC_CH_FLAG_OP_SHIFT) &
            TRACE_IPC_CH_FLAG_OP_MASK) |
           (((uint32_t)wake << TRACE_IPC_CH_FLAG_WAKE_SHIFT) &
            TRACE_IPC_CH_FLAG_WAKE_MASK) |
           (((uint32_t)self_state << TRACE_IPC_CH_FLAG_SELF_STATE_SHIFT) &
            TRACE_IPC_CH_FLAG_SELF_STATE_MASK) |
           (((uint32_t)peer_state << TRACE_IPC_CH_FLAG_PEER_STATE_SHIFT) &
            TRACE_IPC_CH_FLAG_PEER_STATE_MASK) |
           ((TRACE_IPC_CH_FLAG_VERSION_V1 << TRACE_IPC_CH_FLAG_VERSION_SHIFT) &
            TRACE_IPC_CH_FLAG_VERSION_MASK);
}

static inline uint32_t trace_ipc_channel_flags_version(uint32_t flags) {
    return (flags & TRACE_IPC_CH_FLAG_VERSION_MASK) >>
           TRACE_IPC_CH_FLAG_VERSION_SHIFT;
}

static inline enum trace_ipc_channel_op
trace_ipc_channel_flags_op(uint32_t flags) {
    return (enum trace_ipc_channel_op)((flags & TRACE_IPC_CH_FLAG_OP_MASK) >>
                                       TRACE_IPC_CH_FLAG_OP_SHIFT);
}

static inline enum trace_ipc_channel_wake
trace_ipc_channel_flags_wake(uint32_t flags) {
    return (enum trace_ipc_channel_wake)((flags & TRACE_IPC_CH_FLAG_WAKE_MASK) >>
                                         TRACE_IPC_CH_FLAG_WAKE_SHIFT);
}

static inline enum trace_ipc_channel_endpoint_state
trace_ipc_channel_flags_self_state(uint32_t flags) {
    return (enum trace_ipc_channel_endpoint_state)(
        (flags & TRACE_IPC_CH_FLAG_SELF_STATE_MASK) >>
        TRACE_IPC_CH_FLAG_SELF_STATE_SHIFT);
}

static inline enum trace_ipc_channel_endpoint_state
trace_ipc_channel_flags_peer_state(uint32_t flags) {
    return (enum trace_ipc_channel_endpoint_state)(
        (flags & TRACE_IPC_CH_FLAG_PEER_STATE_MASK) >>
        TRACE_IPC_CH_FLAG_PEER_STATE_SHIFT);
}

static inline uint32_t
trace_ipc_cap_flags_build(enum trace_ipc_cap_op op) {
    return (((uint32_t)op << TRACE_IPC_CAP_FLAG_OP_SHIFT) &
            TRACE_IPC_CAP_FLAG_OP_MASK) |
           ((TRACE_IPC_CAP_FLAG_VERSION_V1 << TRACE_IPC_CAP_FLAG_VERSION_SHIFT) &
            TRACE_IPC_CAP_FLAG_VERSION_MASK);
}

static inline uint32_t trace_ipc_cap_flags_version(uint32_t flags) {
    return (flags & TRACE_IPC_CAP_FLAG_VERSION_MASK) >>
           TRACE_IPC_CAP_FLAG_VERSION_SHIFT;
}

static inline enum trace_ipc_cap_op trace_ipc_cap_flags_op(uint32_t flags) {
    return (enum trace_ipc_cap_op)((flags & TRACE_IPC_CAP_FLAG_OP_MASK) >>
                                   TRACE_IPC_CAP_FLAG_OP_SHIFT);
}

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
