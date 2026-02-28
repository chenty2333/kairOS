/**
 * kernel/core/tests/fault_inject.c - Lightweight fault injection controls
 */

#include <kairos/fault_inject.h>

static uint32_t fi_enabled;
static uint32_t fi_scope_depth;
static uint64_t fi_prng_state = 0x9e3779b97f4a7c15ULL;

static uint32_t fi_rate_permille[FAULT_INJECT_POINT_MAX];
static uint64_t fi_warmup_hits[FAULT_INJECT_POINT_MAX];
static uint64_t fi_fail_budget[FAULT_INJECT_POINT_MAX];
static uint64_t fi_hits_ctr[FAULT_INJECT_POINT_MAX];
static uint64_t fi_fail_ctr[FAULT_INJECT_POINT_MAX];

static inline bool point_valid(enum fault_inject_point point) {
    return (unsigned int)point < FAULT_INJECT_POINT_MAX;
}

static uint32_t fi_next_rand1000(void) {
    uint64_t old = __atomic_load_n(&fi_prng_state, __ATOMIC_RELAXED);
    while (1) {
        uint64_t x = old;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        uint64_t next = x * 2685821657736338717ULL;
        if (next == 0)
            next = 0x2545f4914f6cdd1dULL;
        if (__atomic_compare_exchange_n(&fi_prng_state, &old, next, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return (uint32_t)(next % 1000ULL);
    }
}

void fault_inject_reset(void) {
    __atomic_store_n(&fi_enabled, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&fi_scope_depth, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&fi_prng_state, 0x9e3779b97f4a7c15ULL, __ATOMIC_RELEASE);
    for (unsigned int i = 0; i < FAULT_INJECT_POINT_MAX; i++) {
        __atomic_store_n(&fi_rate_permille[i], 0, __ATOMIC_RELEASE);
        __atomic_store_n(&fi_warmup_hits[i], 0, __ATOMIC_RELEASE);
        __atomic_store_n(&fi_fail_budget[i], 0, __ATOMIC_RELEASE);
        __atomic_store_n(&fi_hits_ctr[i], 0, __ATOMIC_RELEASE);
        __atomic_store_n(&fi_fail_ctr[i], 0, __ATOMIC_RELEASE);
    }
}

void fault_inject_set_seed(uint64_t seed) {
    if (seed == 0)
        seed = 0x9e3779b97f4a7c15ULL;
    __atomic_store_n(&fi_prng_state, seed, __ATOMIC_RELEASE);
}

void fault_inject_enable(bool enabled) {
    __atomic_store_n(&fi_enabled, enabled ? 1U : 0U, __ATOMIC_RELEASE);
}

bool fault_inject_enabled(void) {
    return __atomic_load_n(&fi_enabled, __ATOMIC_ACQUIRE) != 0;
}

void fault_inject_scope_enter(void) {
    __atomic_add_fetch(&fi_scope_depth, 1, __ATOMIC_ACQ_REL);
}

void fault_inject_scope_exit(void) {
    uint32_t old = __atomic_load_n(&fi_scope_depth, __ATOMIC_ACQUIRE);
    while (old > 0) {
        if (__atomic_compare_exchange_n(&fi_scope_depth, &old, old - 1, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return;
    }
}

void fault_inject_set_rate_permille(enum fault_inject_point point,
                                    uint32_t permille) {
    if (!point_valid(point))
        return;
    if (permille > 1000U)
        permille = 1000U;
    __atomic_store_n(&fi_rate_permille[point], permille, __ATOMIC_RELEASE);
}

void fault_inject_set_warmup_hits(enum fault_inject_point point,
                                  uint64_t warmup_hits) {
    if (!point_valid(point))
        return;
    __atomic_store_n(&fi_warmup_hits[point], warmup_hits, __ATOMIC_RELEASE);
}

void fault_inject_set_fail_budget(enum fault_inject_point point,
                                  uint64_t fail_budget) {
    if (!point_valid(point))
        return;
    __atomic_store_n(&fi_fail_budget[point], fail_budget, __ATOMIC_RELEASE);
}

bool fault_inject_should_fail(enum fault_inject_point point) {
    if (!point_valid(point))
        return false;
    if (__atomic_load_n(&fi_enabled, __ATOMIC_ACQUIRE) == 0)
        return false;
    if (__atomic_load_n(&fi_scope_depth, __ATOMIC_ACQUIRE) == 0)
        return false;

    uint64_t hit = __atomic_add_fetch(&fi_hits_ctr[point], 1, __ATOMIC_ACQ_REL);
    uint64_t warmup = __atomic_load_n(&fi_warmup_hits[point], __ATOMIC_ACQUIRE);
    if (hit <= warmup)
        return false;

    uint32_t rate = __atomic_load_n(&fi_rate_permille[point], __ATOMIC_ACQUIRE);
    if (rate == 0)
        return false;

    uint64_t budget = __atomic_load_n(&fi_fail_budget[point], __ATOMIC_ACQUIRE);
    uint64_t done = __atomic_load_n(&fi_fail_ctr[point], __ATOMIC_ACQUIRE);
    if (budget != 0 && done >= budget)
        return false;

    if (fi_next_rand1000() >= rate)
        return false;

    done = __atomic_add_fetch(&fi_fail_ctr[point], 1, __ATOMIC_ACQ_REL);
    if (budget != 0 && done > budget) {
        __atomic_sub_fetch(&fi_fail_ctr[point], 1, __ATOMIC_ACQ_REL);
        return false;
    }
    return true;
}

uint64_t fault_inject_hits(enum fault_inject_point point) {
    if (!point_valid(point))
        return 0;
    return __atomic_load_n(&fi_hits_ctr[point], __ATOMIC_ACQUIRE);
}

uint64_t fault_inject_failures(enum fault_inject_point point) {
    if (!point_valid(point))
        return 0;
    return __atomic_load_n(&fi_fail_ctr[point], __ATOMIC_ACQUIRE);
}

const char *fault_inject_point_name(enum fault_inject_point point) {
    switch (point) {
    case FAULT_INJECT_POINT_KMALLOC:
        return "kmalloc";
    case FAULT_INJECT_POINT_COPY_FROM_USER:
        return "copy_from_user";
    case FAULT_INJECT_POINT_COPY_TO_USER:
        return "copy_to_user";
    case FAULT_INJECT_POINT_IPC_CHANNEL_SEND:
        return "ipc_channel_send";
    case FAULT_INJECT_POINT_IPC_CHANNEL_RECV:
        return "ipc_channel_recv";
    case FAULT_INJECT_POINT_IPC_CHANNEL_CLOSE:
        return "ipc_channel_close";
    case FAULT_INJECT_POINT_POLLWAIT_BLOCK:
        return "pollwait_block";
    case FAULT_INJECT_POINT_POLLWAIT_WAKE:
        return "pollwait_wake";
    default:
        return "unknown";
    }
}
