/**
 * kernel/core/tests/soak_tests.c - PR-level soak tests with low-rate injection
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/fault_inject.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/string.h>

#if CONFIG_KERNEL_TESTS

int run_driver_tests(void);
int run_mm_tests(void);
int run_syscall_trap_tests(void);
int run_vfs_ipc_tests(void);
int run_socket_tests(void);
int run_device_virtio_tests(void);
int run_tty_tests(void);
extern int run_sched_stress_tests(void);

struct soak_suite_entry {
    const char *name;
    int (*run)(void);
    uint32_t bit;
};

static const struct soak_suite_entry soak_suites[] = {
    {"driver", run_driver_tests, 1U << 0},
    {"mm", run_mm_tests, 1U << 1},
    {"syscall_trap", run_syscall_trap_tests, 1U << 2},
    {"vfs_ipc", run_vfs_ipc_tests, 1U << 3},
    {"socket", run_socket_tests, 1U << 4},
    {"device_virtio", run_device_virtio_tests, 1U << 5},
    {"tty", run_tty_tests, 1U << 6},
    {"sched", run_sched_stress_tests, 1U << 7},
};

static int tests_failed;
static uint64_t soak_prng_state = 0x6a09e667f3bcc909ULL;

static uint32_t soak_rand32(void) {
    uint64_t x = soak_prng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    soak_prng_state = x ? x : 0x9e3779b97f4a7c15ULL;
    return (uint32_t)((soak_prng_state * 2685821657736338717ULL) >> 32);
}

static int run_suite_once(const struct soak_suite_entry *suite, uint32_t iter) {
    int ret = suite->run();
    if (ret > 0) {
        pr_err("soak_pr: iter=%u suite=%s failed=%d\n", iter, suite->name, ret);
        return ret;
    }
    return 0;
}

static int soak_fault_probe_kmalloc(uint32_t iter) {
    static const size_t sizes[] = {8,   16,   32,   64,   96,   128,
                                   256, 512,  1024, 2048, 3072, 4096};
    int alloc_ok = 0;

    fault_inject_scope_enter();
    for (uint32_t i = 0; i < CONFIG_KERNEL_SOAK_PR_FAULT_PROBE_OPS; i++) {
        size_t sz = sizes[soak_rand32() % ARRAY_SIZE(sizes)];
        void *p = kmalloc(sz);
        if (!p)
            continue;
        memset(p, 0xA5, MIN(sz, 64));
        kfree(p);
        alloc_ok++;
    }
    fault_inject_scope_exit();

    if (alloc_ok == 0) {
        pr_err("soak_pr: iter=%u kmalloc fault probe made no progress\n", iter);
        return 1;
    }
    return 0;
}

int run_soak_tests(void) {
    uint64_t start_ticks = arch_timer_ticks();
    uint64_t duration_ns =
        (uint64_t)CONFIG_KERNEL_SOAK_PR_DURATION_SEC * 1000000000ULL;
    uint64_t duration_ticks = arch_timer_ns_to_ticks(duration_ns);
    size_t enabled_non_sched[ARRAY_SIZE(soak_suites)];
    uint32_t suite_runs[ARRAY_SIZE(soak_suites)];
    size_t enabled_non_sched_cnt = 0;
    size_t sched_idx = ARRAY_SIZE(soak_suites) - 1;
    bool sched_enabled = false;
    bool ran_any = false;
    uint32_t iter = 0;

    if (duration_ticks == 0)
        duration_ticks = 1;

    tests_failed = 0;
    memset(suite_runs, 0, sizeof(suite_runs));
    soak_prng_state = start_ticks ^ 0xa0761d6478bd642fULL;
    if (soak_prng_state == 0)
        soak_prng_state = 0x6a09e667f3bcc909ULL;

    fault_inject_reset();
    fault_inject_set_seed(start_ticks ^ 0xe7037ed1a0b428dbULL);
    fault_inject_set_rate_permille(FAULT_INJECT_POINT_KMALLOC,
                                   CONFIG_KERNEL_SOAK_PR_FAULT_PERMILLE);
    fault_inject_set_warmup_hits(FAULT_INJECT_POINT_KMALLOC,
                                 CONFIG_KERNEL_SOAK_PR_FAULT_WARMUP_HITS);
    fault_inject_set_fail_budget(FAULT_INJECT_POINT_KMALLOC,
                                 CONFIG_KERNEL_SOAK_PR_FAULT_FAIL_BUDGET);
    fault_inject_enable(true);

    pr_info("\n=== Soak PR Tests ===\n");
    pr_info("soak_pr: duration=%us kmalloc_fault=%u/1000 suite_mask=0x%x\n",
            CONFIG_KERNEL_SOAK_PR_DURATION_SEC,
            CONFIG_KERNEL_SOAK_PR_FAULT_PERMILLE,
            CONFIG_KERNEL_SOAK_PR_SUITE_MASK);

    for (size_t i = 0; i < ARRAY_SIZE(soak_suites); i++) {
        if ((CONFIG_KERNEL_SOAK_PR_SUITE_MASK & soak_suites[i].bit) == 0)
            continue;
        if (i == sched_idx)
            sched_enabled = true;
        else
            enabled_non_sched[enabled_non_sched_cnt++] = i;
    }
    if (enabled_non_sched_cnt == 0 && !sched_enabled) {
        pr_err("soak_pr: no suites enabled (CONFIG_KERNEL_SOAK_PR_SUITE_MASK)\n");
        tests_failed++;
        goto out;
    }

    while ((arch_timer_ticks() - start_ticks) < duration_ticks) {
        size_t idx = 0;
        bool run_sched_now = false;

        if (CONFIG_KERNEL_SOAK_PR_MAX_ITERS != 0 &&
            iter >= CONFIG_KERNEL_SOAK_PR_MAX_ITERS)
            break;

        if (sched_enabled && CONFIG_KERNEL_SOAK_PR_SCHED_EVERY != 0 &&
            iter != 0 && (iter % CONFIG_KERNEL_SOAK_PR_SCHED_EVERY) == 0)
            run_sched_now = true;

        if (run_sched_now || enabled_non_sched_cnt == 0)
            idx = sched_idx;
        else
            idx = enabled_non_sched[soak_rand32() % enabled_non_sched_cnt];

        int ret = run_suite_once(&soak_suites[idx], iter++);
        ran_any = true;
        suite_runs[idx]++;
        if (ret > 0) {
            tests_failed += ret;
            break;
        }

        if (CONFIG_KERNEL_SOAK_PR_FAULT_EVERY != 0 &&
            (iter % CONFIG_KERNEL_SOAK_PR_FAULT_EVERY) == 0) {
            int ret = soak_fault_probe_kmalloc(iter);
            if (ret > 0) {
                tests_failed += ret;
                break;
            }
        }

        if ((iter & 7U) == 0) {
            uint64_t elapsed_ns =
                arch_timer_ticks_to_ns(arch_timer_ticks() - start_ticks);
            pr_info("soak_pr: iter=%u elapsed=%llums kmalloc: hits=%llu fail=%llu\n",
                    iter, (unsigned long long)(elapsed_ns / 1000000ULL),
                    (unsigned long long)fault_inject_hits(
                        FAULT_INJECT_POINT_KMALLOC),
                    (unsigned long long)fault_inject_failures(
                        FAULT_INJECT_POINT_KMALLOC));
        }
        proc_yield();
    }
    if (!ran_any) {
        pr_err("soak_pr: ran zero iterations\n");
        tests_failed++;
    }

out:
    fault_inject_enable(false);
    uint64_t elapsed_ns = arch_timer_ticks_to_ns(arch_timer_ticks() - start_ticks);
    pr_info("soak_pr: done elapsed=%llums iterations=%u kmalloc: hits=%llu fail=%llu\n",
            (unsigned long long)(elapsed_ns / 1000000ULL), iter,
            (unsigned long long)fault_inject_hits(FAULT_INJECT_POINT_KMALLOC),
            (unsigned long long)fault_inject_failures(FAULT_INJECT_POINT_KMALLOC));
    for (size_t i = 0; i < ARRAY_SIZE(soak_suites); i++) {
        if ((CONFIG_KERNEL_SOAK_PR_SUITE_MASK & soak_suites[i].bit) == 0)
            continue;
        pr_info("soak_pr: suite=%s runs=%u\n", soak_suites[i].name, suite_runs[i]);
    }

    if (tests_failed == 0)
        pr_info("soak tests: all passed\n");
    else
        pr_err("soak tests: %d failures\n", tests_failed);
    return tests_failed;
}

#else

int run_soak_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
