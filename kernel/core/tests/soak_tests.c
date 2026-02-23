/**
 * kernel/core/tests/soak_tests.c - PR-level soak tests with low-rate injection
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/fault_inject.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/string.h>
#include <kairos/uaccess.h>

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

static void shuffle_indices(size_t *arr, size_t n) {
    if (!arr || n < 2)
        return;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)(soak_rand32() % (uint32_t)(i + 1));
        size_t t = arr[i];
        arr[i] = arr[j];
        arr[j] = t;
    }
}

struct suite_run_ctx {
    const struct soak_suite_entry *suite;
    volatile int done;
    int ret;
};

static int soak_suite_worker(void *arg) {
    struct suite_run_ctx *ctx = (struct suite_run_ctx *)arg;
    if (!ctx || !ctx->suite || !ctx->suite->run) {
        if (ctx) {
            ctx->ret = 1;
            __atomic_store_n(&ctx->done, 1, __ATOMIC_RELEASE);
        }
        proc_exit(0);
    }
    ctx->ret = ctx->suite->run();
    __atomic_store_n(&ctx->done, 1, __ATOMIC_RELEASE);
    proc_exit(0);
}

static int run_suite_once(const struct soak_suite_entry *suite, uint32_t iter) {
    struct suite_run_ctx *ctx = kzalloc(sizeof(*ctx));
    if (!ctx) {
        pr_err("soak_pr: iter=%u suite=%s alloc failed\n", iter, suite->name);
        return 1;
    }
    ctx->suite = suite;
    ctx->done = 0;
    ctx->ret = -EIO;

    struct process *child =
        kthread_create_joinable(soak_suite_worker, ctx, "soakrun");
    if (!child) {
        pr_err("soak_pr: iter=%u suite=%s create failed\n", iter, suite->name);
        kfree(ctx);
        return 1;
    }
    pid_t cpid = child->pid;
    sched_enqueue(child);

    uint64_t timeout_ticks = arch_timer_ns_to_ticks(
        (uint64_t)CONFIG_KERNEL_SOAK_PR_SUITE_TIMEOUT_SEC * 1000000000ULL);
    if (timeout_ticks == 0)
        timeout_ticks = 1;
    uint64_t start = arch_timer_ticks();

    while (1) {
        int status = 0;
        pid_t wp = proc_wait(cpid, &status, WNOHANG);
        if (wp == cpid) {
            int ret = ctx->ret;
            if (ret > 0) {
                pr_err("soak_pr: iter=%u suite=%s failed=%d\n", iter, suite->name,
                       ret);
            }
            kfree(ctx);
            return ret > 0 ? ret : 0;
        }
        if (wp < 0) {
            pr_err("soak_pr: iter=%u suite=%s wait failed (%d)\n", iter,
                   suite->name, (int)wp);
            kfree(ctx);
            return 1;
        }
        if ((arch_timer_ticks() - start) >= timeout_ticks) {
            pr_err("soak_pr: iter=%u suite=%s timeout %us, killing\n", iter,
                   suite->name, CONFIG_KERNEL_SOAK_PR_SUITE_TIMEOUT_SEC);
            signal_send(cpid, SIGKILL);
            (void)proc_wait(cpid, &status, 0);
            kfree(ctx);
            return 1;
        }
        proc_yield();
    }
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

static int soak_fault_probe_uaccess(uint32_t iter) {
    uint8_t kbuf[16];
    void *bad_user =
        (void *)(uintptr_t)(USER_SPACE_END + (vaddr_t)CONFIG_PAGE_SIZE);

    fault_inject_scope_enter();
    for (uint32_t i = 0; i < CONFIG_KERNEL_SOAK_PR_UACCESS_FAULT_PROBE_OPS; i++) {
        int r1 = copy_from_user(kbuf, bad_user, sizeof(kbuf));
        int r2 = copy_to_user(bad_user, kbuf, sizeof(kbuf));
        if (r1 != -EFAULT || r2 != -EFAULT) {
            fault_inject_scope_exit();
            pr_err("soak_pr: iter=%u uaccess probe unexpected ret r1=%d r2=%d\n",
                   iter, r1, r2);
            return 1;
        }
    }
    fault_inject_scope_exit();
    return 0;
}

int run_soak_tests(void) {
    uint64_t start_ticks = arch_timer_ticks();
    uint64_t duration_ns =
        (uint64_t)CONFIG_KERNEL_SOAK_PR_DURATION_SEC * 1000000000ULL;
    uint64_t duration_ticks = arch_timer_ns_to_ticks(duration_ns);
    size_t enabled_non_sched[ARRAY_SIZE(soak_suites)];
    size_t non_sched_cycle[ARRAY_SIZE(soak_suites)];
    uint32_t suite_runs[ARRAY_SIZE(soak_suites)];
    size_t enabled_non_sched_cnt = 0;
    size_t non_sched_pos = 0;
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
    pr_info("soak_pr: duration=%us kmalloc_fault=%u/1000 suite_mask=0x%x "
            "min_runs=%u suite_timeout=%us\n",
            CONFIG_KERNEL_SOAK_PR_DURATION_SEC,
            CONFIG_KERNEL_SOAK_PR_FAULT_PERMILLE,
            CONFIG_KERNEL_SOAK_PR_SUITE_MASK,
            CONFIG_KERNEL_SOAK_PR_MIN_RUNS_PER_SUITE,
            CONFIG_KERNEL_SOAK_PR_SUITE_TIMEOUT_SEC);

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
    memcpy(non_sched_cycle, enabled_non_sched,
           enabled_non_sched_cnt * sizeof(enabled_non_sched[0]));
    shuffle_indices(non_sched_cycle, enabled_non_sched_cnt);
    non_sched_pos = 0;

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
        else {
            if (non_sched_pos >= enabled_non_sched_cnt) {
                memcpy(non_sched_cycle, enabled_non_sched,
                       enabled_non_sched_cnt * sizeof(enabled_non_sched[0]));
                shuffle_indices(non_sched_cycle, enabled_non_sched_cnt);
                non_sched_pos = 0;
            }
            idx = non_sched_cycle[non_sched_pos++];
        }

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
            ret = soak_fault_probe_uaccess(iter);
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
            pr_info("soak_pr: iter=%u uaccess: cfu_hits=%llu cfu_fail=%llu "
                    "ctu_hits=%llu ctu_fail=%llu\n",
                    iter,
                    (unsigned long long)fault_inject_hits(
                        FAULT_INJECT_POINT_COPY_FROM_USER),
                    (unsigned long long)fault_inject_failures(
                        FAULT_INJECT_POINT_COPY_FROM_USER),
                    (unsigned long long)fault_inject_hits(
                        FAULT_INJECT_POINT_COPY_TO_USER),
                    (unsigned long long)fault_inject_failures(
                        FAULT_INJECT_POINT_COPY_TO_USER));
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
    pr_info("soak_pr: uaccess cfu_hits=%llu cfu_fail=%llu ctu_hits=%llu ctu_fail=%llu\n",
            (unsigned long long)fault_inject_hits(
                FAULT_INJECT_POINT_COPY_FROM_USER),
            (unsigned long long)fault_inject_failures(
                FAULT_INJECT_POINT_COPY_FROM_USER),
            (unsigned long long)fault_inject_hits(
                FAULT_INJECT_POINT_COPY_TO_USER),
            (unsigned long long)fault_inject_failures(
                FAULT_INJECT_POINT_COPY_TO_USER));

    for (size_t i = 0; i < ARRAY_SIZE(soak_suites); i++) {
        if ((CONFIG_KERNEL_SOAK_PR_SUITE_MASK & soak_suites[i].bit) == 0)
            continue;
        if (suite_runs[i] < CONFIG_KERNEL_SOAK_PR_MIN_RUNS_PER_SUITE) {
            pr_err("soak_pr: suite=%s runs=%u below min=%u\n", soak_suites[i].name,
                   suite_runs[i], CONFIG_KERNEL_SOAK_PR_MIN_RUNS_PER_SUITE);
            tests_failed++;
        }
    }
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
