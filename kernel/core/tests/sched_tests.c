/**
 * kernel/core/tests/sched_tests.c - Scheduler stress tests
 */

#if CONFIG_KERNEL_TESTS

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/wait.h>

/* ---------- test_sched_fork_exit_storm ---------- */

#define FORK_STORM_N 64

static int fork_exit_child(void *arg) {
    (void)arg;
    proc_exit(0);
    /* unreachable */
    return 0;
}

static void test_sched_fork_exit_storm(void) {
    pr_info("sched_stress: fork_exit_storm\n");
    int created = 0;
    for (int i = 0; i < FORK_STORM_N; i++) {
        struct process *p = kthread_create(fork_exit_child, NULL, "fes");
        if (p) {
            sched_enqueue(p);
            created++;
        } else {
            pr_warn("sched_stress: fork_exit_storm: kthread_create failed at i=%d\n", i);
        }
    }
    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;
    pr_info("sched_stress: fork_exit_storm done (%d/%d created)\n", created, FORK_STORM_N);
}

/* ---------- test_sched_sleep_wakeup_stress ---------- */

#define SLEEP_WAKE_ROUNDS 200
#define SLEEP_WAKE_SLEEPERS 4

static struct wait_queue sw_wq;
static volatile int sw_live_sleepers;

static int sleeper_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < SLEEP_WAKE_ROUNDS; i++) {
        proc_sleep_on(&sw_wq, NULL, false);
    }
    __atomic_fetch_sub(&sw_live_sleepers, 1, __ATOMIC_RELEASE);
    proc_exit(0);
    return 0;
}

static int waker_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < SLEEP_WAKE_ROUNDS; i++) {
        wait_queue_wakeup_all(&sw_wq);
        proc_yield();
    }
    /* Keep waking until all sleepers have exited */
    while (__atomic_load_n(&sw_live_sleepers, __ATOMIC_ACQUIRE) > 0) {
        wait_queue_wakeup_all(&sw_wq);
        proc_yield();
    }
    proc_exit(0);
    return 0;
}

static void test_sched_sleep_wakeup_stress(void) {
    pr_info("sched_stress: sleep_wakeup_stress\n");
    wait_queue_init(&sw_wq);
    __atomic_store_n(&sw_live_sleepers, 0, __ATOMIC_RELEASE);

    int created = 0;
    for (int i = 0; i < SLEEP_WAKE_SLEEPERS; i++) {
        struct process *p = kthread_create(sleeper_thread, NULL, "slp");
        if (p) {
            __atomic_fetch_add(&sw_live_sleepers, 1, __ATOMIC_RELEASE);
            sched_enqueue(p);
            created++;
        } else {
            pr_warn("sched_stress: sleep_wakeup: kthread_create failed at i=%d\n", i);
        }
    }
    struct process *w = kthread_create(waker_thread, NULL, "wkr");
    if (w) {
        sched_enqueue(w);
    } else {
        pr_warn("sched_stress: sleep_wakeup: waker kthread_create failed\n");
    }

    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;
    pr_info("sched_stress: sleep_wakeup_stress done (%d/%d sleepers created)\n",
            created, SLEEP_WAKE_SLEEPERS);
}

/* ---------- test_sched_yield_storm ---------- */

#define YIELD_ROUNDS 500

static int yield_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < YIELD_ROUNDS; i++) {
        proc_yield();
    }
    proc_exit(0);
    return 0;
}

static void test_sched_yield_storm(void) {
    pr_info("sched_stress: yield_storm\n");
    int n = sched_cpu_count() * 2;
    int created = 0;
    for (int i = 0; i < n; i++) {
        struct process *p = kthread_create(yield_thread, NULL, "yld");
        if (p) {
            sched_enqueue(p);
            created++;
        } else {
            pr_warn("sched_stress: yield_storm: kthread_create failed at i=%d\n", i);
        }
    }
    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;
    pr_info("sched_stress: yield_storm done (%d/%d created)\n", created, n);
}

/* ---------- test_sched_preempt_stress ---------- */

#define PREEMPT_ROUNDS 300

static uint64_t preempt_sink;

static int preempt_thread(void *arg) {
    (void)arg;
    uint64_t acc = 0;
    for (int i = 0; i < PREEMPT_ROUNDS; i++) {
        /* Compute-bound work to trigger tick preemption */
        for (int j = 0; j < 10000; j++)
            acc += (uint64_t)j * 7 + 13;
        if (i % 50 == 0)
            proc_yield();
    }
    __atomic_fetch_add(&preempt_sink, acc, __ATOMIC_RELAXED);
    proc_exit(0);
    return 0;
}

static void test_sched_preempt_stress(void) {
    pr_info("sched_stress: preempt_stress\n");
    int n = sched_cpu_count() * 2;
    int created = 0;
    for (int i = 0; i < n; i++) {
        struct process *p = kthread_create(preempt_thread, NULL, "pre");
        if (p) {
            sched_enqueue(p);
            created++;
        } else {
            pr_warn("sched_stress: preempt_stress: kthread_create failed at i=%d\n", i);
        }
    }
    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;
    pr_info("sched_stress: preempt_stress done (%d/%d created)\n", created, n);
}

/* ---------- Entry point ---------- */

void run_sched_stress_tests(void) {
    pr_info("sched_stress: starting\n");
    test_sched_fork_exit_storm();
    test_sched_sleep_wakeup_stress();
    test_sched_yield_storm();
    test_sched_preempt_stress();
    pr_info("sched_stress: all passed\n");
}

#endif /* CONFIG_KERNEL_TESTS */
