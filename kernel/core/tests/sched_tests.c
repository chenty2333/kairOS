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
    for (int i = 0; i < FORK_STORM_N; i++) {
        struct process *p = kthread_create(fork_exit_child, NULL, "fes");
        if (p)
            sched_enqueue(p);
    }
    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;
    pr_info("sched_stress: fork_exit_storm done\n");
}

/* ---------- test_sched_sleep_wakeup_stress ---------- */

#define SLEEP_WAKE_ROUNDS 200
#define SLEEP_WAKE_SLEEPERS 4

static struct wait_queue sw_wq;
static volatile int sw_waker_go;

static int sleeper_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < SLEEP_WAKE_ROUNDS; i++) {
        proc_sleep_on(&sw_wq, NULL, false);
    }
    proc_exit(0);
    return 0;
}

static int waker_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < SLEEP_WAKE_ROUNDS; i++) {
        wait_queue_wakeup_all(&sw_wq);
        proc_yield();
    }
    /* Final wakeup to flush any remaining sleepers */
    wait_queue_wakeup_all(&sw_wq);
    proc_exit(0);
    return 0;
}

static void test_sched_sleep_wakeup_stress(void) {
    pr_info("sched_stress: sleep_wakeup_stress\n");
    wait_queue_init(&sw_wq);
    sw_waker_go = 0;

    for (int i = 0; i < SLEEP_WAKE_SLEEPERS; i++) {
        struct process *p = kthread_create(sleeper_thread, NULL, "slp");
        if (p)
            sched_enqueue(p);
    }
    struct process *w = kthread_create(waker_thread, NULL, "wkr");
    if (w)
        sched_enqueue(w);

    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;
    pr_info("sched_stress: sleep_wakeup_stress done\n");
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
    for (int i = 0; i < n; i++) {
        struct process *p = kthread_create(yield_thread, NULL, "yld");
        if (p)
            sched_enqueue(p);
    }
    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;
    pr_info("sched_stress: yield_storm done\n");
}

/* ---------- test_sched_preempt_stress ---------- */

#define PREEMPT_ROUNDS 300

static volatile uint64_t preempt_sink;

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
    preempt_sink += acc;
    proc_exit(0);
    return 0;
}

static void test_sched_preempt_stress(void) {
    pr_info("sched_stress: preempt_stress\n");
    int n = sched_cpu_count() * 2;
    for (int i = 0; i < n; i++) {
        struct process *p = kthread_create(preempt_thread, NULL, "pre");
        if (p)
            sched_enqueue(p);
    }
    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;
    pr_info("sched_stress: preempt_stress done\n");
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
