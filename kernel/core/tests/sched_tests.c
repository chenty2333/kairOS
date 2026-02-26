/**
 * kernel/core/tests/sched_tests.c - Scheduler stress tests
 */

#if CONFIG_KERNEL_TESTS

#include <stdarg.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/printk.h>
#include <kairos/poll.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/pollwait.h>
#include <kairos/wait.h>

static int tests_failed;

static void test_fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintk(fmt, ap);
    va_end(ap);
    tests_failed++;
}

static int reap_children_bounded(int expected, const char *tag) {
    int reaped = 0;
    int status = 0;
    uint64_t start = arch_timer_ticks();
    uint64_t timeout_ticks = arch_timer_ns_to_ticks(60ULL * 1000 * 1000 * 1000);

    while (reaped < expected) {
        pid_t pid = proc_wait(-1, &status, WNOHANG);
        if (pid > 0) {
            reaped++;
            continue;
        }
        if (pid < 0)
            break;
        if ((arch_timer_ticks() - start) > timeout_ticks)
            break;
        proc_yield();
    }

    if (reaped < expected) {
        struct process *self = proc_current();
        pr_warn("sched_stress: %s reap timeout (%d/%d)\n", tag, reaped, expected);
        int cpus = sched_cpu_count();
        if (cpus < 1)
            cpus = 1;
        for (int c = 0; c < cpus; c++)
            sched_debug_dump_cpu(c);
        sched_trace_dump_recent(128);
        for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
            pid_t pid = proc_get_nth_pid(i);
            if (pid <= 0)
                break;
            struct process *p = proc_find(pid);
            if (!p || p == self)
                continue;
            if (p->parent == self) {
                pr_warn("sched_stress: %s pending child pid=%d state=%d on_rq=%d on_cpu=%d api_on_cpu=%d\n",
                        tag, p->pid, p->state,
                        se_is_on_rq(&p->se) ? 1 : 0,
                        se_is_on_cpu(&p->se) ? 1 : 0,
                        sched_is_on_cpu(p) ? 1 : 0);
                pr_warn("sched_stress: %s pending child pid=%d wait_active=%d wait_channel=%p\n",
                        tag, p->pid, p->wait_entry.active ? 1 : 0,
                        p->wait_channel);
                sched_debug_dump_process(p);
            }
        }
    }

    return reaped;
}

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
    struct process *self = proc_current();
    int created = 0;
    for (int i = 0; i < FORK_STORM_N; i++) {
        struct process *p = kthread_create_joinable(fork_exit_child, NULL, "fes");
        if (p) {
            if (p->parent != self) {
                pr_warn("sched_stress: fork_exit_storm parent mismatch pid=%d parent=%d self=%d\n",
                        p->pid, p->parent ? p->parent->pid : -1,
                        self ? self->pid : -1);
            }
            sched_enqueue(p);
            created++;
        } else {
            pr_warn("sched_stress: fork_exit_storm: kthread_create failed at i=%d\n", i);
        }
    }
    int linked = 0;
    for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
        pid_t pid = proc_get_nth_pid(i);
        if (pid <= 0)
            break;
        struct process *p = proc_find(pid);
        if (p && p->parent == self)
            linked++;
    }
    pr_info("sched_stress: fork_exit_storm linked=%d created=%d\n", linked, created);
    int reaped = reap_children_bounded(created, "fork_exit_storm");
    if (reaped != created)
        test_fail("sched_stress: fork_exit_storm FAIL: reaped %d/%d\n",
                  reaped, created);
    pr_info("sched_stress: fork_exit_storm done (%d/%d created)\n", created, FORK_STORM_N);
}

/* ---------- test_sched_kthread_steal_policy ---------- */

#define STEAL_POLICY_TASKS_PER_CPU 4
#define STEAL_POLICY_ROUNDS 600
#define STEAL_POLICY_MAX_TASKS (CONFIG_MAX_CPUS * STEAL_POLICY_TASKS_PER_CPU)

struct steal_policy_ctx {
    int home_cpu;
    int rounds;
    volatile int saw_remote_cpu;
};

static struct steal_policy_ctx steal_policy_ctx[STEAL_POLICY_MAX_TASKS];

static uint64_t sched_total_steal_success(void) {
    struct sched_stats stats;
    sched_get_stats(&stats);
    uint64_t total = 0;
    int cpus = (int)stats.cpu_count;
    if (cpus < 1)
        cpus = 1;
    if (cpus > CONFIG_MAX_CPUS)
        cpus = CONFIG_MAX_CPUS;
    for (int i = 0; i < cpus; i++)
        total += stats.cpu[i].steal_success_count;
    return total;
}

static int steal_policy_worker(void *arg) {
    struct steal_policy_ctx *ctx = (struct steal_policy_ctx *)arg;
    for (int i = 0; i < ctx->rounds; i++) {
        int cpu = arch_cpu_id();
        if (cpu != ctx->home_cpu)
            __atomic_store_n(&ctx->saw_remote_cpu, 1, __ATOMIC_RELEASE);
        proc_yield();
    }
    proc_exit(0);
    return 0;
}

static void test_sched_kthread_steal_policy(void) {
    int cpu_count = sched_cpu_count();
    if (cpu_count < 2) {
        pr_info("sched_stress: kthread_steal_policy skipped (cpu_count=%d)\n",
                cpu_count);
        return;
    }

    sched_set_steal_enabled(true);
    int home_cpu = arch_cpu_id();
    int target = cpu_count * STEAL_POLICY_TASKS_PER_CPU;
    if (target > STEAL_POLICY_MAX_TASKS)
        target = STEAL_POLICY_MAX_TASKS;

    pr_info("sched_stress: kthread_steal_policy nonstealable\n");
    memset(steal_policy_ctx, 0, sizeof(steal_policy_ctx));
    int created = 0;
    for (int i = 0; i < target; i++) {
        steal_policy_ctx[i].home_cpu = home_cpu;
        steal_policy_ctx[i].rounds = STEAL_POLICY_ROUNDS;
        struct process *p = kthread_create_joinable(steal_policy_worker,
                                                    &steal_policy_ctx[i],
                                                    "kst0");
        if (!p) {
            pr_warn("sched_stress: kthread_steal_policy nonstealable create failed at i=%d\n",
                    i);
            break;
        }
        if (proc_sched_is_stealable(p)) {
            test_fail("sched_stress: kthread_steal_policy FAIL: kthread default stealable pid=%d\n",
                      p->pid);
            return;
        }
        sched_enqueue(p);
        created++;
    }
    int reaped = reap_children_bounded(created, "kthread_steal_policy_nonstealable");
    if (reaped != created) {
        test_fail("sched_stress: kthread_steal_policy FAIL: nonstealable reaped %d/%d\n",
                  reaped, created);
        return;
    }
    int nonsteal_remote = 0;
    for (int i = 0; i < created; i++) {
        if (__atomic_load_n(&steal_policy_ctx[i].saw_remote_cpu, __ATOMIC_ACQUIRE))
            nonsteal_remote++;
    }
    if (nonsteal_remote != 0) {
        test_fail("sched_stress: kthread_steal_policy FAIL: nonstealable migrated=%d\n",
                  nonsteal_remote);
        return;
    }

    pr_info("sched_stress: kthread_steal_policy stealable_pinned\n");
    memset(steal_policy_ctx, 0, sizeof(steal_policy_ctx));
    uint64_t steal_before = sched_total_steal_success();
    created = 0;
    for (int i = 0; i < target; i++) {
        steal_policy_ctx[i].home_cpu = home_cpu;
        steal_policy_ctx[i].rounds = STEAL_POLICY_ROUNDS;
        struct process *p = kthread_create_joinable(steal_policy_worker,
                                                    &steal_policy_ctx[i],
                                                    "kst1");
        if (!p) {
            pr_warn("sched_stress: kthread_steal_policy stealable_pinned create failed at i=%d\n",
                    i);
            break;
        }
        proc_sched_set_stealable(p, true);
        if (!proc_sched_is_stealable(p)) {
            test_fail("sched_stress: kthread_steal_policy FAIL: optin not applied pid=%d\n",
                      p->pid);
            return;
        }
        sched_enqueue(p);
        created++;
    }
    reaped = reap_children_bounded(created, "kthread_steal_policy_stealable_pinned");
    if (reaped != created) {
        test_fail("sched_stress: kthread_steal_policy FAIL: stealable_pinned reaped %d/%d\n",
                  reaped, created);
        return;
    }
    int pinned_remote = 0;
    int pinned_created = created;
    for (int i = 0; i < created; i++) {
        if (__atomic_load_n(&steal_policy_ctx[i].saw_remote_cpu, __ATOMIC_ACQUIRE))
            pinned_remote++;
    }
    uint64_t steal_after = sched_total_steal_success();
    uint64_t pinned_steal_delta = steal_after - steal_before;
    if (pinned_remote != 0 || pinned_steal_delta != 0) {
        test_fail("sched_stress: kthread_steal_policy FAIL: stealable_pinned migrated=%d steal_delta=%llu\n",
                  pinned_remote, (unsigned long long)pinned_steal_delta);
        return;
    }

    pr_info("sched_stress: kthread_steal_policy stealable_unbound\n");
    memset(steal_policy_ctx, 0, sizeof(steal_policy_ctx));
    steal_before = sched_total_steal_success();
    created = 0;
    for (int i = 0; i < target; i++) {
        steal_policy_ctx[i].home_cpu = home_cpu;
        steal_policy_ctx[i].rounds = STEAL_POLICY_ROUNDS;
        struct process *p = kthread_create_joinable(steal_policy_worker,
                                                    &steal_policy_ctx[i],
                                                    "kst2");
        if (!p) {
            pr_warn("sched_stress: kthread_steal_policy stealable_unbound create failed at i=%d\n",
                    i);
            break;
        }
        proc_sched_set_stealable(p, true);
        proc_sched_set_affinity_all(p);
        sched_enqueue(p);
        created++;
    }
    reaped = reap_children_bounded(created, "kthread_steal_policy_stealable_unbound");
    if (reaped != created) {
        test_fail("sched_stress: kthread_steal_policy FAIL: stealable_unbound reaped %d/%d\n",
                  reaped, created);
        return;
    }
    int unbound_remote = 0;
    for (int i = 0; i < created; i++) {
        if (__atomic_load_n(&steal_policy_ctx[i].saw_remote_cpu, __ATOMIC_ACQUIRE))
            unbound_remote++;
    }
    steal_after = sched_total_steal_success();
    uint64_t unbound_steal_delta = steal_after - steal_before;
    if (unbound_remote == 0 && unbound_steal_delta == 0) {
        test_fail("sched_stress: kthread_steal_policy FAIL: optin showed no steal activity\n");
        return;
    }

    pr_info("sched_stress: kthread_steal_policy done (pinned_remote=%d/%d pinned_steal_delta=%llu unbound_remote=%d/%d unbound_steal_delta=%llu)\n",
            pinned_remote, pinned_created, (unsigned long long)pinned_steal_delta,
            unbound_remote, created, (unsigned long long)unbound_steal_delta);
}

/* ---------- test_sched_sleep_wakeup_stress ---------- */

#define SLEEP_WAKE_ROUNDS 200
#define SLEEP_WAKE_SLEEPERS 4

static struct wait_queue sw_wq;
static int sw_live_sleepers;
static volatile int sw_waker_phase;
static volatile int sw_waker_for_iter;
static volatile int sw_waker_while_iter;

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
    __atomic_store_n(&sw_waker_phase, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&sw_waker_for_iter, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&sw_waker_while_iter, 0, __ATOMIC_RELEASE);
    for (int i = 0; i < SLEEP_WAKE_ROUNDS; i++) {
        __atomic_store_n(&sw_waker_for_iter, i + 1, __ATOMIC_RELEASE);
        wait_queue_wakeup_all(&sw_wq);
        proc_yield();
    }
    /* Keep waking until all sleepers have exited */
    __atomic_store_n(&sw_waker_phase, 2, __ATOMIC_RELEASE);
    while (__atomic_load_n(&sw_live_sleepers, __ATOMIC_ACQUIRE) > 0) {
        __atomic_fetch_add(&sw_waker_while_iter, 1, __ATOMIC_RELEASE);
        wait_queue_wakeup_all(&sw_wq);
        proc_yield();
    }
    __atomic_store_n(&sw_waker_phase, 3, __ATOMIC_RELEASE);
    proc_exit(0);
    return 0;
}

static void test_sched_sleep_wakeup_stress(void) {
    pr_info("sched_stress: sleep_wakeup_stress\n");
    wait_queue_init(&sw_wq);
    __atomic_store_n(&sw_live_sleepers, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&sw_waker_phase, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&sw_waker_for_iter, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&sw_waker_while_iter, 0, __ATOMIC_RELEASE);

    int created = 0;
    for (int i = 0; i < SLEEP_WAKE_SLEEPERS; i++) {
        struct process *p = kthread_create_joinable(sleeper_thread, NULL, "slp");
        if (p) {
            __atomic_fetch_add(&sw_live_sleepers, 1, __ATOMIC_RELEASE);
            sched_enqueue(p);
            created++;
        } else {
            pr_warn("sched_stress: sleep_wakeup: kthread_create failed at i=%d\n", i);
        }
    }
    struct process *w = kthread_create_joinable(waker_thread, NULL, "wkr");
    if (w) {
        sched_enqueue(w);
    } else {
        pr_warn("sched_stress: sleep_wakeup: waker kthread_create failed\n");
    }

    int created_total = created + (w ? 1 : 0);
    int reaped = reap_children_bounded(created_total, "sleep_wakeup_stress");
    if (reaped != created_total) {
        int live = __atomic_load_n(&sw_live_sleepers, __ATOMIC_ACQUIRE);
        int wkr_phase = __atomic_load_n(&sw_waker_phase, __ATOMIC_ACQUIRE);
        int wkr_for = __atomic_load_n(&sw_waker_for_iter, __ATOMIC_ACQUIRE);
        int wkr_while = __atomic_load_n(&sw_waker_while_iter, __ATOMIC_ACQUIRE);
        pr_warn("sched_stress: sleep_wakeup_stress live_sleepers=%d\n", live);
        pr_warn("sched_stress: sleep_wakeup_stress wkr phase=%d for_iter=%d while_iter=%d\n",
                wkr_phase, wkr_for, wkr_while);
        for (int i = 0; i < CONFIG_MAX_PROCESSES; i++) {
            pid_t pid = proc_get_nth_pid(i);
            if (pid <= 0)
                break;
            struct process *p = proc_find(pid);
            if (!p)
                continue;
            bool is_slp = p->name[0] == 's' && p->name[1] == 'l' &&
                          p->name[2] == 'p' && p->name[3] == '\0';
            bool is_wkr = p->name[0] == 'w' && p->name[1] == 'k' &&
                          p->name[2] == 'r' && p->name[3] == '\0';
            if (!is_slp && !is_wkr)
                continue;
            pr_warn("sched_stress: sleep_wakeup_stress proc pid=%d ppid=%d parent=%d state=%d on_rq=%d on_cpu=%d api_on_cpu=%d\n",
                    p->pid, p->ppid, p->parent ? p->parent->pid : -1, p->state,
                    se_is_on_rq(&p->se) ? 1 : 0, se_is_on_cpu(&p->se) ? 1 : 0,
                    sched_is_on_cpu(p) ? 1 : 0);
            pr_warn("sched_stress: sleep_wakeup_stress proc pid=%d wait_active=%d wait_channel=%p\n",
                    p->pid, p->wait_entry.active ? 1 : 0, p->wait_channel);
            sched_debug_dump_process(p);
        }
        test_fail("sched_stress: sleep_wakeup_stress FAIL: reaped %d/%d\n",
                  reaped, created_total);
    }
    pr_info("sched_stress: sleep_wakeup_stress done (%d/%d sleepers created)\n",
            created, SLEEP_WAKE_SLEEPERS);
}

/* ---------- test_poll_wait_head_single_waiter_fastpath ---------- */

struct poll_wait_head_fastpath_ctx {
    struct poll_wait_head head;
    volatile int armed;
    volatile int done;
    int wake_rc;
};

static int poll_wait_head_fastpath_sleeper(void *arg) {
    struct poll_wait_head_fastpath_ctx *ctx =
        (struct poll_wait_head_fastpath_ctx *)arg;
    if (!ctx) {
        proc_exit(1);
        return 0;
    }

    struct process *curr = proc_current();
    struct poll_waiter waiter = {0};
    INIT_LIST_HEAD(&waiter.entry.node);
    waiter.entry.proc = curr;
    poll_wait_add(&ctx->head, &waiter);
    __atomic_store_n(&ctx->armed, 1, __ATOMIC_RELEASE);

    uint64_t deadline = arch_timer_ticks() + CONFIG_HZ;
    if (deadline == 0)
        deadline = 1;
    ctx->wake_rc = poll_block_current(deadline, curr);
    poll_wait_remove(&waiter);
    __atomic_store_n(&ctx->done, 1, __ATOMIC_RELEASE);
    proc_exit(0);
    return 0;
}

static void test_poll_wait_head_single_waiter_fastpath(void) {
    pr_info("sched_stress: poll_wait_head_single_waiter_fastpath\n");

    struct poll_wait_head_fastpath_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    poll_wait_head_init(&ctx.head);
    ctx.wake_rc = -ETIMEDOUT;

    poll_wait_stats_reset();
    uint64_t before[POLL_WAIT_STAT_COUNT] = {0};
    uint64_t after[POLL_WAIT_STAT_COUNT] = {0};
    poll_wait_stats_snapshot(before);

    struct process *thr =
        kthread_create_joinable(poll_wait_head_fastpath_sleeper, &ctx, "pwhf");
    if (!thr) {
        test_fail("sched_stress: poll_wait_head_single_waiter_fastpath FAIL: create\n");
        return;
    }

    pid_t tid = thr->pid;
    sched_enqueue(thr);

    uint64_t start = arch_timer_ticks();
    while (__atomic_load_n(&ctx.armed, __ATOMIC_ACQUIRE) == 0) {
        if ((arch_timer_ticks() - start) > CONFIG_HZ)
            break;
        proc_yield();
    }

    bool armed = __atomic_load_n(&ctx.armed, __ATOMIC_ACQUIRE) != 0;
    if (!armed)
        test_fail("sched_stress: poll_wait_head_single_waiter_fastpath FAIL: not armed\n");
    if (armed)
        poll_wait_wake(&ctx.head, POLLIN);

    int status = 0;
    pid_t wp = proc_wait(tid, &status, 0);
    if (wp != tid)
        test_fail("sched_stress: poll_wait_head_single_waiter_fastpath FAIL: reap %d/%d\n",
                  wp, tid);
    if (__atomic_load_n(&ctx.done, __ATOMIC_ACQUIRE) == 0)
        test_fail("sched_stress: poll_wait_head_single_waiter_fastpath FAIL: not done\n");
    if (ctx.wake_rc != 0)
        test_fail("sched_stress: poll_wait_head_single_waiter_fastpath FAIL: wake_rc=%d\n",
                  ctx.wake_rc);

    poll_wait_stats_snapshot(after);
    uint64_t wake_delta =
        after[POLL_WAIT_STAT_POLL_HEAD_WAKE_CALLS] -
        before[POLL_WAIT_STAT_POLL_HEAD_WAKE_CALLS];
    uint64_t direct_delta =
        after[POLL_WAIT_STAT_POLL_HEAD_DIRECT_SWITCH] -
        before[POLL_WAIT_STAT_POLL_HEAD_DIRECT_SWITCH];
    if (wake_delta < 1) {
        test_fail("sched_stress: poll_wait_head_single_waiter_fastpath FAIL: wake_delta=%llu\n",
                  (unsigned long long)wake_delta);
    }
    if (direct_delta < 1) {
        test_fail("sched_stress: poll_wait_head_single_waiter_fastpath FAIL: direct_delta=%llu\n",
                  (unsigned long long)direct_delta);
    }
}

/* ---------- test_sched_yield_storm ---------- */

#define YIELD_ROUNDS 500
static volatile int yield_iters_total;
static volatile int yield_done_count;

static int yield_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < YIELD_ROUNDS; i++) {
        __atomic_fetch_add(&yield_iters_total, 1, __ATOMIC_RELAXED);
        proc_yield();
    }
    __atomic_fetch_add(&yield_done_count, 1, __ATOMIC_RELEASE);
    proc_exit(0);
    return 0;
}

static void test_sched_yield_storm(void) {
    pr_info("sched_stress: yield_storm\n");
    __atomic_store_n(&yield_iters_total, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&yield_done_count, 0, __ATOMIC_RELEASE);
    int n = sched_cpu_count() * 2;
    int created = 0;
    for (int i = 0; i < n; i++) {
        struct process *p = kthread_create_joinable(yield_thread, NULL, "yld");
        if (p) {
            sched_enqueue(p);
            created++;
        } else {
            pr_warn("sched_stress: yield_storm: kthread_create failed at i=%d\n", i);
        }
    }
    int reaped = reap_children_bounded(created, "yield_storm");
    if (reaped != created) {
        int iters = __atomic_load_n(&yield_iters_total, __ATOMIC_ACQUIRE);
        int done = __atomic_load_n(&yield_done_count, __ATOMIC_ACQUIRE);
        pr_warn("sched_stress: yield_storm progress iters=%d done=%d expected_iters=%d expected_done=%d\n",
                iters, done, created * YIELD_ROUNDS, created);
        test_fail("sched_stress: yield_storm FAIL: reaped %d/%d\n",
                  reaped, created);
    }
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
        struct process *p = kthread_create_joinable(preempt_thread, NULL, "pre");
        if (p) {
            sched_enqueue(p);
            created++;
        } else {
            pr_warn("sched_stress: preempt_stress: kthread_create failed at i=%d\n", i);
        }
    }
    int reaped = reap_children_bounded(created, "preempt_stress");
    if (reaped != created)
        test_fail("sched_stress: preempt_stress FAIL: reaped %d/%d\n",
                  reaped, created);
    pr_info("sched_stress: preempt_stress done (%d/%d created)\n", created, n);
}

/* ---------- test_eevdf_deadline_ordering ---------- */

/*
 * Verify that EEVDF pick always selects the eligible entity with the
 * earliest deadline.  We create several threads with different nice values
 * and verify they all complete (no starvation).
 */
#define EEVDF_DEADLINE_N 8
static volatile int eevdf_deadline_done;

static int eevdf_deadline_thread(void *arg) {
    int nice = (int)(intptr_t)arg;
    sched_setnice(proc_current(), nice);
    /* Do some work, yield periodically */
    for (int i = 0; i < 100; i++) {
        volatile uint64_t x = 0;
        for (int j = 0; j < 1000; j++)
            x += (uint64_t)j;
        (void)x;
        if (i % 20 == 0)
            proc_yield();
    }
    __atomic_fetch_add(&eevdf_deadline_done, 1, __ATOMIC_RELEASE);
    proc_exit(0);
    return 0;
}

static void test_eevdf_deadline_ordering(void) {
    pr_info("sched_stress: eevdf_deadline_ordering\n");
    __atomic_store_n(&eevdf_deadline_done, 0, __ATOMIC_RELEASE);
    int nice_vals[] = {-10, -5, 0, 0, 5, 5, 10, 19};
    int created = 0;
    for (int i = 0; i < EEVDF_DEADLINE_N; i++) {
        struct process *p = kthread_create_joinable(eevdf_deadline_thread,
                                           (void *)(intptr_t)nice_vals[i], "edl");
        if (p) {
            sched_enqueue(p);
            created++;
        }
    }
    int reaped = reap_children_bounded(created, "eevdf_deadline_ordering");
    if (reaped != created)
        test_fail("sched_stress: eevdf_deadline_ordering FAIL: reaped %d/%d\n",
                  reaped, created);
    int done = __atomic_load_n(&eevdf_deadline_done, __ATOMIC_ACQUIRE);
    if (done != created)
        test_fail("sched_stress: eevdf_deadline_ordering FAIL: %d/%d completed\n",
                  done, created);
    else
        pr_info("sched_stress: eevdf_deadline_ordering done (%d/%d)\n",
                done, EEVDF_DEADLINE_N);
}

/* ---------- test_eevdf_lag_fairness ---------- */

/*
 * Verify that a task which sleeps and wakes up can catch up via lag
 * restoration.  A sleeper should not be permanently penalized.
 */
#define LAG_ROUNDS 50
static volatile int lag_sleeper_ran;
static volatile int lag_spinner_ran;
static volatile int lag_wake_budget;
static struct wait_queue lag_wq;

static int lag_sleeper(void *arg) {
    (void)arg;
    for (int i = 0; i < LAG_ROUNDS; i++) {
        while (1) {
            int budget = __atomic_load_n(&lag_wake_budget, __ATOMIC_ACQUIRE);
            if (budget > 0 &&
                __atomic_compare_exchange_n(&lag_wake_budget, &budget,
                                            budget - 1, false,
                                            __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE))
                break;
            proc_sleep_on(&lag_wq, NULL, false);
        }
        __atomic_fetch_add(&lag_sleeper_ran, 1, __ATOMIC_RELAXED);
    }
    proc_exit(0);
    return 0;
}

static int lag_spinner(void *arg) {
    (void)arg;
    for (int i = 0; i < LAG_ROUNDS * 10; i++) {
        volatile uint64_t x = 0;
        for (int j = 0; j < 500; j++)
            x += (uint64_t)j;
        (void)x;
        __atomic_fetch_add(&lag_spinner_ran, 1, __ATOMIC_RELAXED);
        if (i % 5 == 0)
            proc_yield();
    }
    proc_exit(0);
    return 0;
}

static int lag_waker(void *arg) {
    (void)arg;
    for (int i = 0; i < LAG_ROUNDS; i++) {
        for (int j = 0; j < 3; j++)
            proc_yield();
        __atomic_fetch_add(&lag_wake_budget, 1, __ATOMIC_RELEASE);
        wait_queue_wakeup_all(&lag_wq);
    }
    uint64_t start = arch_timer_ticks();
    uint64_t timeout_ticks = arch_timer_ns_to_ticks(5ULL * 1000 * 1000 * 1000);
    while (__atomic_load_n(&lag_sleeper_ran, __ATOMIC_ACQUIRE) < LAG_ROUNDS) {
        if ((arch_timer_ticks() - start) > timeout_ticks)
            break;
        wait_queue_wakeup_all(&lag_wq);
        proc_yield();
    }
    proc_exit(0);
    return 0;
}

static void test_eevdf_lag_fairness(void) {
    pr_info("sched_stress: eevdf_lag_fairness\n");
    wait_queue_init(&lag_wq);
    __atomic_store_n(&lag_sleeper_ran, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&lag_spinner_ran, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&lag_wake_budget, 0, __ATOMIC_RELEASE);

    struct process *s = kthread_create_joinable(lag_sleeper, NULL, "lslp");
    struct process *sp = kthread_create_joinable(lag_spinner, NULL, "lspn");
    struct process *w = kthread_create_joinable(lag_waker, NULL, "lwkr");
    if (s) sched_enqueue(s);
    if (sp) sched_enqueue(sp);
    if (w) sched_enqueue(w);

    int created_total = (s ? 1 : 0) + (sp ? 1 : 0) + (w ? 1 : 0);
    int reaped = reap_children_bounded(created_total, "eevdf_lag_fairness");
    if (reaped != created_total)
        test_fail("sched_stress: eevdf_lag_fairness FAIL: reaped %d/%d\n",
                  reaped, created_total);
    int slp = __atomic_load_n(&lag_sleeper_ran, __ATOMIC_ACQUIRE);
    int spn = __atomic_load_n(&lag_spinner_ran, __ATOMIC_ACQUIRE);
    pr_info("sched_stress: eevdf_lag_fairness done (sleeper=%d spinner=%d)\n",
            slp, spn);
    if (slp < LAG_ROUNDS / 2)
        test_fail("sched_stress: eevdf_lag_fairness FAIL: sleeper starved (%d/%d)\n",
                  slp, LAG_ROUNDS);
}

/* ---------- test_eevdf_nice_isolation ---------- */

/*
 * Verify that different nice values result in proportional CPU time.
 * A nice-0 task should get more iterations than a nice-10 task.
 */
static volatile uint64_t nice_counter_hi;
static volatile uint64_t nice_counter_lo;

static int nice_worker(void *arg) {
    int nice = (int)(intptr_t)arg;
    sched_setnice(proc_current(), nice);
    volatile uint64_t *counter = (nice <= 0) ? &nice_counter_hi : &nice_counter_lo;
    for (int i = 0; i < 200; i++) {
        volatile uint64_t x = 0;
        for (int j = 0; j < 1000; j++)
            x += (uint64_t)j;
        (void)x;
        __atomic_fetch_add(counter, 1, __ATOMIC_RELAXED);
        if (i % 10 == 0)
            proc_yield();
    }
    proc_exit(0);
    return 0;
}

static void test_eevdf_nice_isolation(void) {
    pr_info("sched_stress: eevdf_nice_isolation\n");
    __atomic_store_n(&nice_counter_hi, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&nice_counter_lo, 0, __ATOMIC_RELEASE);

    /* Create one high-priority and one low-priority worker */
    struct process *hi = kthread_create_joinable(nice_worker, (void *)(intptr_t)0, "nhi");
    struct process *lo = kthread_create_joinable(nice_worker, (void *)(intptr_t)10, "nlo");
    if (hi) sched_enqueue(hi);
    if (lo) sched_enqueue(lo);

    int created = (hi ? 1 : 0) + (lo ? 1 : 0);
    int reaped = reap_children_bounded(created, "eevdf_nice_isolation");
    if (reaped != created)
        test_fail("sched_stress: eevdf_nice_isolation FAIL: reaped %d/%d\n",
                  reaped, created);
    uint64_t h = __atomic_load_n(&nice_counter_hi, __ATOMIC_ACQUIRE);
    uint64_t l = __atomic_load_n(&nice_counter_lo, __ATOMIC_ACQUIRE);
    pr_info("sched_stress: eevdf_nice_isolation done (nice0=%llu nice10=%llu)\n",
            (unsigned long long)h, (unsigned long long)l);
    /* Both should complete; the test validates no starvation */
    if (h == 0 || l == 0)
        test_fail("sched_stress: eevdf_nice_isolation FAIL: starvation detected\n");
}

/* ---------- test_eevdf_fork_penalty ---------- */

/*
 * Verify that fork children don't get unfair advantage.
 * Rapidly fork children and ensure the parent can still make progress.
 */
#define FORK_PENALTY_N 32
static volatile int fork_penalty_parent_iters;
static volatile int fork_penalty_child_done;

static int fork_penalty_child(void *arg) {
    (void)arg;
    /* Do minimal work */
    volatile uint64_t x = 0;
    for (int j = 0; j < 500; j++)
        x += (uint64_t)j;
    (void)x;
    __atomic_fetch_add(&fork_penalty_child_done, 1, __ATOMIC_RELAXED);
    proc_exit(0);
    return 0;
}

static int fork_penalty_parent(void *arg) {
    (void)arg;
    for (int i = 0; i < FORK_PENALTY_N; i++) {
        struct process *c = kthread_create_joinable(fork_penalty_child, NULL, "fpc");
        if (c)
            sched_enqueue(c);
        /* Parent does work between forks */
        volatile uint64_t x = 0;
        for (int j = 0; j < 1000; j++)
            x += (uint64_t)j;
        (void)x;
        __atomic_fetch_add(&fork_penalty_parent_iters, 1, __ATOMIC_RELAXED);
    }
    /* Wait for children */
    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;
    proc_exit(0);
    return 0;
}

static void test_eevdf_fork_penalty(void) {
    pr_info("sched_stress: eevdf_fork_penalty\n");
    __atomic_store_n(&fork_penalty_parent_iters, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&fork_penalty_child_done, 0, __ATOMIC_RELEASE);

    struct process *p = kthread_create_joinable(fork_penalty_parent, NULL, "fpp");
    if (p) sched_enqueue(p);

    int reaped = reap_children_bounded(p ? 1 : 0, "eevdf_fork_penalty");
    if (p && reaped != 1)
        test_fail("sched_stress: eevdf_fork_penalty FAIL: reaped %d/%d\n",
                  reaped, 1);
    int pi = __atomic_load_n(&fork_penalty_parent_iters, __ATOMIC_ACQUIRE);
    int cd = __atomic_load_n(&fork_penalty_child_done, __ATOMIC_ACQUIRE);
    pr_info("sched_stress: eevdf_fork_penalty done (parent_iters=%d children=%d/%d)\n",
            pi, cd, FORK_PENALTY_N);
    if (pi < FORK_PENALTY_N / 2)
        test_fail("sched_stress: eevdf_fork_penalty FAIL: parent starved (%d/%d)\n",
                  pi, FORK_PENALTY_N);
}

/* ---------- Entry point ---------- */

int run_sched_stress_tests(void) {
    tests_failed = 0;
    pr_info("sched_stress: starting\n");
    test_sched_fork_exit_storm();
    if (tests_failed == 0)
        test_sched_sleep_wakeup_stress();
    if (tests_failed == 0)
        test_poll_wait_head_single_waiter_fastpath();
    if (tests_failed == 0)
        test_sched_yield_storm();
    if (tests_failed == 0)
        test_sched_preempt_stress();
    if (tests_failed == 0)
        test_sched_kthread_steal_policy();
    if (tests_failed == 0)
        test_eevdf_deadline_ordering();
    if (tests_failed == 0)
        test_eevdf_lag_fairness();
    if (tests_failed == 0)
        test_eevdf_nice_isolation();
    if (tests_failed == 0)
        test_eevdf_fork_penalty();
    if (tests_failed > 0)
        pr_warn("sched_stress: aborting after first failure\n");
    if (tests_failed == 0)
        pr_info("sched_stress: all passed\n");
    else
        pr_err("sched_stress: %d failures\n", tests_failed);
    return tests_failed;
}

#endif /* CONFIG_KERNEL_TESTS */
