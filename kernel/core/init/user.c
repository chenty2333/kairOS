/**
 * kernel/core/init/user.c - User mode initialization
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/init.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/vfs.h>

int run_driver_tests(void);
int run_mm_tests(void);
int run_syscall_trap_tests(void);
int run_vfs_ipc_tests(void);
int run_socket_tests(void);
int run_device_virtio_tests(void);
int run_tty_tests(void);
int run_soak_tests(void);
int run_input_tests(void);
extern int run_sched_stress_tests(void);

#if CONFIG_KERNEL_TESTS
enum kernel_test_module_bits {
    KTEST_MOD_DRIVER = 1U << 0,
    KTEST_MOD_MM = 1U << 1,
    KTEST_MOD_SYNC = 1U << 2,
    KTEST_MOD_VFORK = 1U << 3,
    KTEST_MOD_SCHED = 1U << 4,
    KTEST_MOD_CRASH = 1U << 5,
    KTEST_MOD_SYSCALL_TRAP = 1U << 6,
    KTEST_MOD_VFS_IPC = 1U << 7,
    KTEST_MOD_SOCKET = 1U << 8,
    KTEST_MOD_DEV_VIRTIO = 1U << 9,
    KTEST_MOD_TTY = 1U << 10,
    KTEST_MOD_SOAK = 1U << 11,
    KTEST_MOD_INPUT = 1U << 12,
};

static int kernel_test_module_enabled(unsigned int bit) {
    return (CONFIG_KERNEL_TEST_MASK & bit) != 0;
}

static void kernel_test_log_ipc_hash_stats(void) {
    struct file *f = NULL;
    char buf[1024];

    int rc = vfs_open("/sys/ipc/hash_stats", O_RDONLY, 0, &f);
    if (rc < 0 || !f) {
        pr_warn("kernel tests: /sys/ipc/hash_stats open failed (ret=%d)\n", rc);
        return;
    }

    ssize_t n = vfs_read(f, buf, sizeof(buf) - 1);
    vfs_close(f);
    if (n < 0) {
        pr_warn("kernel tests: /sys/ipc/hash_stats read failed (ret=%zd)\n", n);
        return;
    }
    buf[n] = '\0';

    pr_info("kernel tests: /sys/ipc/hash_stats begin\n");
    pr_info("%s", buf);
    if (n == 0 || buf[n - 1] != '\n')
        pr_info("\n");
    pr_info("kernel tests: /sys/ipc/hash_stats end\n");
}

static void kernel_test_drain_children(void) {
    int status = 0;
    int miss_streak = 0;
    uint64_t start = arch_timer_ticks();
    uint64_t timeout_ticks = arch_timer_ns_to_ticks(10ULL * 1000 * 1000 * 1000);

    while (1) {
        pid_t pid = proc_wait(-1, &status, WNOHANG);
        if (pid > 0) {
            miss_streak = 0;
            continue;
        }
        if (pid < 0)
            break;
        if ((arch_timer_ticks() - start) > timeout_ticks) {
            pr_err("kernel tests: child drain timeout\n");
            int cpus = sched_cpu_count();
            if (cpus < 1)
                cpus = 1;
            for (int c = 0; c < cpus; c++)
                sched_debug_dump_cpu(c);
            break;
        }
        miss_streak++;
        if ((miss_streak & 31) == 0)
            proc_yield();
        else
            arch_cpu_relax();
    }
}

static int kernel_test_main(void *arg __attribute__((unused))) {
    int suite_fail = 0;
    int total_failed = 0;

    if (kernel_test_module_enabled(KTEST_MOD_DRIVER)) {
        suite_fail = run_driver_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping driver tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_MM)) {
        suite_fail = run_mm_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping mm tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_SYSCALL_TRAP)) {
        suite_fail = run_syscall_trap_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping syscall/trap tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_VFS_IPC)) {
        suite_fail = run_vfs_ipc_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping vfs/ipc tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_SOCKET)) {
        suite_fail = run_socket_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping socket tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_DEV_VIRTIO)) {
        suite_fail = run_device_virtio_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping device/virtio tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_TTY)) {
        suite_fail = run_tty_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping tty tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_SOAK)) {
        suite_fail = run_soak_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping soak tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_INPUT)) {
        suite_fail = run_input_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping input tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_SYNC) ||
        kernel_test_module_enabled(KTEST_MOD_VFORK) ||
        kernel_test_module_enabled(KTEST_MOD_SCHED) ||
        kernel_test_module_enabled(KTEST_MOD_CRASH)) {
        pr_info("Starting robustness test...\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_SYNC))
        run_sync_test();
    else
        pr_info("Skipping sync test (CONFIG_KERNEL_TEST_MASK)\n");

    if (kernel_test_module_enabled(KTEST_MOD_VFORK))
        run_vfork_test();
    else
        pr_info("Skipping vfork test (CONFIG_KERNEL_TEST_MASK)\n");

    if (kernel_test_module_enabled(KTEST_MOD_SCHED)) {
        suite_fail = run_sched_stress_tests();
        total_failed += (suite_fail > 0) ? suite_fail : 0;
    } else {
        pr_info("Skipping sched tests (CONFIG_KERNEL_TEST_MASK)\n");
    }

    if (kernel_test_module_enabled(KTEST_MOD_CRASH)) {
#if defined(ARCH_riscv64)
        run_crash_test();
#else
        pr_info("Skipping crash test on this architecture\n");
#endif
    } else {
        pr_info("Skipping crash test (CONFIG_KERNEL_TEST_MASK)\n");
    }

    arch_irq_enable();
    kernel_test_drain_children();
    kernel_test_log_ipc_hash_stats();

    if (total_failed == 0)
        pr_info("TEST_SUMMARY: failed=0\n");
    else
        pr_err("TEST_SUMMARY: failed=%d\n", total_failed);
    pr_info("TEST_RESULT_JSON: {\"schema_version\":1,\"failed\":%d,\"done\":true,\"enabled_mask\":%u}\n",
            total_failed, (unsigned int)CONFIG_KERNEL_TEST_MASK);
    pr_info("Tests complete. Stopping system...\n");
    arch_cpu_shutdown();
    while (1) {
        arch_cpu_halt();
    }
}
#endif

void init_user(void) {
#if CONFIG_KERNEL_TESTS
    struct process *runner = kthread_create(kernel_test_main, NULL, "ktest");
    if (!runner) {
        pr_err("kernel tests: failed to start test runner thread\n");
        arch_cpu_shutdown();
        while (1) {
            arch_cpu_halt();
        }
    }
    sched_enqueue(runner);
    arch_irq_enable();
    while (1) {
        schedule();
    }
#else
    struct process *initp = proc_start_init();
    if (!initp) {
        pr_warn("init: failed to start init thread\n");
    }
    arch_irq_enable();
    /* No test harness: keep the scheduler running. */
    while (1) {
        schedule();
    }
#endif
}
