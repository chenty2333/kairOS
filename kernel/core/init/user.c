/**
 * kernel/core/init/user.c - User mode initialization
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/init.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>

void run_driver_tests(void);
extern void run_sched_stress_tests(void);

void init_user(void) {
#if CONFIG_KERNEL_TESTS
    run_driver_tests();
    pr_info("Starting robustness test...\n");
    run_sync_test();
    run_vfork_test();
    run_sched_stress_tests();
#if defined(ARCH_riscv64)
    run_crash_test();
#else
    pr_info("Skipping crash test on this architecture\n");
#endif

    arch_irq_enable();
    int status;
    while (proc_wait(-1, &status, 0) > 0) {
        ;
    }

    pr_info("Tests complete. Stopping system...\n");
    arch_cpu_shutdown();
    while (1) {
        arch_cpu_halt();
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
