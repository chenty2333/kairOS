/**
 * kernel/core/tests/syscall_trap_tests.c - Syscall/trap boundary tests
 */

#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/trap_core.h>

#if CONFIG_KERNEL_TESTS

static int tests_failed;

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("syscall_trap_tests: %s failed\n", name);
        tests_failed++;
    }
}

static int trap_handle_calls;
static int trap_should_deliver_calls;
static bool trap_handler_saw_current_tf;
static struct trap_frame *trap_handler_tf;

static int64_t dispatch_legacy(uint64_t num, uint64_t a0, uint64_t a1,
                               uint64_t a2, uint64_t a3, uint64_t a4,
                               uint64_t a5) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    enum syscall_abi old_abi = p->syscall_abi;
    p->syscall_abi = SYSCALL_ABI_LEGACY;
    int64_t ret = syscall_dispatch(num, a0, a1, a2, a3, a4, a5);
    p->syscall_abi = old_abi;
    return ret;
}

static int trap_handle_probe(const struct trap_core_event *ev) {
    trap_handle_calls++;
    trap_handler_tf = ev ? ev->tf : NULL;
    trap_handler_saw_current_tf =
        ev && (arch_get_percpu()->current_tf == ev->tf);
    return 0;
}

static bool trap_should_deliver_false(const struct trap_core_event *ev) {
    (void)ev;
    trap_should_deliver_calls++;
    return false;
}

static void test_syscall_table_slot_coverage(void) {
    test_check(syscall_table[SYS_exit] != NULL, "table SYS_exit present");
    test_check(syscall_table[SYS_fork] != NULL, "table SYS_fork present");
    test_check(syscall_table[SYS_getpid] != NULL, "table SYS_getpid present");
    test_check(syscall_table[SYS_getppid] != NULL, "table SYS_getppid present");
    test_check(syscall_table[SYS_getuid] != NULL, "table SYS_getuid present");
    test_check(syscall_table[SYS_getgid] != NULL, "table SYS_getgid present");
    test_check(syscall_table[SYS_open] != NULL, "table SYS_open present");
    test_check(syscall_table[SYS_read] != NULL, "table SYS_read present");
    test_check(syscall_table[SYS_write] != NULL, "table SYS_write present");
    test_check(syscall_table[SYS_close] != NULL, "table SYS_close present");
    test_check(syscall_table[SYS_pipe2] != NULL, "table SYS_pipe2 present");
    test_check(syscall_table[SYS_poll] != NULL, "table SYS_poll present");
    test_check(syscall_table[SYS_clock_gettime] != NULL,
               "table SYS_clock_gettime present");
    test_check(syscall_table[SYS_uname] != NULL, "table SYS_uname present");

    test_check(syscall_table[SYS_yield] == NULL, "table SYS_yield absent");
    test_check(syscall_table[SYS_clone] == NULL, "table SYS_clone absent");
    test_check(syscall_table[SYS_mmap] == NULL, "table SYS_mmap absent");
    test_check(syscall_table[SYS_munmap] == NULL, "table SYS_munmap absent");
    test_check(syscall_table[SYS_mprotect] == NULL,
               "table SYS_mprotect absent");
}

static void test_syscall_invalid_num_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_invalid_num proc_current");
    if (!p)
        return;

    int64_t ret = dispatch_legacy(SYS_MAX, 0, 0, 0, 0, 0, 0);

    test_check(ret == -ENOSYS, "legacy_invalid_num enosys");
}

static void test_syscall_unimplemented_slot_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_unimplemented proc_current");
    if (!p)
        return;

    const uint64_t missing[] = {
        SYS_yield,
        SYS_clone,
        SYS_mmap,
        SYS_munmap,
        SYS_mprotect,
    };

    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); i++) {
        int64_t ret = dispatch_legacy(missing[i], 0, 0, 0, 0, 0, 0);
        test_check(ret == -ENOSYS, "legacy_unimplemented enosys");
    }
}

static void test_syscall_identity_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_identity proc_current");
    if (!p)
        return;

    int64_t pid = dispatch_legacy(SYS_getpid, 0, 0, 0, 0, 0, 0);
    int64_t ppid = dispatch_legacy(SYS_getppid, 0, 0, 0, 0, 0, 0);
    int64_t uid = dispatch_legacy(SYS_getuid, 0, 0, 0, 0, 0, 0);
    int64_t gid = dispatch_legacy(SYS_getgid, 0, 0, 0, 0, 0, 0);

    test_check(pid == (int64_t)p->tgid, "legacy_getpid matches_current");
    test_check(ppid == (int64_t)p->ppid, "legacy_getppid matches_current");
    test_check(uid == (int64_t)p->uid, "legacy_getuid matches_current");
    test_check(gid == (int64_t)p->gid, "legacy_getgid matches_current");
}

static void test_syscall_error_paths_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_errors proc_current");
    if (!p)
        return;

    int64_t uname_ret = dispatch_legacy(SYS_uname, 0, 0, 0, 0, 0, 0);
    test_check(uname_ret == -EFAULT, "legacy_uname null_efault");
}

static void test_trap_dispatch_guard_clauses(void) {
    struct trap_frame tf;
    memset(&tf, 0, sizeof(tf));

    struct trap_core_event ev = {
        .type = TRAP_CORE_EVENT_SYSCALL,
        .tf = &tf,
        .from_user = false,
        .code = 0,
        .fault_addr = 0,
    };
    struct trap_core_ops ops = {
        .handle_event = trap_handle_probe,
        .should_deliver_signals = trap_should_deliver_false,
    };
    struct trap_core_ops ops_no_handler = {
        .handle_event = NULL,
        .should_deliver_signals = trap_should_deliver_false,
    };

    trap_handle_calls = 0;
    trap_should_deliver_calls = 0;

    trap_core_dispatch(NULL, &ops);
    trap_core_dispatch(&ev, NULL);
    trap_core_dispatch(&ev, &ops_no_handler);
    ev.tf = NULL;
    trap_core_dispatch(&ev, &ops);

    test_check(trap_handle_calls == 0, "trap_guard no_handle_calls");
    test_check(trap_should_deliver_calls == 0, "trap_guard no_deliver_calls");
}

static void test_trap_dispatch_sets_and_restores_tf(void) {
    struct trap_frame tf;
    memset(&tf, 0, sizeof(tf));

    struct trap_core_event ev = {
        .type = TRAP_CORE_EVENT_SYSCALL,
        .tf = &tf,
        .from_user = false,
        .code = 0,
        .fault_addr = 0,
    };
    struct trap_core_ops ops = {
        .handle_event = trap_handle_probe,
        .should_deliver_signals = trap_should_deliver_false,
    };

    struct percpu_data *cpu = arch_get_percpu();
    struct trap_frame *old_tf = cpu->current_tf;

    trap_handle_calls = 0;
    trap_should_deliver_calls = 0;
    trap_handler_saw_current_tf = false;
    trap_handler_tf = NULL;

    trap_core_dispatch(&ev, &ops);

    test_check(trap_handle_calls == 1, "trap_dispatch handle_called");
    test_check(trap_should_deliver_calls == 1, "trap_dispatch deliver_called");
    test_check(trap_handler_tf == &tf, "trap_dispatch handler_tf");
    test_check(trap_handler_saw_current_tf, "trap_dispatch saw_current_tf");
    test_check(cpu->current_tf == old_tf, "trap_dispatch restored_tf");
}

static void test_trap_dispatch_restores_preexisting_tf(void) {
    struct trap_frame tf;
    struct trap_frame injected_old;
    memset(&tf, 0, sizeof(tf));
    memset(&injected_old, 0, sizeof(injected_old));

    struct trap_core_event ev = {
        .type = TRAP_CORE_EVENT_PAGE_FAULT,
        .tf = &tf,
        .from_user = true,
        .code = 1,
        .fault_addr = 0x1000,
    };
    struct trap_core_ops ops = {
        .handle_event = trap_handle_probe,
        .should_deliver_signals = trap_should_deliver_false,
    };

    struct percpu_data *cpu = arch_get_percpu();
    struct trap_frame *saved = cpu->current_tf;
    cpu->current_tf = &injected_old;

    trap_handle_calls = 0;
    trap_should_deliver_calls = 0;
    trap_handler_saw_current_tf = false;
    trap_handler_tf = NULL;

    trap_core_dispatch(&ev, &ops);

    test_check(trap_handle_calls == 1, "trap_restore_nonnull handle_called");
    test_check(trap_should_deliver_calls == 1,
               "trap_restore_nonnull deliver_called");
    test_check(trap_handler_tf == &tf, "trap_restore_nonnull handler_tf");
    test_check(trap_handler_saw_current_tf, "trap_restore_nonnull saw_current");
    test_check(cpu->current_tf == &injected_old,
               "trap_restore_nonnull restored_previous");

    cpu->current_tf = saved;
}

int run_syscall_trap_tests(void) {
    tests_failed = 0;
    pr_info("Running syscall/trap tests...\n");

    test_syscall_table_slot_coverage();
    test_syscall_invalid_num_legacy();
    test_syscall_unimplemented_slot_legacy();
    test_syscall_identity_legacy();
    test_syscall_error_paths_legacy();
    test_trap_dispatch_guard_clauses();
    test_trap_dispatch_sets_and_restores_tf();
    test_trap_dispatch_restores_preexisting_tf();

    if (tests_failed == 0)
        pr_info("syscall/trap tests: all passed\n");
    else
        pr_err("syscall/trap tests: %d failures\n", tests_failed);

    return tests_failed;
}

#else

int run_syscall_trap_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
