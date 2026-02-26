/**
 * kernel/core/tests/input_tests.c - Input subsystem tests
 */

#include <kairos/input.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>

#if CONFIG_KERNEL_TESTS

static int tests_failed;

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("input_tests: %s failed\n", name);
        tests_failed++;
    }
}

static void test_input_dev_alloc_free(void) {
    struct input_dev *dev = input_dev_alloc();
    test_check(dev != NULL, "input_dev_alloc returns non-NULL");
    if (!dev)
        return;

    test_check(dev->name[0] == '\0', "input_dev name initially empty");
    input_dev_free(dev);
}

static void test_input_dev_register_unregister(void) {
    struct input_dev *dev = input_dev_alloc();
    test_check(dev != NULL, "alloc for register test");
    if (!dev)
        return;

    strncpy(dev->name, "ktest-input", sizeof(dev->name) - 1);
    dev->id_bus = BUS_VIRTUAL;
    dev->id_vendor = 0xFFFF;
    dev->id_product = 0xFFFF;

    int ret = input_dev_register(dev);
    test_check(ret == 0, "input_dev_register succeeds");

    int count = input_dev_get_count();
    test_check(count > 0, "input_dev_get_count > 0 after register");

    input_dev_unregister(dev);

    int count_after = input_dev_get_count();
    test_check(count_after == count - 1, "count decremented after unregister");

    input_dev_free(dev);
}

static void test_input_event_report(void) {
    struct input_dev *dev = input_dev_alloc();
    test_check(dev != NULL, "alloc for event report test");
    if (!dev)
        return;

    strncpy(dev->name, "ktest-event", sizeof(dev->name) - 1);
    dev->id_bus = BUS_VIRTUAL;

    int ret = input_dev_register(dev);
    test_check(ret == 0, "register for event report test");

    /* Report events with no clients — should not crash */
    input_report_key(dev, KEY_A, 1);
    input_report_key(dev, KEY_A, 0);
    input_sync(dev);
    input_report_rel(dev, REL_X, 10);
    input_sync(dev);

    test_check(true, "event report with no clients does not crash");

    input_dev_unregister(dev);
    input_dev_free(dev);
}

static void test_scancode_mapping(void) {
    /* Verify a few well-known scancode positions via the keyboard driver's
     * exported tables. Since the tables are static, we just verify the
     * key code constants are sane. */
    test_check(KEY_A == 30, "KEY_A == 30");
    test_check(KEY_ENTER == 28, "KEY_ENTER == 28");
    test_check(KEY_SPACE == 57, "KEY_SPACE == 57");
    test_check(KEY_ESC == 1, "KEY_ESC == 1");
    test_check(BTN_LEFT == 0x110, "BTN_LEFT == 0x110");
    test_check(REL_X == 0x00, "REL_X == 0x00");
    test_check(REL_Y == 0x01, "REL_Y == 0x01");
}

int run_input_tests(void) {
    tests_failed = 0;

    pr_info("=== Input subsystem tests ===\n");

    test_input_dev_alloc_free();
    test_input_dev_register_unregister();
    test_input_event_report();
    test_scancode_mapping();

    if (tests_failed)
        pr_err("input_tests: %d test(s) FAILED\n", tests_failed);
    else
        pr_info("input_tests: all tests passed\n");

    return tests_failed;
}

#else /* !CONFIG_KERNEL_TESTS */

int run_input_tests(void) { return 0; }

#endif
