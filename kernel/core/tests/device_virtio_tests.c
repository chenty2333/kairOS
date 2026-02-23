/**
 * kernel/core/tests/device_virtio_tests.c - Device model and VirtIO tests
 */

#include <kairos/device.h>
#include <kairos/io.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/virtio.h>

#if CONFIG_KERNEL_TESTS

#define KT_VIRTIO_DEV_ID_OK 0x7feeU
#define KT_VIRTIO_DEV_ID_NOMATCH 0x7fedU
#define KT_VIRTIO_DEV_ID_FAIL 0x7fecU

#define VIRTIO_MMIO_MAGIC_VALUE 0x000
#define VIRTIO_MMIO_DEVICE_ID 0x008

extern struct driver virtio_mmio_driver;

static int tests_failed;

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("device_virtio_tests: %s failed\n", name);
        tests_failed++;
    }
}

static int match_by_compatible(struct device *dev, struct driver *drv) {
    if (!drv || !drv->compatible)
        return 0;
    return strcmp(dev->compatible, drv->compatible) == 0;
}

/* ---- Device model: success + cleanup ---- */

static int dm_probe_ok_calls;
static int dm_remove_ok_calls;
static int dm_probe_ok(struct device *dev) {
    dm_probe_ok_calls++;
    dev_set_drvdata(dev, (void *)"bound");
    return 0;
}

static void dm_remove_ok(struct device *dev) {
    dm_remove_ok_calls++;
    dev_set_drvdata(dev, NULL);
}

static void test_device_register_bind_unbind(void) {
    struct bus_type bus = {
        .name = "ktest-bus-ok",
        .match = match_by_compatible,
    };
    struct driver drv = {
        .name = "ktest-drv-ok",
        .compatible = "ktest,ok",
        .bus = &bus,
        .probe = dm_probe_ok,
        .remove = dm_remove_ok,
    };
    struct device dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, "ktest-dev-ok", sizeof(dev.name) - 1);
    strncpy(dev.compatible, "ktest,ok", sizeof(dev.compatible) - 1);
    dev.bus = &bus;

    dm_probe_ok_calls = 0;
    dm_remove_ok_calls = 0;

    int ret = bus_register(&bus);
    test_check(ret == 0, "dm_ok bus_register");
    if (ret < 0)
        return;

    ret = device_register(&dev);
    test_check(ret == 0, "dm_ok device_register pre-driver");
    test_check(dev.driver == NULL, "dm_ok pre-driver unbound");
    if (ret < 0) {
        bus_unregister(&bus);
        return;
    }

    ret = driver_register(&drv);
    test_check(ret == 0, "dm_ok driver_register");
    test_check(dev.driver == &drv, "dm_ok bound after driver_register");
    test_check(dm_probe_ok_calls == 1, "dm_ok probe called once");
    test_check(strcmp((const char *)dev_get_drvdata(&dev), "bound") == 0,
               "dm_ok drvdata set");

    device_unregister(&dev);
    test_check(dm_remove_ok_calls == 1, "dm_ok remove called on device_unregister");
    test_check(dev.driver == NULL, "dm_ok device driver cleared");
    test_check(dev_get_drvdata(&dev) == NULL, "dm_ok drvdata cleared");

    driver_unregister(&drv);
    bus_unregister(&bus);
}

/* ---- Device model: probe failure rollback ---- */

static int dm_probe_fail_calls;
static int dm_remove_fail_calls;
static int dm_probe_fail(struct device *dev) {
    (void)dev;
    dm_probe_fail_calls++;
    return -EIO;
}

static void dm_remove_fail(struct device *dev) {
    (void)dev;
    dm_remove_fail_calls++;
}

static void test_device_probe_failure_rollback(void) {
    struct bus_type bus = {
        .name = "ktest-bus-fail",
        .match = match_by_compatible,
    };
    struct driver drv = {
        .name = "ktest-drv-fail",
        .compatible = "ktest,fail",
        .bus = &bus,
        .probe = dm_probe_fail,
        .remove = dm_remove_fail,
    };
    struct device dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, "ktest-dev-fail", sizeof(dev.name) - 1);
    strncpy(dev.compatible, "ktest,fail", sizeof(dev.compatible) - 1);
    dev.bus = &bus;

    dm_probe_fail_calls = 0;
    dm_remove_fail_calls = 0;

    int ret = bus_register(&bus);
    test_check(ret == 0, "dm_fail bus_register");
    if (ret < 0)
        return;

    ret = driver_register(&drv);
    test_check(ret == 0, "dm_fail driver_register");
    if (ret < 0) {
        bus_unregister(&bus);
        return;
    }

    ret = device_register(&dev);
    test_check(ret == 0, "dm_fail device_register");
    test_check(dm_probe_fail_calls == 1, "dm_fail probe called");
    test_check(dev.driver == NULL, "dm_fail rollback unbound");

    device_unregister(&dev);
    test_check(dm_remove_fail_calls == 0, "dm_fail remove not called");

    driver_unregister(&drv);
    bus_unregister(&bus);
}

/* ---- Device model: driver_unregister unbind ---- */

static int dm_probe_unbind_calls;
static int dm_remove_unbind_calls;
static int dm_probe_unbind(struct device *dev) {
    dm_probe_unbind_calls++;
    dev_set_drvdata(dev, (void *)"unbind");
    return 0;
}

static void dm_remove_unbind(struct device *dev) {
    dm_remove_unbind_calls++;
    dev_set_drvdata(dev, NULL);
}

static void test_driver_unregister_cleanup(void) {
    struct bus_type bus = {
        .name = "ktest-bus-unbind",
        .match = match_by_compatible,
    };
    struct driver drv = {
        .name = "ktest-drv-unbind",
        .compatible = "ktest,unbind",
        .bus = &bus,
        .probe = dm_probe_unbind,
        .remove = dm_remove_unbind,
    };
    struct device dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, "ktest-dev-unbind", sizeof(dev.name) - 1);
    strncpy(dev.compatible, "ktest,unbind", sizeof(dev.compatible) - 1);
    dev.bus = &bus;

    dm_probe_unbind_calls = 0;
    dm_remove_unbind_calls = 0;

    int ret = bus_register(&bus);
    test_check(ret == 0, "dm_unbind bus_register");
    if (ret < 0)
        return;

    ret = driver_register(&drv);
    test_check(ret == 0, "dm_unbind driver_register");
    if (ret < 0) {
        bus_unregister(&bus);
        return;
    }

    ret = device_register(&dev);
    test_check(ret == 0, "dm_unbind device_register");
    test_check(dm_probe_unbind_calls == 1, "dm_unbind probe called");
    test_check(dev.driver == &drv, "dm_unbind bound");

    driver_unregister(&drv);
    test_check(dm_remove_unbind_calls == 1, "dm_unbind remove on driver_unregister");
    test_check(dev.driver == NULL, "dm_unbind driver cleared");
    test_check(dev_get_drvdata(&dev) == NULL, "dm_unbind drvdata cleared");

    device_unregister(&dev);
    test_check(dm_remove_unbind_calls == 1, "dm_unbind remove not double-called");
    bus_unregister(&bus);
}

/* ---- VirtIO core lifecycle ---- */

struct fake_virtio_transport {
    uint8_t status;
    uint64_t features;
    uint64_t finalized_features;
    bool reject_features_ok;
};

static uint8_t fake_get_status(struct virtio_device *vdev) {
    struct fake_virtio_transport *t = vdev->priv;
    return t ? t->status : 0;
}

static void fake_set_status(struct virtio_device *vdev, uint8_t status) {
    struct fake_virtio_transport *t = vdev->priv;
    if (!t)
        return;
    if (t->reject_features_ok && (status & VIRTIO_STATUS_FEATURES_OK))
        status &= (uint8_t)~VIRTIO_STATUS_FEATURES_OK;
    t->status = status;
}

static uint64_t fake_get_features(struct virtio_device *vdev) {
    struct fake_virtio_transport *t = vdev->priv;
    return t ? t->features : 0;
}

static void fake_finalize_features(struct virtio_device *vdev, uint64_t features) {
    struct fake_virtio_transport *t = vdev->priv;
    if (t)
        t->finalized_features = features;
}

static int fake_setup_vq(struct virtio_device *vdev, uint32_t index,
                         struct virtqueue *vq) {
    (void)vdev;
    (void)index;
    (void)vq;
    return 0;
}

static void fake_notify(struct virtqueue *vq) { (void)vq; }
static void fake_get_config(struct virtio_device *vdev, uint32_t offset, void *buf,
                            uint32_t len) {
    (void)vdev;
    (void)offset;
    memset(buf, 0, len);
}

static struct virtio_config_ops fake_ops = {
    .get_status = fake_get_status,
    .set_status = fake_set_status,
    .get_features = fake_get_features,
    .finalize_features = fake_finalize_features,
    .setup_vq = fake_setup_vq,
    .notify = fake_notify,
    .get_config = fake_get_config,
};

static int vt_probe_ok_calls;
static int vt_remove_ok_calls;
static int vt_probe_ok(struct virtio_device *vdev) {
    vt_probe_ok_calls++;
    int ret = virtio_device_init(vdev, 0x5a5aU);
    if (ret < 0)
        return ret;
    ret = virtio_device_ready(vdev);
    if (ret < 0)
        return ret;
    virtio_device_set_failed(vdev);
    return 0;
}

static void vt_remove_ok(struct virtio_device *vdev) {
    (void)vdev;
    vt_remove_ok_calls++;
}

static int vt_probe_fail_calls;
static int vt_remove_fail_calls;
static int vt_probe_fail(struct virtio_device *vdev) {
    vt_probe_fail_calls++;
    return virtio_device_init(vdev, 0x33U);
}

static void vt_remove_fail(struct virtio_device *vdev) {
    (void)vdev;
    vt_remove_fail_calls++;
}

static void test_virtio_bus_probe_and_rollback(void) {
    struct fake_virtio_transport t_nomatch = {
        .features = 0xffff,
    };
    struct fake_virtio_transport t_match = {
        .features = 0xffff,
    };
    struct fake_virtio_transport t_fail = {
        .features = 0xffff,
        .reject_features_ok = true,
    };

    struct virtio_driver ok_drv = {
        .drv = {.name = "ktest-virtio-ok"},
        .device_id = KT_VIRTIO_DEV_ID_OK,
        .probe = vt_probe_ok,
        .remove = vt_remove_ok,
    };
    struct virtio_driver fail_drv = {
        .drv = {.name = "ktest-virtio-fail"},
        .device_id = KT_VIRTIO_DEV_ID_FAIL,
        .probe = vt_probe_fail,
        .remove = vt_remove_fail,
    };

    struct virtio_device nomatch_dev;
    struct virtio_device match_dev;
    struct virtio_device fail_dev;
    memset(&nomatch_dev, 0, sizeof(nomatch_dev));
    memset(&match_dev, 0, sizeof(match_dev));
    memset(&fail_dev, 0, sizeof(fail_dev));

    nomatch_dev.id = KT_VIRTIO_DEV_ID_NOMATCH;
    nomatch_dev.ops = &fake_ops;
    nomatch_dev.priv = &t_nomatch;
    strncpy(nomatch_dev.dev.name, "ktest-virtio-nomatch",
            sizeof(nomatch_dev.dev.name) - 1);

    match_dev.id = KT_VIRTIO_DEV_ID_OK;
    match_dev.ops = &fake_ops;
    match_dev.priv = &t_match;
    strncpy(match_dev.dev.name, "ktest-virtio-match",
            sizeof(match_dev.dev.name) - 1);

    fail_dev.id = KT_VIRTIO_DEV_ID_FAIL;
    fail_dev.ops = &fake_ops;
    fail_dev.priv = &t_fail;
    strncpy(fail_dev.dev.name, "ktest-virtio-fail",
            sizeof(fail_dev.dev.name) - 1);

    vt_probe_ok_calls = 0;
    vt_remove_ok_calls = 0;
    vt_probe_fail_calls = 0;
    vt_remove_fail_calls = 0;

    int ret = virtio_register_driver(&ok_drv);
    test_check(ret == 0, "virtio_ok driver_register");
    if (ret < 0)
        return;

    ret = virtio_register_driver(&fail_drv);
    test_check(ret == 0, "virtio_fail driver_register");
    if (ret < 0) {
        driver_unregister(&ok_drv.drv);
        return;
    }

    ret = virtio_device_register(&nomatch_dev);
    test_check(ret == 0, "virtio nomatch device_register");
    test_check(nomatch_dev.dev.driver == NULL, "virtio nomatch unbound");

    ret = virtio_device_register(&match_dev);
    test_check(ret == 0, "virtio match device_register");
    test_check(match_dev.dev.driver == &ok_drv.drv, "virtio match bound");
    test_check(vt_probe_ok_calls == 1, "virtio match probe called");
    test_check(t_match.finalized_features == 0x5a5aU, "virtio match finalize features");
    test_check((t_match.status & VIRTIO_STATUS_ACKNOWLEDGE) != 0,
               "virtio match status acknowledge");
    test_check((t_match.status & VIRTIO_STATUS_DRIVER) != 0,
               "virtio match status driver");
    test_check((t_match.status & VIRTIO_STATUS_FEATURES_OK) != 0,
               "virtio match status features_ok");
    test_check((t_match.status & VIRTIO_STATUS_DRIVER_OK) != 0,
               "virtio match status driver_ok");
    test_check((t_match.status & VIRTIO_STATUS_FAILED) != 0,
               "virtio match status failed");

    ret = virtio_device_register(&fail_dev);
    test_check(ret == 0, "virtio fail device_register");
    test_check(vt_probe_fail_calls == 1, "virtio fail probe called");
    test_check(fail_dev.dev.driver == NULL, "virtio fail rollback unbound");
    test_check((t_fail.status & VIRTIO_STATUS_FAILED) != 0,
               "virtio fail status failed");
    test_check((t_fail.status & VIRTIO_STATUS_DRIVER_OK) == 0,
               "virtio fail no driver_ok");

    device_unregister(&match_dev.dev);
    test_check(vt_remove_ok_calls == 1, "virtio match remove on device_unregister");

    device_unregister(&nomatch_dev.dev);
    device_unregister(&fail_dev.dev);
    test_check(vt_remove_fail_calls == 0, "virtio fail remove not called");

    driver_unregister(&fail_drv.drv);
    driver_unregister(&ok_drv.drv);
}

/* ---- VirtIO MMIO detection fail-fast ---- */

static void mmio_write32(uint8_t *base, uint32_t off, uint32_t val) {
    writel(val, (void *)(base + off));
}

static void test_virtio_mmio_probe_failfast(void) {
    struct device dev_no_res;
    memset(&dev_no_res, 0, sizeof(dev_no_res));
    int ret = virtio_mmio_driver.probe(&dev_no_res);
    test_check(ret == -ENODEV, "virtio_mmio no_resources enodev");

    uint8_t *mmio = kzalloc(0x200);
    test_check(mmio != NULL, "virtio_mmio alloc regs");
    if (!mmio)
        return;

    paddr_t mmio_pa = virt_to_phys(mmio);
    struct resource res[2] = {
        {
            .start = mmio_pa,
            .end = mmio_pa + 0x1ff,
            .flags = IORESOURCE_MEM,
        },
        {
            .start = 1,
            .end = 1,
            .flags = IORESOURCE_IRQ,
        },
    };

    struct device dev_bad_magic;
    memset(&dev_bad_magic, 0, sizeof(dev_bad_magic));
    strncpy(dev_bad_magic.name, "ktest-mmio-badmagic", sizeof(dev_bad_magic.name) - 1);
    dev_bad_magic.resources = res;
    dev_bad_magic.num_resources = 2;
    ret = virtio_mmio_driver.probe(&dev_bad_magic);
    test_check(ret == -ENODEV, "virtio_mmio bad_magic enodev");

    mmio_write32(mmio, VIRTIO_MMIO_MAGIC_VALUE, 0x74726976);
    mmio_write32(mmio, VIRTIO_MMIO_DEVICE_ID, 0);
    struct device dev_reserved;
    memset(&dev_reserved, 0, sizeof(dev_reserved));
    strncpy(dev_reserved.name, "ktest-mmio-reserved", sizeof(dev_reserved.name) - 1);
    dev_reserved.resources = res;
    dev_reserved.num_resources = 2;
    ret = virtio_mmio_driver.probe(&dev_reserved);
    test_check(ret == -ENODEV, "virtio_mmio reserved_id enodev");

    kfree(mmio);
}

int run_device_virtio_tests(void) {
    tests_failed = 0;
    pr_info("\n=== Device/VirtIO Tests ===\n");

    test_device_register_bind_unbind();
    test_device_probe_failure_rollback();
    test_driver_unregister_cleanup();
    test_virtio_bus_probe_and_rollback();
    test_virtio_mmio_probe_failfast();

    if (tests_failed == 0)
        pr_info("device/virtio tests: all passed\n");
    else
        pr_err("device/virtio tests: %d failures\n", tests_failed);
    return tests_failed;
}

#else

int run_device_virtio_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
