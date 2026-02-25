/**
 * kernel/core/tests/driver_tests.c - Driver and helper tests
 */

#include <kairos/arch.h>
#include <kairos/blkdev.h>
#include <kairos/config.h>
#include <kairos/dma.h>
#include <kairos/net.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/ringbuf.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
#include <kairos/virtio.h>

static int tests_failed;

#if CONFIG_KERNEL_TESTS
extern int virtio_net_test_rx_deliver_len(uint32_t len);
extern void lwip_netif_test_reset_rx_stats(void);
extern uint64_t lwip_netif_test_rx_input_count_get(void);
extern uint64_t lwip_netif_test_rx_input_last_len_get(void);
extern bool lwip_netif_is_ready(void);
#endif

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("tests: %s failed\n", name);
        tests_failed++;
    }
}

static int dummy_blk_read(struct blkdev *dev, uint64_t lba, void *buf, size_t count) {
    (void)dev;
    (void)lba;
    if (buf && count && dev)
        memset(buf, 0, count * dev->sector_size);
    return 0;
}

static int dummy_blk_write(struct blkdev *dev, uint64_t lba, const void *buf, size_t count) {
    (void)dev;
    (void)lba;
    (void)buf;
    (void)count;
    return 0;
}

struct partition_test_image {
    uint8_t sectors[4][512];
    uint64_t last_lba;
    size_t last_count;
};

static void write_le32(uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v & 0xff);
    dst[1] = (uint8_t)((v >> 8) & 0xff);
    dst[2] = (uint8_t)((v >> 16) & 0xff);
    dst[3] = (uint8_t)((v >> 24) & 0xff);
}

static void write_le64(uint8_t *dst, uint64_t v) {
    write_le32(dst, (uint32_t)(v & 0xffffffffULL));
    write_le32(dst + 4, (uint32_t)((v >> 32) & 0xffffffffULL));
}

static int partition_img_read(struct blkdev *dev, uint64_t lba, void *buf, size_t count) {
    if (!dev || !buf || !count || !dev->private)
        return -EINVAL;

    struct partition_test_image *img = dev->private;
    memset(buf, 0, count * dev->sector_size);
    for (size_t i = 0; i < count; i++) {
        uint64_t cur_lba = lba + i;
        if (cur_lba < ARRAY_SIZE(img->sectors)) {
            memcpy((uint8_t *)buf + i * dev->sector_size, img->sectors[cur_lba],
                   dev->sector_size);
        }
    }
    img->last_lba = lba;
    img->last_count = count;
    return 0;
}

static int partition_img_write(struct blkdev *dev, uint64_t lba, const void *buf,
                               size_t count) {
    (void)dev;
    (void)lba;
    (void)buf;
    (void)count;
    return 0;
}

static int dummy_net_xmit(struct netdev *dev, const void *data, size_t len) {
    (void)dev;
    (void)data;
    (void)len;
    return 0;
}

static void test_ringbuf(void) {
    struct ringbuf rb;
    char storage[4];
    ringbuf_init(&rb, storage, sizeof(storage));

    test_check(ringbuf_len(&rb) == 0, "ringbuf init len");
    test_check(ringbuf_push(&rb, 'a', false), "ringbuf push a");
    test_check(ringbuf_push(&rb, 'b', false), "ringbuf push b");
    test_check(ringbuf_push(&rb, 'c', false), "ringbuf push c");
    test_check(ringbuf_len(&rb) == 3, "ringbuf len after push");
    test_check(!ringbuf_push(&rb, 'd', false), "ringbuf push full no overwrite");
    test_check(ringbuf_push(&rb, 'd', true), "ringbuf push full overwrite");

    char out = 0;
    test_check(ringbuf_pop(&rb, &out) && out == 'b', "ringbuf pop b");
    test_check(ringbuf_pop(&rb, &out) && out == 'c', "ringbuf pop c");
    test_check(ringbuf_pop(&rb, &out) && out == 'd', "ringbuf pop d");
    test_check(!ringbuf_pop(&rb, &out), "ringbuf pop empty");
}

static void test_virtqueue(void) {
    struct virtio_device vdev = {0};
    struct virtqueue *vq = virtqueue_alloc(&vdev, 0, 8);
    test_check(vq != NULL, "virtqueue alloc");
    if (!vq)
        return;

    struct virtq_desc desc;
    memset(&desc, 0, sizeof(desc));
    desc.addr = 0x1000;
    desc.len = 128;
    desc.flags = 0;

    uint16_t free_before = vq->free_count;
    int ret = virtqueue_add_buf(vq, &desc, 1, (void *)0xdeadbeef);
    test_check(ret == 0, "virtqueue add buf");
    test_check(vq->free_count == (uint16_t)(free_before - 1), "virtqueue free count dec");

    vq->used->ring[0].id = 0;
    vq->used->ring[0].len = 128;
    vq->used->idx = 1;

    uint32_t len = 0;
    void *cookie = virtqueue_get_buf(vq, &len);
    test_check(cookie == (void *)0xdeadbeef, "virtqueue cookie");
    test_check(len == 128, "virtqueue len");
    test_check(vq->free_count == free_before, "virtqueue free count restore");

    virtqueue_free(vq);
}

static void test_blkdev_registry(void) {
    struct blkdev_ops ops = {
        .read = dummy_blk_read,
        .write = dummy_blk_write,
    };
    struct blkdev dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, "testblk0", sizeof(dev.name) - 1);
    dev.sector_count = 16;
    dev.sector_size = 512;
    dev.ops = &ops;

    int ret = blkdev_register(&dev);
    test_check(ret == 0, "blkdev register");
    ret = blkdev_register(&dev);
    test_check(ret == -EEXIST, "blkdev duplicate");

    blkdev_unregister(&dev);
}

static void test_blkdev_partition_children(void) {
    struct partition_test_image img;
    memset(&img, 0, sizeof(img));
    img.last_lba = UINT64_MAX;

    /* MBR signature */
    img.sectors[0][510] = 0x55;
    img.sectors[0][511] = 0xAA;
    /* First entry: Linux partition, lba=2048, sectors=1024 */
    uint8_t *entry = &img.sectors[0][446];
    entry[4] = 0x83;
    write_le32(entry + 8, 2048U);
    write_le32(entry + 12, 1024U);

    struct blkdev_ops ops = {
        .read = partition_img_read,
        .write = partition_img_write,
    };
    struct blkdev dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, "testblk1", sizeof(dev.name) - 1);
    dev.sector_count = 32768;
    dev.sector_size = 512;
    dev.ops = &ops;
    dev.private = &img;

    int ret = blkdev_register(&dev);
    test_check(ret == 0, "blkdev partition parent register");
    if (ret < 0)
        return;

    struct blkdev *part = blkdev_get("testblk1p1");
    test_check(part != NULL, "blkdev partition child discovered");
    if (part) {
        test_check(part->parent == &dev, "blkdev partition child parent link");
        test_check(part->start_lba == 2048ULL, "blkdev partition child start lba");
        test_check(part->sector_count == 1024ULL, "blkdev partition child sectors");

        uint8_t buf[512];
        memset(buf, 0, sizeof(buf));
        img.last_lba = UINT64_MAX;
        ret = blkdev_read(part, 0, buf, 1);
        test_check(ret == 0, "blkdev partition child read");
        test_check(img.last_lba == 2048ULL, "blkdev partition child lba translate");

        blkdev_put(part);
    }

    blkdev_unregister(&dev);
    part = blkdev_get("testblk1p1");
    test_check(part == NULL, "blkdev partition child removed on parent unregister");
    if (part)
        blkdev_put(part);
}

static void test_blkdev_gpt_partition_bounds(void) {
    struct partition_test_image img;
    memset(&img, 0, sizeof(img));
    img.last_lba = UINT64_MAX;

    /* Protective MBR */
    img.sectors[0][510] = 0x55;
    img.sectors[0][511] = 0xAA;
    uint8_t *mbr_entry = &img.sectors[0][446];
    mbr_entry[4] = 0xEE;
    write_le32(mbr_entry + 8, 1U);
    write_le32(mbr_entry + 12, 65535U);

    /* GPT header at LBA1 */
    memcpy(img.sectors[1], "EFI PART", 8);
    write_le64(&img.sectors[1][72], 2ULL);  /* partition entries start LBA */
    write_le32(&img.sectors[1][80], 2U);    /* entries count */
    write_le32(&img.sectors[1][84], 128U);  /* entry size */

    /* GPT entry 1: valid partition [4096,8191] */
    uint8_t *gpt1 = &img.sectors[2][0];
    gpt1[0] = 1; /* non-zero type GUID */
    write_le64(gpt1 + 32, 4096ULL);
    write_le64(gpt1 + 40, 8191ULL);

    /* GPT entry 2: out-of-bounds partition, should be ignored */
    uint8_t *gpt2 = &img.sectors[2][128];
    gpt2[0] = 2; /* non-zero type GUID */
    write_le64(gpt2 + 32, 70000ULL);
    write_le64(gpt2 + 40, 70010ULL);

    struct blkdev_ops ops = {
        .read = partition_img_read,
        .write = partition_img_write,
    };
    struct blkdev dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, "testgpt0", sizeof(dev.name) - 1);
    dev.sector_count = 65536;
    dev.sector_size = 512;
    dev.ops = &ops;
    dev.private = &img;

    int ret = blkdev_register(&dev);
    test_check(ret == 0, "blkdev gpt parent register");
    if (ret < 0)
        return;

    struct blkdev *part1 = blkdev_get("testgpt0p1");
    test_check(part1 != NULL, "blkdev gpt valid child discovered");
    if (part1) {
        test_check(part1->parent == &dev, "blkdev gpt child parent link");
        test_check(part1->start_lba == 4096ULL, "blkdev gpt child start lba");
        test_check(part1->sector_count == 4096ULL, "blkdev gpt child sectors");

        uint8_t buf[512];
        memset(buf, 0, sizeof(buf));
        img.last_lba = UINT64_MAX;
        ret = blkdev_read(part1, 0, buf, 1);
        test_check(ret == 0, "blkdev gpt child read");
        test_check(img.last_lba == 4096ULL, "blkdev gpt child lba translate");
        blkdev_put(part1);
    }

    struct blkdev *part2 = blkdev_get("testgpt0p2");
    test_check(part2 == NULL, "blkdev gpt out-of-bounds child ignored");
    if (part2)
        blkdev_put(part2);

    blkdev_unregister(&dev);
    part1 = blkdev_get("testgpt0p1");
    test_check(part1 == NULL, "blkdev gpt child removed on parent unregister");
    if (part1)
        blkdev_put(part1);
}

static void test_netdev_registry(void) {
    struct netdev_ops ops = {
        .xmit = dummy_net_xmit,
    };
    struct netdev dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, "testnet0", sizeof(dev.name) - 1);
    dev.ops = &ops;

    int ret = netdev_register(&dev);
    test_check(ret == 0, "netdev register");
    ret = netdev_register(&dev);
    test_check(ret == -EEXIST, "netdev duplicate");

    netdev_unregister(&dev);
}

static void test_dma_coherent_alloc_free(void) {
    dma_addr_t dma = 0;
    size_t sz = CONFIG_PAGE_SIZE + 128;
    uint8_t *buf = dma_alloc_coherent(sz, &dma);
    test_check(buf != NULL, "dma coherent alloc");
    if (!buf)
        return;

    test_check(dma == (dma_addr_t)virt_to_phys(buf), "dma coherent addr mapping");
    test_check(buf[0] == 0 && buf[sz - 1] == 0, "dma coherent zeroed");
    dma_free_coherent(buf, sz);
}

static volatile uint32_t irq_deferred_hits;

static void test_irq_deferred_handler(void *arg,
                                      const struct trap_core_event *ev __unused) {
    uint32_t *last = arg;
    __atomic_add_fetch(&irq_deferred_hits, 1, __ATOMIC_RELAXED);
    if (last)
        __atomic_store_n(last, __atomic_load_n(&irq_deferred_hits, __ATOMIC_RELAXED),
                         __ATOMIC_RELAXED);
}

static void test_irq_deferred_dispatch(void) {
    const int irq = 900;
    static uint32_t last_seen;
    irq_deferred_hits = 0;
    last_seen = 0;

    arch_irq_register_ex(irq, test_irq_deferred_handler, &last_seen,
                         IRQ_FLAG_SHARED | IRQ_FLAG_DEFERRED |
                             IRQ_FLAG_NO_AUTO_ENABLE);
    arch_irq_enable_nr(irq);
    platform_irq_dispatch_nr((uint32_t)irq);

    for (int i = 0; i < 200; i++) {
        if (__atomic_load_n(&irq_deferred_hits, __ATOMIC_RELAXED) > 0)
            break;
        proc_yield();
    }
    test_check(__atomic_load_n(&irq_deferred_hits, __ATOMIC_RELAXED) > 0,
               "irq deferred dispatch");
    test_check(last_seen > 0, "irq deferred handler ran");
    arch_irq_disable_nr(irq);
}

static volatile uint32_t irq_shared_hits_a;
static volatile uint32_t irq_shared_hits_b;
static volatile uint32_t irq_gate_hits;
static volatile uint32_t irq_mock_dispatch_hits;

struct irq_mock_state {
    uint32_t enable_hits;
    uint32_t disable_hits;
    uint32_t set_type_hits;
    uint32_t set_affinity_hits;
    int last_enable_irq;
    int last_disable_irq;
    int last_type_irq;
    int last_affinity_irq;
    uint32_t last_type;
    uint32_t last_affinity_mask;
};

static struct irq_mock_state irq_mock_state;

static void test_irq_shared_handler_a(void *arg __unused,
                                      const struct trap_core_event *ev __unused) {
    __atomic_add_fetch(&irq_shared_hits_a, 1, __ATOMIC_RELAXED);
}

static void test_irq_shared_handler_b(void *arg __unused,
                                      const struct trap_core_event *ev __unused) {
    __atomic_add_fetch(&irq_shared_hits_b, 1, __ATOMIC_RELAXED);
}

static void test_irq_gate_handler(void *arg __unused,
                                  const struct trap_core_event *ev __unused) {
    __atomic_add_fetch(&irq_gate_hits, 1, __ATOMIC_RELAXED);
}

static void test_irq_mock_handler(void *arg __unused,
                                  const struct trap_core_event *ev __unused) {
    __atomic_add_fetch(&irq_mock_dispatch_hits, 1, __ATOMIC_RELAXED);
}

static void test_irq_shared_actions(void) {
    const int irq = 901;
    irq_shared_hits_a = 0;
    irq_shared_hits_b = 0;

    arch_irq_register_ex(irq, test_irq_shared_handler_a, NULL,
                         IRQ_FLAG_SHARED | IRQ_FLAG_TRIGGER_LEVEL |
                             IRQ_FLAG_NO_AUTO_ENABLE | IRQ_FLAG_NO_CHIP);
    arch_irq_register_ex(irq, test_irq_shared_handler_b, NULL,
                         IRQ_FLAG_SHARED | IRQ_FLAG_TRIGGER_LEVEL |
                             IRQ_FLAG_NO_AUTO_ENABLE | IRQ_FLAG_NO_CHIP);

    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_shared_hits_a, __ATOMIC_RELAXED) == 0,
               "irq shared disabled gate a");
    test_check(__atomic_load_n(&irq_shared_hits_b, __ATOMIC_RELAXED) == 0,
               "irq shared disabled gate b");

    arch_irq_enable_nr(irq);
    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_shared_hits_a, __ATOMIC_RELAXED) == 1,
               "irq shared handler a");
    test_check(__atomic_load_n(&irq_shared_hits_b, __ATOMIC_RELAXED) == 1,
               "irq shared handler b");
    arch_irq_disable_nr(irq);
}

static void test_irq_enable_disable_gate(void) {
    const int irq = 902;
    irq_gate_hits = 0;

    arch_irq_register_ex(irq, test_irq_gate_handler, NULL,
                         IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_AUTO_ENABLE |
                             IRQ_FLAG_NO_CHIP);

    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_gate_hits, __ATOMIC_RELAXED) == 0,
               "irq gate disabled no dispatch");

    arch_irq_enable_nr(irq);
    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_gate_hits, __ATOMIC_RELAXED) == 1,
               "irq gate enabled dispatch");

    arch_irq_disable_nr(irq);
    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_gate_hits, __ATOMIC_RELAXED) == 1,
               "irq gate disabled stops dispatch");
}

static void irq_mock_enable(int irq) {
    irq_mock_state.enable_hits++;
    irq_mock_state.last_enable_irq = irq;
}

static void irq_mock_disable(int irq) {
    irq_mock_state.disable_hits++;
    irq_mock_state.last_disable_irq = irq;
}

static int irq_mock_set_type(int irq, uint32_t type) {
    irq_mock_state.set_type_hits++;
    irq_mock_state.last_type_irq = irq;
    irq_mock_state.last_type = type;
    return 0;
}

static int irq_mock_set_affinity(int irq, uint32_t cpu_mask) {
    irq_mock_state.set_affinity_hits++;
    irq_mock_state.last_affinity_irq = irq;
    irq_mock_state.last_affinity_mask = cpu_mask;
    return 0;
}

static const struct irqchip_ops test_irq_mock_ops = {
    .enable = irq_mock_enable,
    .disable = irq_mock_disable,
    .set_type = irq_mock_set_type,
    .set_affinity = irq_mock_set_affinity,
};

static void test_irq_domain_programming(void) {
    memset(&irq_mock_state, 0, sizeof(irq_mock_state));
    irq_mock_state.last_enable_irq = -1;
    irq_mock_state.last_disable_irq = -1;
    irq_mock_state.last_type_irq = -1;
    irq_mock_state.last_affinity_irq = -1;
    irq_mock_dispatch_hits = 0;

    const uint32_t fwnode = 0xD00D0010U;
    uint32_t virq_base = 0;
    int ret = platform_irq_domain_alloc_linear_fwnode("test-mock-domain",
                                                      &test_irq_mock_ops,
                                                      fwnode, 32, 8,
                                                      &virq_base);
    test_check(ret == 0, "irq domain auto alloc");
    if (ret < 0)
        return;

    int virq = (int)(virq_base + 1);
    int mapped = platform_irq_domain_map(&test_irq_mock_ops, 33);
    test_check(mapped == virq, "irq domain hwirq map");
    int mapped_fwnode = platform_irq_domain_map_fwnode(fwnode, 33);
    test_check(mapped_fwnode == virq, "irq domain fwnode map");

    arch_irq_register_ex(virq, test_irq_mock_handler, NULL,
                         IRQ_FLAG_TRIGGER_EDGE | IRQ_FLAG_NO_AUTO_ENABLE);
    arch_irq_set_affinity(virq, 0x3);
    arch_irq_enable_nr(virq);

#if CONFIG_MAX_CPUS >= 32
    uint32_t expected_mask = 0x3U;
#else
    uint32_t expected_mask = 0x3U & ((1U << CONFIG_MAX_CPUS) - 1U);
#endif
    if (!expected_mask)
        expected_mask = 1U;

    test_check(irq_mock_state.enable_hits == 1 &&
                   irq_mock_state.last_enable_irq == 33,
               "irq chip enable uses hwirq");
    test_check(irq_mock_state.set_type_hits > 0 &&
                   irq_mock_state.last_type_irq == 33 &&
                   irq_mock_state.last_type == IRQ_FLAG_TRIGGER_EDGE,
               "irq chip set_type uses hwirq");
    test_check(irq_mock_state.set_affinity_hits > 0 &&
                   irq_mock_state.last_affinity_irq == 33 &&
                   irq_mock_state.last_affinity_mask == expected_mask,
               "irq chip set_affinity uses hwirq");

    platform_irq_dispatch_fwnode_hwirq(fwnode, 33, NULL);
    test_check(__atomic_load_n(&irq_mock_dispatch_hits, __ATOMIC_RELAXED) == 1,
               "irq domain dispatch fwnode hwirq");

    arch_irq_disable_nr(virq);
    test_check(irq_mock_state.disable_hits == 1 &&
                   irq_mock_state.last_disable_irq == 33,
               "irq chip disable uses hwirq");
}

#if CONFIG_KERNEL_TESTS
static void test_virtio_net_rx_to_lwip_bridge(void) {
    if (!lwip_netif_is_ready()) {
        pr_info("tests: skip virtio_net rx bridge (lwip netif not ready)\n");
        return;
    }

    lwip_netif_test_reset_rx_stats();
    uint64_t before = lwip_netif_test_rx_input_count_get();

    int ret = virtio_net_test_rx_deliver_len(10U + 64U);
    test_check(ret == 0, "virtio_net rx bridge deliver");
    uint64_t after = lwip_netif_test_rx_input_count_get();
    test_check(after == before + 1, "virtio_net rx bridge count inc");
    test_check(lwip_netif_test_rx_input_last_len_get() == 64U,
               "virtio_net rx bridge payload len");

    ret = virtio_net_test_rx_deliver_len(10U);
    test_check(ret == 0, "virtio_net rx bridge header only");
    test_check(lwip_netif_test_rx_input_count_get() == after,
               "virtio_net rx bridge header skipped");
}
#endif

static void test_vfs_umount_busy_with_child_mount(void) {
    struct stat st;
    int ret = vfs_stat("/tmp", &st);
    if (ret < 0 || !S_ISDIR(st.st_mode)) {
        pr_warn("tests: skip vfs umount busy test (/tmp unavailable)\n");
        return;
    }

    const char *mntpt = "/tmp/.kairos_umount_busy";
    ret = vfs_mkdir(mntpt, 0755);
    if (ret < 0 && ret != -EEXIST) {
        pr_warn("tests: skip vfs umount busy test (mkdir ret=%d)\n", ret);
        return;
    }

    ret = vfs_mount(NULL, mntpt, "tmpfs", 0);
    if (ret < 0) {
        pr_warn("tests: skip vfs umount busy test (mount ret=%d)\n", ret);
        return;
    }

    ret = vfs_umount("/tmp");
    test_check(ret == -EBUSY, "vfs umount busy on parent with child mount");

    ret = vfs_umount(mntpt);
    test_check(ret == 0, "vfs umount child mount cleanup");
}

int run_driver_tests(void) {
    tests_failed = 0;
    pr_info("\n=== Driver Tests ===\n");

    test_ringbuf();
    test_virtqueue();
    test_blkdev_registry();
    test_blkdev_partition_children();
    test_blkdev_gpt_partition_bounds();
    test_netdev_registry();
    test_dma_coherent_alloc_free();
    test_irq_deferred_dispatch();
    test_irq_shared_actions();
    test_irq_enable_disable_gate();
    test_irq_domain_programming();
#if CONFIG_KERNEL_TESTS
    test_virtio_net_rx_to_lwip_bridge();
#endif
    test_vfs_umount_busy_with_child_mount();

    if (tests_failed == 0)
        pr_info("driver tests: all passed\n");
    else
        pr_err("driver tests: %d failures\n", tests_failed);
    return tests_failed;
}
