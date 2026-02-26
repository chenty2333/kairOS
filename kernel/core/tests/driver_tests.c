/**
 * kernel/core/tests/driver_tests.c - Driver and helper tests
 */

#include <kairos/arch.h>
#include <kairos/blkdev.h>
#include <kairos/config.h>
#include <kairos/dma.h>
#include <kairos/iommu.h>
#include <kairos/net.h>
#include <kairos/platform.h>
#include <kairos/platform_irq.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/ringbuf.h>
#include <kairos/sched.h>
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

static int test_reap_children_bounded(int expected, const char *tag) {
    int reaped = 0;
    int status = 0;
    uint64_t start = arch_timer_ticks();
    uint64_t timeout_ticks =
        arch_timer_ns_to_ticks(10ULL * 1000 * 1000 * 1000);

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
    if (reaped < expected)
        pr_warn("tests: %s reap timeout (%d/%d)\n", tag, reaped, expected);
    return reaped;
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
    uint8_t *buf = dma_alloc_coherent(NULL, sz, &dma);
    test_check(buf != NULL, "dma coherent alloc");
    if (!buf)
        return;

    test_check(dma == (dma_addr_t)virt_to_phys(buf), "dma coherent addr mapping");
    test_check(buf[0] == 0 && buf[sz - 1] == 0, "dma coherent zeroed");
    dma_free_coherent(NULL, buf, sz, dma);
}

static void test_dma_constraints_direct_backend(void) {
    struct device dev;
    memset(&dev, 0, sizeof(dev));

    uint8_t buf[128];
    dma_addr_t phys = (dma_addr_t)virt_to_phys(buf);

    dma_addr_t dma = dma_map_single(&dev, buf, sizeof(buf), DMA_TO_DEVICE);
    test_check(dma != 0, "dma direct unconstrained map");
    if (dma)
        dma_unmap_single(&dev, dma, sizeof(buf), DMA_TO_DEVICE);

    dma_set_mask(&dev, 0xFFFULL);
    dma = dma_map_single(&dev, buf, sizeof(buf), DMA_TO_DEVICE);
    test_check(dma == 0, "dma direct mask reject");

    dma_set_mask(&dev, DMA_MASK_FULL);
    int ret = dma_set_aperture(&dev, phys + CONFIG_PAGE_SIZE,
                               phys + CONFIG_PAGE_SIZE * 2 - 1);
    test_check(ret == 0, "dma direct aperture set");
    dma = dma_map_single(&dev, buf, sizeof(buf), DMA_TO_DEVICE);
    test_check(dma == 0, "dma direct aperture reject");

    ret = dma_set_aperture(&dev, phys, phys + CONFIG_PAGE_SIZE - 1);
    test_check(ret == 0, "dma direct aperture set allow");
    dma = dma_map_single(&dev, buf, sizeof(buf), DMA_TO_DEVICE);
    test_check(dma != 0, "dma direct aperture allow");
    if (dma)
        dma_unmap_single(&dev, dma, sizeof(buf), DMA_TO_DEVICE);
    dma_clear_aperture(&dev);
}

static void test_iommu_domain_dma_ops(void) {
    struct iommu_domain *domain = iommu_domain_create(IOMMU_DOMAIN_DMA, 0, 0);
    test_check(domain != NULL, "iommu domain create");
    if (!domain)
        return;

    struct device dev;
    memset(&dev, 0, sizeof(dev));
    int ret = iommu_attach_device(domain, &dev);
    test_check(ret == 0, "iommu attach device");
    if (ret < 0) {
        iommu_domain_destroy(domain);
        return;
    }

    uint8_t *buf = kmalloc(CONFIG_PAGE_SIZE + 96);
    test_check(buf != NULL, "iommu dma map alloc");
    if (buf) {
        dma_addr_t mapped = dma_map_single(&dev, buf + 32, 128, DMA_TO_DEVICE);
        test_check(mapped != 0, "iommu dma map single");
        if (mapped) {
            dma_addr_t phys = (dma_addr_t)virt_to_phys(buf + 32);
            test_check(mapped != phys, "iommu dma map translated iova");
            dma_unmap_single(&dev, mapped, 128, DMA_TO_DEVICE);
        }
        kfree(buf);
    }

    dma_addr_t coh_dma = 0;
    void *coh = dma_alloc_coherent(&dev, CONFIG_PAGE_SIZE + 64, &coh_dma);
    test_check(coh != NULL, "iommu dma coherent alloc");
    if (coh) {
        dma_addr_t coh_phys = (dma_addr_t)virt_to_phys(coh);
        test_check(coh_dma != 0 && coh_dma != coh_phys,
                   "iommu dma coherent translated handle");
        dma_free_coherent(&dev, coh, CONFIG_PAGE_SIZE + 64, coh_dma);
    }

    iommu_detach_device(&dev);
    iommu_domain_destroy(domain);
}

static void test_dma_constraints_iommu_backend(void) {
    struct iommu_domain *domain =
        iommu_domain_create(IOMMU_DOMAIN_DMA, 0x10000ULL, 0x30000ULL);
    test_check(domain != NULL, "dma iommu constraints domain create");
    if (!domain)
        return;

    struct device dev;
    memset(&dev, 0, sizeof(dev));
    int ret = iommu_attach_device(domain, &dev);
    test_check(ret == 0, "dma iommu constraints attach");
    if (ret < 0) {
        iommu_domain_destroy(domain);
        return;
    }

    void *aligned = kmalloc_aligned(256, CONFIG_PAGE_SIZE);
    test_check(aligned != NULL, "dma iommu constraints aligned alloc");
    if (aligned) {
        dma_set_mask(&dev, 0xFFFFULL);
        dma_addr_t dma =
            dma_map_single(&dev, aligned, 128, DMA_TO_DEVICE);
        test_check(dma == 0, "dma iommu constraints mask reject");

        dma_set_mask(&dev, DMA_MASK_FULL);
        ret = dma_set_aperture(&dev, 0x18000ULL, 0x18FFFULL);
        test_check(ret == 0, "dma iommu constraints aperture set");
        dma = dma_map_single(&dev, aligned, 128, DMA_TO_DEVICE);
        test_check(dma != 0, "dma iommu constraints aperture allow");
        if (dma) {
            test_check(dma >= 0x18000ULL && dma < 0x19000ULL,
                       "dma iommu constraints aperture range");
            dma_unmap_single(&dev, dma, 128, DMA_TO_DEVICE);
        }

        dma_clear_aperture(&dev);
        kfree_aligned(aligned);
    }

    iommu_detach_device(&dev);
    iommu_domain_destroy(domain);
}

static void test_iommu_default_domain_attach(void) {
    struct device dev;
    memset(&dev, 0, sizeof(dev));
    int ret = iommu_attach_default_domain(&dev);
    test_check(ret == 0, "iommu default attach");
    if (ret < 0)
        return;

    test_check(iommu_get_domain(&dev) == iommu_get_passthrough_domain(),
               "iommu default passthrough domain");

    uint8_t buf[128];
    dma_addr_t dma = dma_map_single(&dev, buf, sizeof(buf), DMA_TO_DEVICE);
    dma_addr_t phys = (dma_addr_t)virt_to_phys(buf);
    test_check(dma == phys, "iommu default passthrough dma");
    dma_unmap_single(&dev, dma, sizeof(buf), DMA_TO_DEVICE);

    iommu_detach_device(&dev);
}

static struct iommu_domain *test_iommu_hw_alloc_default(struct device *dev __unused,
                                                        bool *owned, void *priv __unused) {
    if (owned)
        *owned = true;
    return iommu_domain_create(IOMMU_DOMAIN_DMA, 0, 0);
}

static const struct iommu_hw_ops test_iommu_hw_ops = {
    .alloc_default_domain = test_iommu_hw_alloc_default,
};

static void test_iommu_hw_ops_default_attach(void) {
    iommu_unregister_hw_ops(&test_iommu_hw_ops);
    int ret = iommu_register_hw_ops(&test_iommu_hw_ops, NULL);
    test_check(ret == 0, "iommu hw ops register");
    if (ret < 0)
        return;

    ret = iommu_register_hw_ops(&test_iommu_hw_ops, NULL);
    test_check(ret == -EBUSY, "iommu hw ops register busy");

    struct device dev;
    memset(&dev, 0, sizeof(dev));
    ret = iommu_attach_default_domain(&dev);
    test_check(ret == 0, "iommu hw ops default attach");
    if (ret == 0) {
        struct iommu_domain *domain = iommu_get_domain(&dev);
        test_check(domain != NULL && domain->type == IOMMU_DOMAIN_DMA,
                   "iommu hw ops dma domain");
        test_check(dev.iommu_domain_owned, "iommu hw ops domain ownership");

        uint8_t buf[128];
        dma_addr_t dma = dma_map_single(&dev, buf, sizeof(buf), DMA_TO_DEVICE);
        dma_addr_t phys = (dma_addr_t)virt_to_phys(buf);
        test_check(dma != 0 && dma != phys, "iommu hw ops translated dma");
        dma_unmap_single(&dev, dma, sizeof(buf), DMA_TO_DEVICE);
        iommu_detach_device(&dev);
        test_check(iommu_get_domain(&dev) == NULL,
                   "iommu hw ops detach clears domain");
    }

    iommu_unregister_hw_ops(&test_iommu_hw_ops);
}

static volatile uint32_t iommu_replace_map_calls;
static volatile uint32_t iommu_replace_unmap_calls;

static int test_iommu_replace_map(struct iommu_domain *domain __unused,
                                  dma_addr_t iova __unused, paddr_t paddr __unused,
                                  size_t size __unused, uint32_t prot __unused) {
    __atomic_add_fetch(&iommu_replace_map_calls, 1, __ATOMIC_RELAXED);
    return 0;
}

static void test_iommu_replace_unmap(struct iommu_domain *domain __unused,
                                     dma_addr_t iova __unused,
                                     size_t size __unused) {
    __atomic_add_fetch(&iommu_replace_unmap_calls, 1, __ATOMIC_RELAXED);
}

static const struct iommu_domain_ops test_iommu_replace_domain_ops = {
    .map = test_iommu_replace_map,
    .unmap = test_iommu_replace_unmap,
};

static struct iommu_domain *test_iommu_replace_alloc_default(struct device *dev __unused,
                                                             bool *owned, void *priv __unused) {
    struct iommu_domain *domain = iommu_domain_create(IOMMU_DOMAIN_DMA, 0, 0);
    if (!domain)
        return NULL;
    iommu_domain_set_ops(domain, &test_iommu_replace_domain_ops, NULL);
    if (owned)
        *owned = true;
    return domain;
}

static const struct iommu_hw_ops test_iommu_replace_hw_ops = {
    .alloc_default_domain = test_iommu_replace_alloc_default,
};

static void test_iommu_attach_replaces_owned_domain(void) {
    iommu_unregister_hw_ops(&test_iommu_replace_hw_ops);
    int ret = iommu_register_hw_ops(&test_iommu_replace_hw_ops, NULL);
    test_check(ret == 0, "iommu replace register hw ops");
    if (ret < 0)
        return;

    iommu_replace_map_calls = 0;
    iommu_replace_unmap_calls = 0;

    struct device dev;
    memset(&dev, 0, sizeof(dev));
    ret = iommu_attach_default_domain(&dev);
    test_check(ret == 0, "iommu replace default attach");
    if (ret == 0) {
        uint8_t buf[256];
        dma_addr_t dma = dma_map_single(&dev, buf, sizeof(buf), DMA_FROM_DEVICE);
        test_check(dma != 0, "iommu replace map before reattach");
        test_check(__atomic_load_n(&iommu_replace_map_calls, __ATOMIC_RELAXED) == 1,
                   "iommu replace map callback");

        ret = iommu_attach_device(iommu_get_passthrough_domain(), &dev);
        test_check(ret == 0, "iommu replace attach passthrough");
        test_check(iommu_get_domain(&dev) == iommu_get_passthrough_domain(),
                   "iommu replace domain switched");
        test_check(__atomic_load_n(&iommu_replace_unmap_calls, __ATOMIC_RELAXED) == 1,
                   "iommu replace old mapping unmapped");
    }

    iommu_detach_device(&dev);
    iommu_unregister_hw_ops(&test_iommu_replace_hw_ops);
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
    int ret = platform_irq_unregister_ex(irq, test_irq_deferred_handler, &last_seen);
    test_check(ret == 0, "irq deferred unregister");
}

static volatile uint32_t irq_shared_hits_a;
static volatile uint32_t irq_shared_hits_b;
static volatile uint32_t irq_gate_hits;
static volatile uint32_t irq_mock_dispatch_hits;
static volatile uint32_t irq_cascade_hits;
static volatile uint32_t irq_request_hits;
static volatile uint32_t irq_concurrent_hits;
static volatile uint32_t irq_blocking_entered;
static volatile uint32_t irq_blocking_release;
static volatile uint32_t irq_blocking_hits;
static volatile uint32_t irq_platform_helper_hits;

struct irq_concurrency_ctx {
    int irq;
    int loops;
    volatile uint32_t dispatch_calls;
};

struct irq_free_sync_ctx {
    int irq;
    volatile uint32_t done;
    int ret;
};

struct irq_free_cookie_sync_ctx {
    uint64_t cookie;
    volatile uint32_t done;
    int ret;
};

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
static struct irq_mock_state irq_parent_mock_state;
static struct irq_mock_state irq_child_mock_state;
static const struct irqchip_ops test_irq_mock_ops;

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

static void test_irq_cascade_handler(void *arg __unused,
                                     const struct trap_core_event *ev __unused) {
    __atomic_add_fetch(&irq_cascade_hits, 1, __ATOMIC_RELAXED);
}

static void test_irq_request_handler(void *arg __unused,
                                     const struct trap_core_event *ev __unused) {
    __atomic_add_fetch(&irq_request_hits, 1, __ATOMIC_RELAXED);
}

static void test_irq_concurrent_handler(void *arg __unused,
                                        const struct trap_core_event *ev __unused) {
    __atomic_add_fetch(&irq_concurrent_hits, 1, __ATOMIC_RELAXED);
    proc_yield();
}

static void test_irq_blocking_handler(void *arg __unused,
                                      const struct trap_core_event *ev __unused) {
    __atomic_add_fetch(&irq_blocking_hits, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&irq_blocking_entered, 1, __ATOMIC_RELAXED);
    while (!__atomic_load_n(&irq_blocking_release, __ATOMIC_RELAXED))
        proc_yield();
}

static void test_irq_platform_helper_handler(void *arg __unused) {
    __atomic_add_fetch(&irq_platform_helper_hits, 1, __ATOMIC_RELAXED);
}

static int irq_dispatch_storm_thread(void *arg) {
    struct irq_concurrency_ctx *ctx = arg;
    if (!ctx)
        return -EINVAL;
    for (int i = 0; i < ctx->loops; i++) {
        platform_irq_dispatch_nr((uint32_t)ctx->irq);
        __atomic_add_fetch(&ctx->dispatch_calls, 1, __ATOMIC_RELAXED);
        proc_yield();
    }
    return 0;
}

static int irq_dispatch_once_thread(void *arg) {
    const int *irq = arg;
    if (!irq)
        return -EINVAL;
    platform_irq_dispatch_nr((uint32_t)*irq);
    return 0;
}

static int irq_free_sync_thread(void *arg) {
    struct irq_free_sync_ctx *ctx = arg;
    if (!ctx)
        return -EINVAL;
    ctx->ret = arch_free_irq_ex_sync(ctx->irq, test_irq_blocking_handler, NULL);
    __atomic_store_n(&ctx->done, 1, __ATOMIC_RELAXED);
    return 0;
}

static int irq_free_cookie_sync_thread(void *arg) {
    struct irq_free_cookie_sync_ctx *ctx = arg;
    if (!ctx)
        return -EINVAL;
    ctx->ret = arch_free_irq_cookie_sync(ctx->cookie);
    __atomic_store_n(&ctx->done, 1, __ATOMIC_RELAXED);
    return 0;
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
    int ret = platform_irq_unregister_ex(irq, test_irq_shared_handler_a, NULL);
    test_check(ret == 0, "irq shared unregister a");
    ret = platform_irq_unregister_ex(irq, test_irq_shared_handler_b, NULL);
    test_check(ret == 0, "irq shared unregister b");
}

static void test_irq_unregister_actions(void) {
    const int irq = 903;
    irq_shared_hits_a = 0;
    irq_shared_hits_b = 0;

    arch_irq_register_ex(irq, test_irq_shared_handler_a, NULL,
                         IRQ_FLAG_SHARED | IRQ_FLAG_TRIGGER_LEVEL |
                             IRQ_FLAG_NO_AUTO_ENABLE | IRQ_FLAG_NO_CHIP);
    arch_irq_register_ex(irq, test_irq_shared_handler_b, NULL,
                         IRQ_FLAG_SHARED | IRQ_FLAG_TRIGGER_LEVEL |
                             IRQ_FLAG_NO_AUTO_ENABLE | IRQ_FLAG_NO_CHIP);
    arch_irq_enable_nr(irq);

    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_shared_hits_a, __ATOMIC_RELAXED) == 1 &&
                   __atomic_load_n(&irq_shared_hits_b, __ATOMIC_RELAXED) == 1,
               "irq unregister initial dispatch");

    int ret = platform_irq_unregister_ex(irq, test_irq_shared_handler_a, NULL);
    test_check(ret == 0, "irq unregister first handler");
    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_shared_hits_a, __ATOMIC_RELAXED) == 1 &&
                   __atomic_load_n(&irq_shared_hits_b, __ATOMIC_RELAXED) == 2,
               "irq unregister keeps remaining handler");

    ret = platform_irq_unregister_ex(irq, test_irq_shared_handler_a, NULL);
    test_check(ret == 0, "irq unregister idempotent");

    ret = platform_irq_unregister_ex(irq, test_irq_shared_handler_b, NULL);
    test_check(ret == 0, "irq unregister second handler");
    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_shared_hits_b, __ATOMIC_RELAXED) == 2,
               "irq unregister all handlers removed");
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
    int ret = platform_irq_unregister_ex(irq, test_irq_gate_handler, NULL);
    test_check(ret == 0, "irq gate unregister");
}

static void test_irq_request_free_actions(void) {
    const int irq = 904;
    irq_request_hits = 0;
    irq_shared_hits_a = 0;

    int ret = arch_request_irq_ex(
        irq, test_irq_request_handler, NULL,
        IRQ_FLAG_SHARED | IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "irq request first handler");
    ret = arch_request_irq_ex(
        irq, test_irq_shared_handler_a, NULL,
        IRQ_FLAG_SHARED | IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "irq request second handler");

    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_request_hits, __ATOMIC_RELAXED) == 1,
               "irq request auto-enable dispatch");
    test_check(__atomic_load_n(&irq_shared_hits_a, __ATOMIC_RELAXED) > 0,
               "irq request shared peer dispatch");

    ret = arch_free_irq_ex(irq, test_irq_request_handler, NULL);
    test_check(ret == 0, "irq free first handler");
    ret = arch_free_irq_ex(irq, test_irq_request_handler, NULL);
    test_check(ret == 0, "irq free first handler idempotent");
    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_request_hits, __ATOMIC_RELAXED) == 1,
               "irq free removed first handler");

    ret = arch_free_irq_ex(irq, test_irq_shared_handler_a, NULL);
    test_check(ret == 0, "irq free second handler");
    ret = arch_free_irq_ex(irq, test_irq_shared_handler_a, NULL);
    test_check(ret == 0, "irq free second handler idempotent");
    uint32_t hits_before =
        __atomic_load_n(&irq_shared_hits_a, __ATOMIC_RELAXED);
    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_shared_hits_a, __ATOMIC_RELAXED) ==
                   hits_before,
               "irq free disables empty irq");
}

static void test_platform_device_irq_helpers(void) {
    const int irq = 908;
    irq_platform_helper_hits = 0;

    struct resource res = {
        .start = (uint64_t)irq,
        .end = (uint64_t)irq,
        .flags = IORESOURCE_IRQ,
    };
    struct device dev;
    memset(&dev, 0, sizeof(dev));
    dev.bus = &platform_bus_type;
    dev.resources = &res;
    dev.num_resources = 1;

    int got_irq = platform_device_get_irq(&dev, 0);
    test_check(got_irq == irq, "platform irq helper get irq");
    got_irq = platform_device_get_irq(&dev, 1);
    test_check(got_irq == -ENOENT, "platform irq helper get irq invalid index");

    int ret = platform_device_request_irq(
        &dev, 0, test_irq_platform_helper_handler, NULL,
        IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "platform irq helper request");
    if (ret < 0)
        return;

    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_platform_helper_hits, __ATOMIC_RELAXED) == 1,
               "platform irq helper dispatch");

    ret = platform_device_free_irq(&dev, 0, test_irq_platform_helper_handler,
                                   NULL);
    test_check(ret == 0, "platform irq helper free");

    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_platform_helper_hits, __ATOMIC_RELAXED) == 1,
               "platform irq helper free removed");
}

static void test_irq_stats_export(void) {
    const int irq = 906;
    irq_gate_hits = 0;

    int ret = arch_request_irq_ex(irq, test_irq_gate_handler, NULL,
                                  IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "irq stats request");
    platform_irq_dispatch_nr((uint32_t)irq);
    platform_irq_dispatch_nr((uint32_t)irq);

    size_t cap = 128 + (size_t)IRQCHIP_MAX_IRQS * 128;
    char *buf = kmalloc(cap);
    test_check(buf != NULL, "irq stats buffer alloc");
    if (!buf) {
        ret = arch_free_irq_ex(irq, test_irq_gate_handler, NULL);
        test_check(ret == 0, "irq stats free");
        return;
    }

    int n = platform_irq_format_stats(buf, cap, true);
    test_check(n > 0, "irq stats format");
    test_check(strstr(buf, "dispatch") != NULL, "irq stats header");
    test_check(strstr(buf, "in_flight") != NULL, "irq stats in_flight header");
    test_check(strstr(buf, "retired") != NULL, "irq stats retired header");
    test_check(strstr(buf, "last_cpu") != NULL, "irq stats last_cpu header");

    char needle[32];
    snprintf(needle, sizeof(needle), "%3d ", irq);
    test_check(strstr(buf, needle) != NULL, "irq stats contains irq line");
    kfree(buf);

    ret = arch_free_irq_ex(irq, test_irq_gate_handler, NULL);
    test_check(ret == 0, "irq stats free");
}

static void test_irq_stats_snapshot_and_procfs(void) {
    const int irq = 905;
    irq_gate_hits = 0;

    int ret = arch_request_irq_ex(irq, test_irq_gate_handler, NULL,
                                  IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "irq snapshot request");
    if (ret < 0)
        return;

    platform_irq_dispatch_nr((uint32_t)irq);
    platform_irq_dispatch_nr((uint32_t)irq);

    size_t snap_count = platform_irq_snapshot(NULL, 0, true);
    test_check(snap_count > 0, "irq snapshot active count");

    struct irq_stats_entry *snaps = NULL;
    if (snap_count > 0) {
        snaps = kmalloc(snap_count * sizeof(*snaps));
        test_check(snaps != NULL, "irq snapshot alloc");
    }

    if (snaps) {
        memset(snaps, 0, snap_count * sizeof(*snaps));
        size_t filled = platform_irq_snapshot(snaps, snap_count, true);
        test_check(filled == snap_count, "irq snapshot fill count");

        bool found = false;
        for (size_t i = 0; i < filled; i++) {
            if (snaps[i].virq != (uint32_t)irq)
                continue;
            found = true;
            test_check(snaps[i].dispatch_calls >= 2,
                       "irq snapshot dispatch count");
            test_check(snaps[i].enable_calls > 0, "irq snapshot enable count");
            test_check(snaps[i].action_count > 0, "irq snapshot action count");
            break;
        }
        test_check(found, "irq snapshot contains virq");
        kfree(snaps);
    }

    struct file *f = NULL;
    ret = vfs_open("/proc/interrupts", 0, 0, &f);
    test_check(ret == 0 && f != NULL, "irq proc interrupts open");
    if (ret == 0 && f) {
        char buf[4096];
        ssize_t n = vfs_read(f, buf, sizeof(buf) - 1);
        test_check(n > 0, "irq proc interrupts read");
        if (n > 0) {
            buf[n] = '\0';
            test_check(strstr(buf, "dispatch") != NULL,
                       "irq proc interrupts header");
            char needle[32];
            snprintf(needle, sizeof(needle), "%3d ", irq);
            test_check(strstr(buf, needle) != NULL,
                       "irq proc interrupts contains virq");
        }
        vfs_close(f);
    }

    ret = arch_free_irq_ex(irq, test_irq_gate_handler, NULL);
    test_check(ret == 0, "irq snapshot free");
}

static void test_irq_unregister_dispatch_concurrency(void) {
    const int irq = 907;
    irq_concurrent_hits = 0;

    int ret = arch_request_irq_ex(
        irq, test_irq_concurrent_handler, NULL,
        IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_DEFERRED | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "irq concurrent request");
    if (ret < 0)
        return;

    struct irq_concurrency_ctx ctx = {
        .irq = irq,
        .loops = 300,
        .dispatch_calls = 0,
    };
    struct process *worker =
        kthread_create_joinable(irq_dispatch_storm_thread, &ctx, "irqdisp");
    test_check(worker != NULL, "irq concurrent dispatch worker create");
    if (!worker) {
        (void)arch_free_irq_ex(irq, test_irq_concurrent_handler, NULL);
        return;
    }
    sched_enqueue(worker);

    for (int i = 0; i < 100; i++) {
        if (__atomic_load_n(&ctx.dispatch_calls, __ATOMIC_RELAXED) > 10)
            break;
        proc_yield();
    }

    ret = arch_free_irq_ex(irq, test_irq_concurrent_handler, NULL);
    test_check(ret == 0, "irq concurrent free during dispatch");

    int reaped = test_reap_children_bounded(1, "irq_concurrent_dispatch");
    test_check(reaped == 1, "irq concurrent dispatch worker reaped");

    uint32_t hits_before =
        __atomic_load_n(&irq_concurrent_hits, __ATOMIC_RELAXED);
    for (int i = 0; i < 8; i++)
        platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_concurrent_hits, __ATOMIC_RELAXED) ==
                   hits_before,
               "irq concurrent no hits after free");
}

static void test_irq_domain_remove_waits_reclaim(void) {
    const uint32_t hwirq = 960;
    uint32_t virq_base = 0;

    int ret = platform_irq_domain_alloc_linear("test-reclaim-domain",
                                               &test_irq_mock_ops, hwirq, 1,
                                               &virq_base);
    test_check(ret == 0, "irq reclaim domain alloc");
    if (ret < 0)
        return;

    int irq = platform_irq_domain_map(&test_irq_mock_ops, hwirq);
    test_check(irq == (int)virq_base, "irq reclaim domain map");
    if (irq < 0)
        return;

    irq_blocking_entered = 0;
    irq_blocking_release = 0;
    ret = arch_request_irq_ex(irq, test_irq_blocking_handler, NULL,
                              IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "irq reclaim request");
    if (ret < 0)
        return;

    struct process *worker =
        kthread_create_joinable(irq_dispatch_once_thread, &irq, "irqonce");
    test_check(worker != NULL, "irq reclaim worker create");
    if (!worker) {
        (void)arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
        return;
    }
    sched_enqueue(worker);

    for (int i = 0; i < 200; i++) {
        if (__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED))
            break;
        proc_yield();
    }
    test_check(__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED) == 1,
               "irq reclaim handler entered");

    ret = arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
    test_check(ret == 0, "irq reclaim free while running");

    ret = platform_irq_domain_remove(virq_base);
    test_check(ret == -EBUSY, "irq reclaim remove busy before put");

    __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
    int reaped = test_reap_children_bounded(1, "irq_reclaim_once");
    test_check(reaped == 1, "irq reclaim worker reaped");

    ret = platform_irq_domain_remove(virq_base);
    test_check(ret == 0, "irq reclaim remove after put");
}

static void test_irq_free_sync_waits_handler(void) {
    int irq = 961;
    irq_blocking_entered = 0;
    irq_blocking_release = 0;
    irq_blocking_hits = 0;

    int ret = arch_request_irq_ex(irq, test_irq_blocking_handler, NULL,
                                  IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "irq syncfree request");
    if (ret < 0)
        return;

    struct process *dispatch_worker =
        kthread_create_joinable(irq_dispatch_once_thread, &irq, "irqsyncdisp");
    test_check(dispatch_worker != NULL, "irq syncfree dispatch worker create");
    if (!dispatch_worker) {
        (void)arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
        return;
    }
    sched_enqueue(dispatch_worker);

    for (int i = 0; i < 200; i++) {
        if (__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED))
            break;
        proc_yield();
    }
    test_check(__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED) == 1,
               "irq syncfree handler entered");

    struct irq_free_sync_ctx sync_ctx = {
        .irq = irq,
        .done = 0,
        .ret = -1,
    };
    struct process *free_worker =
        kthread_create_joinable(irq_free_sync_thread, &sync_ctx, "irqsyncfree");
    test_check(free_worker != NULL, "irq syncfree worker create");
    if (!free_worker) {
        __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
        (void)test_reap_children_bounded(1, "irq_syncfree_dispatch_fallback");
        (void)arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
        return;
    }
    sched_enqueue(free_worker);

    for (int i = 0; i < 50; i++)
        proc_yield();
    test_check(__atomic_load_n(&sync_ctx.done, __ATOMIC_RELAXED) == 0,
               "irq syncfree waits in-flight");

    __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
    int reaped = test_reap_children_bounded(2, "irq_syncfree");
    test_check(reaped == 2, "irq syncfree workers reaped");

    test_check(sync_ctx.ret == 0 &&
                   __atomic_load_n(&sync_ctx.done, __ATOMIC_RELAXED) == 1,
               "irq syncfree completed");

    ret = arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
    test_check(ret == 0, "irq syncfree idempotent");
}

static void test_irq_free_sync_waits_after_async_free(void) {
    const int irq = 964;
    irq_blocking_entered = 0;
    irq_blocking_release = 0;
    irq_blocking_hits = 0;

    int ret = arch_request_irq_ex(irq, test_irq_blocking_handler, NULL,
                                  IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "irq syncfree retired request");
    if (ret < 0)
        return;

    struct process *dispatch_worker = kthread_create_joinable(
        irq_dispatch_once_thread, (void *)&irq, "irqsyncretireddisp");
    test_check(dispatch_worker != NULL, "irq syncfree retired dispatch create");
    if (!dispatch_worker) {
        (void)arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
        return;
    }
    sched_enqueue(dispatch_worker);

    for (int i = 0; i < 200; i++) {
        if (__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED))
            break;
        proc_yield();
    }
    test_check(__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED) == 1,
               "irq syncfree retired entered");

    ret = arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
    test_check(ret == 0, "irq syncfree retired async free");

    struct irq_free_sync_ctx sync_ctx = {
        .irq = irq,
        .done = 0,
        .ret = -1,
    };
    struct process *sync_worker = kthread_create_joinable(
        irq_free_sync_thread, &sync_ctx, "irqsyncretiredfree");
    test_check(sync_worker != NULL, "irq syncfree retired sync worker create");
    if (!sync_worker) {
        __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
        (void)test_reap_children_bounded(1, "irq_syncfree_retired_dispatch");
        (void)arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
        return;
    }
    sched_enqueue(sync_worker);

    for (int i = 0; i < 50; i++)
        proc_yield();
    test_check(__atomic_load_n(&sync_ctx.done, __ATOMIC_RELAXED) == 0,
               "irq syncfree retired waits in-flight");

    __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
    int reaped = test_reap_children_bounded(2, "irq_syncfree_retired");
    test_check(reaped == 2, "irq syncfree retired workers reaped");
    test_check(sync_ctx.ret == 0 &&
                   __atomic_load_n(&sync_ctx.done, __ATOMIC_RELAXED) == 1,
               "irq syncfree retired completed");

    ret = arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
    test_check(ret == 0, "irq syncfree retired idempotent");
    uint32_t hits_before = __atomic_load_n(&irq_blocking_hits, __ATOMIC_RELAXED);
    platform_irq_dispatch_nr((uint32_t)irq);
    for (int i = 0; i < 50; i++)
        proc_yield();
    test_check(__atomic_load_n(&irq_blocking_hits, __ATOMIC_RELAXED) ==
                   hits_before,
               "irq syncfree retired removed");
}

static void test_irq_free_sync_waits_with_two_waiters(void) {
    const int irq = 966;
    irq_blocking_entered = 0;
    irq_blocking_release = 0;
    irq_blocking_hits = 0;

    int ret = arch_request_irq_ex(irq, test_irq_blocking_handler, NULL,
                                  IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP);
    test_check(ret == 0, "irq syncfree two waiters request");
    if (ret < 0)
        return;

    struct process *dispatch_worker = kthread_create_joinable(
        irq_dispatch_once_thread, (void *)&irq, "irqsync2disp");
    test_check(dispatch_worker != NULL, "irq syncfree two waiters dispatch create");
    if (!dispatch_worker) {
        (void)arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
        return;
    }
    sched_enqueue(dispatch_worker);

    for (int i = 0; i < 200; i++) {
        if (__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED))
            break;
        proc_yield();
    }
    test_check(__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED) == 1,
               "irq syncfree two waiters entered");

    struct irq_free_sync_ctx sync_a = {
        .irq = irq,
        .done = 0,
        .ret = -1,
    };
    struct irq_free_sync_ctx sync_b = {
        .irq = irq,
        .done = 0,
        .ret = -1,
    };
    struct process *worker_a =
        kthread_create_joinable(irq_free_sync_thread, &sync_a, "irqsync2a");
    struct process *worker_b =
        kthread_create_joinable(irq_free_sync_thread, &sync_b, "irqsync2b");
    test_check(worker_a != NULL && worker_b != NULL,
               "irq syncfree two waiters worker create");
    if (!worker_a || !worker_b) {
        __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
        if (worker_a)
            sched_enqueue(worker_a);
        if (worker_b)
            sched_enqueue(worker_b);
        int expected = 1;
        if (worker_a)
            expected++;
        if (worker_b)
            expected++;
        (void)test_reap_children_bounded(expected,
                                         "irq_syncfree_two_waiters_fallback");
        (void)arch_free_irq_ex(irq, test_irq_blocking_handler, NULL);
        return;
    }
    sched_enqueue(worker_a);
    sched_enqueue(worker_b);

    for (int i = 0; i < 50; i++)
        proc_yield();
    test_check(__atomic_load_n(&sync_a.done, __ATOMIC_RELAXED) == 0 &&
                   __atomic_load_n(&sync_b.done, __ATOMIC_RELAXED) == 0,
               "irq syncfree two waiters blocked");

    __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
    int reaped = test_reap_children_bounded(3, "irq_syncfree_two_waiters");
    test_check(reaped == 3, "irq syncfree two waiters reaped");
    test_check(sync_a.ret == 0 &&
                   __atomic_load_n(&sync_a.done, __ATOMIC_RELAXED) == 1,
               "irq syncfree two waiters first completed");
    test_check(sync_b.ret == 0 &&
                   __atomic_load_n(&sync_b.done, __ATOMIC_RELAXED) == 1,
               "irq syncfree two waiters second completed");
}

static void test_irq_cookie_lifecycle(void) {
    const int irq = 962;
    irq_request_hits = 0;
    uint64_t cookie = 0;

    int ret = arch_request_irq_ex_cookie(
        irq, test_irq_request_handler, NULL,
        IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP, &cookie);
    test_check(ret == 0 && cookie != 0, "irq cookie request");
    if (ret < 0 || cookie == 0)
        return;

    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_request_hits, __ATOMIC_RELAXED) == 1,
               "irq cookie dispatch");

    ret = arch_free_irq_cookie(cookie);
    test_check(ret == 0, "irq cookie free");
    ret = arch_free_irq_cookie(cookie);
    test_check(ret == 0, "irq cookie free idempotent");

    uint32_t hits_before =
        __atomic_load_n(&irq_request_hits, __ATOMIC_RELAXED);
    platform_irq_dispatch_nr((uint32_t)irq);
    test_check(__atomic_load_n(&irq_request_hits, __ATOMIC_RELAXED) ==
                   hits_before,
               "irq cookie removed");
}

static void test_irq_cookie_sync_waits_deferred_handler(void) {
    const int irq = 963;
    irq_blocking_entered = 0;
    irq_blocking_release = 0;
    irq_blocking_hits = 0;
    uint64_t cookie = 0;

    int ret = arch_request_irq_ex_cookie(
        irq, test_irq_blocking_handler, NULL,
        IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_DEFERRED | IRQ_FLAG_NO_CHIP, &cookie);
    test_check(ret == 0 && cookie != 0, "irq cookie sync deferred request");
    if (ret < 0 || cookie == 0)
        return;

    platform_irq_dispatch_nr((uint32_t)irq);
    for (int i = 0; i < 300; i++) {
        if (__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED))
            break;
        proc_yield();
    }
    test_check(__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED) == 1,
               "irq cookie sync deferred entered");

    struct irq_free_cookie_sync_ctx sync_ctx = {
        .cookie = cookie,
        .done = 0,
        .ret = -1,
    };
    struct process *free_worker = kthread_create_joinable(
        irq_free_cookie_sync_thread, &sync_ctx, "irqcookiesyncfree");
    test_check(free_worker != NULL, "irq cookie sync free worker create");
    if (!free_worker) {
        __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
        return;
    }
    sched_enqueue(free_worker);

    for (int i = 0; i < 50; i++)
        proc_yield();
    test_check(__atomic_load_n(&sync_ctx.done, __ATOMIC_RELAXED) == 0,
               "irq cookie sync waits in-flight");

    __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
    int reaped = test_reap_children_bounded(1, "irq_cookie_sync_deferred");
    test_check(reaped == 1, "irq cookie sync deferred worker reaped");
    test_check(sync_ctx.ret == 0 &&
                   __atomic_load_n(&sync_ctx.done, __ATOMIC_RELAXED) == 1,
               "irq cookie sync deferred completed");

    ret = arch_free_irq_cookie(cookie);
    test_check(ret == 0, "irq cookie sync deferred idempotent");

    uint32_t hits_before = __atomic_load_n(&irq_blocking_hits, __ATOMIC_RELAXED);
    platform_irq_dispatch_nr((uint32_t)irq);
    for (int i = 0; i < 50; i++)
        proc_yield();
    test_check(__atomic_load_n(&irq_blocking_hits, __ATOMIC_RELAXED) ==
                   hits_before,
               "irq cookie sync deferred removed");
}

static void test_irq_cookie_sync_waits_after_async_free(void) {
    const int irq = 965;
    irq_blocking_entered = 0;
    irq_blocking_release = 0;
    irq_blocking_hits = 0;
    uint64_t cookie = 0;

    int ret = arch_request_irq_ex_cookie(
        irq, test_irq_blocking_handler, NULL,
        IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_CHIP, &cookie);
    test_check(ret == 0 && cookie != 0, "irq cookie sync retired request");
    if (ret < 0 || cookie == 0)
        return;

    struct process *dispatch_worker = kthread_create_joinable(
        irq_dispatch_once_thread, (void *)&irq, "irqcookiesyncretireddisp");
    test_check(dispatch_worker != NULL,
               "irq cookie sync retired dispatch create");
    if (!dispatch_worker) {
        (void)arch_free_irq_cookie(cookie);
        return;
    }
    sched_enqueue(dispatch_worker);

    for (int i = 0; i < 200; i++) {
        if (__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED))
            break;
        proc_yield();
    }
    test_check(__atomic_load_n(&irq_blocking_entered, __ATOMIC_RELAXED) == 1,
               "irq cookie sync retired entered");

    ret = arch_free_irq_cookie(cookie);
    test_check(ret == 0, "irq cookie sync retired async free");

    struct irq_free_cookie_sync_ctx sync_ctx = {
        .cookie = cookie,
        .done = 0,
        .ret = -1,
    };
    struct process *sync_worker = kthread_create_joinable(
        irq_free_cookie_sync_thread, &sync_ctx, "irqcookiesyncretiredfree");
    test_check(sync_worker != NULL,
               "irq cookie sync retired sync worker create");
    if (!sync_worker) {
        __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
        (void)test_reap_children_bounded(1,
                                         "irq_cookie_sync_retired_dispatch");
        (void)arch_free_irq_cookie(cookie);
        return;
    }
    sched_enqueue(sync_worker);

    for (int i = 0; i < 50; i++)
        proc_yield();
    test_check(__atomic_load_n(&sync_ctx.done, __ATOMIC_RELAXED) == 0,
               "irq cookie sync retired waits in-flight");

    __atomic_store_n(&irq_blocking_release, 1, __ATOMIC_RELAXED);
    int reaped = test_reap_children_bounded(2, "irq_cookie_sync_retired");
    test_check(reaped == 2, "irq cookie sync retired workers reaped");
    test_check(sync_ctx.ret == 0 &&
                   __atomic_load_n(&sync_ctx.done, __ATOMIC_RELAXED) == 1,
               "irq cookie sync retired completed");

    ret = arch_free_irq_cookie(cookie);
    test_check(ret == 0, "irq cookie sync retired idempotent");
    uint32_t hits_before = __atomic_load_n(&irq_blocking_hits, __ATOMIC_RELAXED);
    platform_irq_dispatch_nr((uint32_t)irq);
    for (int i = 0; i < 50; i++)
        proc_yield();
    test_check(__atomic_load_n(&irq_blocking_hits, __ATOMIC_RELAXED) ==
                   hits_before,
               "irq cookie sync retired removed");
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

static void irq_parent_mock_enable(int irq) {
    irq_parent_mock_state.enable_hits++;
    irq_parent_mock_state.last_enable_irq = irq;
}

static void irq_parent_mock_disable(int irq) {
    irq_parent_mock_state.disable_hits++;
    irq_parent_mock_state.last_disable_irq = irq;
}

static int irq_parent_mock_set_type(int irq, uint32_t type) {
    irq_parent_mock_state.set_type_hits++;
    irq_parent_mock_state.last_type_irq = irq;
    irq_parent_mock_state.last_type = type;
    return 0;
}

static int irq_parent_mock_set_affinity(int irq, uint32_t cpu_mask) {
    irq_parent_mock_state.set_affinity_hits++;
    irq_parent_mock_state.last_affinity_irq = irq;
    irq_parent_mock_state.last_affinity_mask = cpu_mask;
    return 0;
}

static void irq_child_mock_enable(int irq) {
    irq_child_mock_state.enable_hits++;
    irq_child_mock_state.last_enable_irq = irq;
}

static void irq_child_mock_disable(int irq) {
    irq_child_mock_state.disable_hits++;
    irq_child_mock_state.last_disable_irq = irq;
}

static int irq_child_mock_set_type(int irq, uint32_t type) {
    irq_child_mock_state.set_type_hits++;
    irq_child_mock_state.last_type_irq = irq;
    irq_child_mock_state.last_type = type;
    return 0;
}

static int irq_child_mock_set_affinity(int irq, uint32_t cpu_mask) {
    irq_child_mock_state.set_affinity_hits++;
    irq_child_mock_state.last_affinity_irq = irq;
    irq_child_mock_state.last_affinity_mask = cpu_mask;
    return 0;
}

static const struct irqchip_ops test_irq_mock_ops = {
    .enable = irq_mock_enable,
    .disable = irq_mock_disable,
    .set_type = irq_mock_set_type,
    .set_affinity = irq_mock_set_affinity,
};

static const struct irqchip_ops test_irq_parent_mock_ops = {
    .enable = irq_parent_mock_enable,
    .disable = irq_parent_mock_disable,
    .set_type = irq_parent_mock_set_type,
    .set_affinity = irq_parent_mock_set_affinity,
};

static const struct irqchip_ops test_irq_child_mock_ops = {
    .enable = irq_child_mock_enable,
    .disable = irq_child_mock_disable,
    .set_type = irq_child_mock_set_type,
    .set_affinity = irq_child_mock_set_affinity,
};

struct test_irq_cascade_ctx {
    uint32_t fwnode;
    const struct irqchip_ops *chip;
    uint32_t hwirq;
};

struct test_irq_sparse_map_ctx {
    uint32_t hwirq[8];
    uint32_t nr;
};

static void test_irq_cascade_parent_handler(void *arg,
                                            const struct trap_core_event *ev) {
    struct test_irq_cascade_ctx *ctx = (struct test_irq_cascade_ctx *)arg;
    if (!ctx)
        return;
    if (ctx->fwnode)
        platform_irq_dispatch_fwnode_hwirq(ctx->fwnode, ctx->hwirq, ev);
    else if (ctx->chip)
        platform_irq_dispatch_hwirq(ctx->chip, ctx->hwirq, ev);
}

static int test_irq_sparse_map_hwirq(uint32_t hwirq, uint32_t virq_base,
                                     uint32_t nr_irqs, void *map_ctx,
                                     uint32_t *virq_out) {
    struct test_irq_sparse_map_ctx *ctx = map_ctx;
    if (!ctx || !virq_out || ctx->nr == 0 || ctx->nr > ARRAY_SIZE(ctx->hwirq))
        return -EINVAL;
    if (ctx->nr > nr_irqs)
        return -EINVAL;

    for (uint32_t i = 0; i < ctx->nr; i++) {
        if (ctx->hwirq[i] != hwirq)
            continue;
        *virq_out = virq_base + i;
        return 0;
    }
    return -ENOENT;
}

static int test_irq_sparse_map_virq(uint32_t virq, uint32_t virq_base,
                                    uint32_t nr_irqs, void *map_ctx,
                                    uint32_t *hwirq_out) {
    struct test_irq_sparse_map_ctx *ctx = map_ctx;
    if (!ctx || !hwirq_out || ctx->nr == 0 || ctx->nr > ARRAY_SIZE(ctx->hwirq))
        return -EINVAL;
    if (ctx->nr > nr_irqs)
        return -EINVAL;
    if (virq < virq_base || virq >= (virq_base + ctx->nr))
        return -ENOENT;
    *hwirq_out = ctx->hwirq[virq - virq_base];
    return 0;
}

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
    ret = platform_irq_unregister_ex(virq, test_irq_mock_handler, NULL);
    test_check(ret == 0, "irq domain unregister");
    ret = platform_irq_domain_remove(virq_base);
    test_check(ret == 0, "irq domain remove");
}

static void test_irq_domain_custom_mapping(void) {
    memset(&irq_mock_state, 0, sizeof(irq_mock_state));
    irq_mock_state.last_enable_irq = -1;
    irq_mock_state.last_disable_irq = -1;
    irq_mock_state.last_type_irq = -1;
    irq_mock_state.last_affinity_irq = -1;
    irq_mock_dispatch_hits = 0;

    struct test_irq_sparse_map_ctx sparse = {
        .hwirq = {910, 914, 922, 931},
        .nr = 4,
    };
    uint32_t virq_base = 0;
    int ret = platform_irq_domain_alloc_mapped(
        "test-sparse-domain", &test_irq_mock_ops, 0, sparse.nr,
        test_irq_sparse_map_hwirq, test_irq_sparse_map_virq, &sparse,
        &virq_base);
    test_check(ret == 0, "irq custom domain alloc");
    if (ret < 0)
        return;

    int virq = platform_irq_domain_map(&test_irq_mock_ops, 922);
    test_check(virq == (int)(virq_base + 2), "irq custom hwirq map");
    if (virq < 0)
        goto out_remove_domain;

    int missing = platform_irq_domain_map(&test_irq_mock_ops, 915);
    test_check(missing == -ENOENT, "irq custom sparse miss");

    arch_irq_register_ex(virq, test_irq_mock_handler, NULL,
                         IRQ_FLAG_TRIGGER_EDGE | IRQ_FLAG_NO_AUTO_ENABLE);
    arch_irq_enable_nr(virq);

    test_check(irq_mock_state.enable_hits == 1 &&
                   irq_mock_state.last_enable_irq == 922,
               "irq custom enable uses mapped hwirq");
    test_check(irq_mock_state.set_type_hits > 0 &&
                   irq_mock_state.last_type_irq == 922 &&
                   irq_mock_state.last_type == IRQ_FLAG_TRIGGER_EDGE,
               "irq custom set_type uses mapped hwirq");

    platform_irq_dispatch_hwirq(&test_irq_mock_ops, 922, NULL);
    test_check(__atomic_load_n(&irq_mock_dispatch_hits, __ATOMIC_RELAXED) == 1,
               "irq custom dispatch mapped hwirq");

    arch_irq_disable_nr(virq);
    test_check(irq_mock_state.disable_hits == 1 &&
                   irq_mock_state.last_disable_irq == 922,
               "irq custom disable uses mapped hwirq");

    ret = platform_irq_unregister_ex(virq, test_irq_mock_handler, NULL);
    test_check(ret == 0, "irq custom unregister");
out_remove_domain:
    ret = platform_irq_domain_remove(virq_base);
    test_check(ret == 0, "irq custom domain remove");
}

static void test_irq_domain_cascade(void) {
    memset(&irq_parent_mock_state, 0, sizeof(irq_parent_mock_state));
    memset(&irq_child_mock_state, 0, sizeof(irq_child_mock_state));
    irq_parent_mock_state.last_enable_irq = -1;
    irq_parent_mock_state.last_disable_irq = -1;
    irq_parent_mock_state.last_type_irq = -1;
    irq_parent_mock_state.last_affinity_irq = -1;
    irq_child_mock_state.last_enable_irq = -1;
    irq_child_mock_state.last_disable_irq = -1;
    irq_child_mock_state.last_type_irq = -1;
    irq_child_mock_state.last_affinity_irq = -1;
    irq_cascade_hits = 0;

    const uint32_t parent_fwnode = 0xD00D0020U;
    const uint32_t child_fwnode = 0xD00D0021U;
    uint32_t parent_virq_base = 0;
    uint32_t child_virq_base = 0;

    bool child0_registered = false;
    bool child1_registered = false;
    int ret = platform_irq_domain_alloc_linear_fwnode("test-parent-domain",
                                                      &test_irq_parent_mock_ops,
                                                      parent_fwnode, 200, 16,
                                                      &parent_virq_base);
    test_check(ret == 0, "irq cascade parent domain alloc");
    if (ret < 0)
        return;

    int parent_irq = platform_irq_domain_map_fwnode(parent_fwnode, 205);
    test_check(parent_irq >= 0, "irq cascade parent virq");
    if (parent_irq < 0)
        goto out_remove_parent;

    struct test_irq_cascade_ctx ctx = {
        .fwnode = child_fwnode,
        .chip = NULL,
        .hwirq = 3,
    };
    ret = platform_irq_domain_setup_cascade_fwnode(
        "test-child-domain", &test_irq_child_mock_ops, child_fwnode, 0, 16,
        parent_irq, test_irq_cascade_parent_handler, &ctx,
        IRQ_FLAG_TRIGGER_LEVEL, &child_virq_base);
    test_check(ret == 0, "irq cascade child domain setup");
    if (ret < 0)
        goto out_remove_parent;

    int child_irq0 = platform_irq_domain_map_fwnode(child_fwnode, 3);
    int child_irq1 = platform_irq_domain_map_fwnode(child_fwnode, 4);
    test_check(parent_irq >= 0 && child_irq0 >= 0 && child_irq1 >= 0,
               "irq cascade domain maps");
    test_check(parent_irq == (int)(parent_virq_base + 5),
               "irq cascade parent linear map");
    test_check(child_irq0 == (int)(child_virq_base + 3) &&
                   child_irq1 == (int)(child_virq_base + 4),
               "irq cascade child linear map");
    if (parent_irq < 0 || child_irq0 < 0 || child_irq1 < 0)
        goto out_remove_child;

    arch_irq_register_ex(child_irq0, test_irq_cascade_handler, NULL,
                         IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_AUTO_ENABLE);
    arch_irq_register_ex(child_irq1, test_irq_mock_handler, NULL,
                         IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_AUTO_ENABLE);
    child0_registered = true;
    child1_registered = true;

    arch_irq_enable_nr(child_irq0);
    test_check(irq_child_mock_state.enable_hits == 1 &&
                   irq_child_mock_state.last_enable_irq == 3,
               "irq cascade child enable uses child hwirq");
    test_check(irq_parent_mock_state.enable_hits == 1 &&
                   irq_parent_mock_state.last_enable_irq == 205,
               "irq cascade parent enabled on first child");

    platform_irq_dispatch_nr((uint32_t)parent_irq);
    test_check(__atomic_load_n(&irq_cascade_hits, __ATOMIC_RELAXED) == 1,
               "irq cascade parent dispatches child");

    arch_irq_enable_nr(child_irq1);
    test_check(irq_child_mock_state.enable_hits == 2 &&
                   irq_child_mock_state.last_enable_irq == 4,
               "irq cascade second child enable");
    test_check(irq_parent_mock_state.enable_hits == 1,
               "irq cascade parent enable refcount");

    arch_irq_disable_nr(child_irq0);
    test_check(irq_child_mock_state.disable_hits == 1 &&
                   irq_child_mock_state.last_disable_irq == 3,
               "irq cascade first child disable");
    test_check(irq_parent_mock_state.disable_hits == 0,
               "irq cascade parent stays enabled");

    arch_irq_disable_nr(child_irq1);
    test_check(irq_child_mock_state.disable_hits == 2 &&
                   irq_child_mock_state.last_disable_irq == 4,
               "irq cascade second child disable");
    test_check(irq_parent_mock_state.disable_hits == 1 &&
                   irq_parent_mock_state.last_disable_irq == 205,
               "irq cascade parent disabled on last child");
out_remove_child:
    if (child0_registered) {
        ret = platform_irq_unregister_ex(child_irq0, test_irq_cascade_handler, NULL);
        test_check(ret == 0, "irq cascade unregister child0");
    }
    if (child1_registered) {
        ret = platform_irq_unregister_ex(child_irq1, test_irq_mock_handler, NULL);
        test_check(ret == 0, "irq cascade unregister child1");
    }
    ret = platform_irq_domain_remove_fwnode(child_fwnode);
    test_check(ret == 0, "irq cascade remove child");
out_remove_parent:
    ret = platform_irq_domain_remove_fwnode(parent_fwnode);
    test_check(ret == 0, "irq cascade remove parent");
}

static void test_irq_domain_cascade_generic(void) {
    memset(&irq_parent_mock_state, 0, sizeof(irq_parent_mock_state));
    memset(&irq_child_mock_state, 0, sizeof(irq_child_mock_state));
    irq_parent_mock_state.last_enable_irq = -1;
    irq_parent_mock_state.last_disable_irq = -1;
    irq_parent_mock_state.last_type_irq = -1;
    irq_parent_mock_state.last_affinity_irq = -1;
    irq_child_mock_state.last_enable_irq = -1;
    irq_child_mock_state.last_disable_irq = -1;
    irq_child_mock_state.last_type_irq = -1;
    irq_child_mock_state.last_affinity_irq = -1;
    irq_cascade_hits = 0;

    uint32_t parent_virq_base = 0;
    uint32_t child_virq_base = 0;

    bool child0_registered = false;
    bool child1_registered = false;
    int ret = platform_irq_domain_alloc_linear("test-parent-domain-generic",
                                               &test_irq_parent_mock_ops, 320,
                                               16, &parent_virq_base);
    test_check(ret == 0, "irq cascade generic parent domain alloc");
    if (ret < 0)
        return;

    int parent_irq = platform_irq_domain_map(&test_irq_parent_mock_ops, 324);
    test_check(parent_irq >= 0, "irq cascade generic parent virq");
    if (parent_irq < 0)
        goto out_remove_parent;

    struct test_irq_cascade_ctx ctx = {
        .fwnode = 0,
        .chip = &test_irq_child_mock_ops,
        .hwirq = 67,
    };
    ret = platform_irq_domain_setup_cascade(
        "test-child-domain-generic", &test_irq_child_mock_ops, 64, 16,
        parent_irq, test_irq_cascade_parent_handler, &ctx,
        IRQ_FLAG_TRIGGER_LEVEL, &child_virq_base);
    test_check(ret == 0, "irq cascade generic child domain setup");
    if (ret < 0)
        goto out_remove_parent;

    int child_irq0 = platform_irq_domain_map(&test_irq_child_mock_ops, 67);
    int child_irq1 = platform_irq_domain_map(&test_irq_child_mock_ops, 68);
    test_check(parent_irq >= 0 && child_irq0 >= 0 && child_irq1 >= 0,
               "irq cascade generic domain maps");
    test_check(parent_irq == (int)(parent_virq_base + 4),
               "irq cascade generic parent linear map");
    test_check(child_irq0 == (int)(child_virq_base + 3) &&
                   child_irq1 == (int)(child_virq_base + 4),
               "irq cascade generic child linear map");
    if (parent_irq < 0 || child_irq0 < 0 || child_irq1 < 0)
        goto out_remove_child;

    arch_irq_register_ex(child_irq0, test_irq_cascade_handler, NULL,
                         IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_AUTO_ENABLE);
    arch_irq_register_ex(child_irq1, test_irq_mock_handler, NULL,
                         IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_AUTO_ENABLE);
    child0_registered = true;
    child1_registered = true;

    arch_irq_enable_nr(child_irq0);
    test_check(irq_child_mock_state.enable_hits == 1 &&
                   irq_child_mock_state.last_enable_irq == 67,
               "irq cascade generic child enable uses child hwirq");
    test_check(irq_parent_mock_state.enable_hits == 1 &&
                   irq_parent_mock_state.last_enable_irq == 324,
               "irq cascade generic parent enabled on first child");

    platform_irq_dispatch_nr((uint32_t)parent_irq);
    test_check(__atomic_load_n(&irq_cascade_hits, __ATOMIC_RELAXED) == 1,
               "irq cascade generic parent dispatches child");

    arch_irq_enable_nr(child_irq1);
    test_check(irq_child_mock_state.enable_hits == 2 &&
                   irq_child_mock_state.last_enable_irq == 68,
               "irq cascade generic second child enable");
    test_check(irq_parent_mock_state.enable_hits == 1,
               "irq cascade generic parent enable refcount");

    arch_irq_disable_nr(child_irq0);
    test_check(irq_child_mock_state.disable_hits == 1 &&
                   irq_child_mock_state.last_disable_irq == 67,
               "irq cascade generic first child disable");
    test_check(irq_parent_mock_state.disable_hits == 0,
               "irq cascade generic parent stays enabled");

    arch_irq_disable_nr(child_irq1);
    test_check(irq_child_mock_state.disable_hits == 2 &&
                   irq_child_mock_state.last_disable_irq == 68,
               "irq cascade generic second child disable");
    test_check(irq_parent_mock_state.disable_hits == 1 &&
                   irq_parent_mock_state.last_disable_irq == 324,
               "irq cascade generic parent disabled on last child");
out_remove_child:
    if (child0_registered) {
        ret = platform_irq_unregister_ex(child_irq0, test_irq_cascade_handler, NULL);
        test_check(ret == 0, "irq cascade generic unregister child0");
    }
    if (child1_registered) {
        ret = platform_irq_unregister_ex(child_irq1, test_irq_mock_handler, NULL);
        test_check(ret == 0, "irq cascade generic unregister child1");
    }
    ret = platform_irq_domain_remove(child_virq_base);
    test_check(ret == 0, "irq cascade generic remove child");
out_remove_parent:
    ret = platform_irq_domain_remove(parent_virq_base);
    test_check(ret == 0, "irq cascade generic remove parent");
}

static void test_irq_domain_cascade_mapped(void) {
    memset(&irq_parent_mock_state, 0, sizeof(irq_parent_mock_state));
    memset(&irq_child_mock_state, 0, sizeof(irq_child_mock_state));
    irq_parent_mock_state.last_enable_irq = -1;
    irq_parent_mock_state.last_disable_irq = -1;
    irq_child_mock_state.last_enable_irq = -1;
    irq_child_mock_state.last_disable_irq = -1;
    irq_cascade_hits = 0;
    const uint32_t parent_fwnode = 0xD00D00A4U;
    const uint32_t child_fwnode = 0xD00D00A5U;

    uint32_t parent_virq_base = 0;
    uint32_t child_virq_base = 0;
    int ret = platform_irq_domain_alloc_linear_fwnode(
        "test-mapped-parent", &test_irq_parent_mock_ops, parent_fwnode, 340, 8,
        &parent_virq_base);
    test_check(ret == 0, "irq mapped cascade parent alloc");
    if (ret < 0)
        return;

    int parent_irq = platform_irq_domain_map_fwnode(parent_fwnode, 342);
    test_check(parent_irq == (int)(parent_virq_base + 2),
               "irq mapped cascade parent map");
    if (parent_irq < 0)
        return;

    struct test_irq_sparse_map_ctx sparse = {
        .hwirq = {41, 43, 47},
        .nr = 3,
    };
    struct test_irq_cascade_ctx ctx = {
        .fwnode = child_fwnode,
        .chip = NULL,
        .hwirq = 47,
    };
    ret = platform_irq_domain_setup_cascade_mapped_fwnode(
        "test-mapped-child", &test_irq_child_mock_ops, child_fwnode, 0,
        sparse.nr, test_irq_sparse_map_hwirq, test_irq_sparse_map_virq, &sparse,
        parent_irq, test_irq_cascade_parent_handler, &ctx,
        IRQ_FLAG_TRIGGER_LEVEL, &child_virq_base);
    test_check(ret == 0, "irq mapped cascade child setup");
    if (ret < 0)
        return;

    int child_irq = platform_irq_domain_map_fwnode(child_fwnode, 47);
    test_check(child_irq == (int)(child_virq_base + 2),
               "irq mapped cascade child map");
    if (child_irq < 0)
        return;

    arch_irq_register_ex(child_irq, test_irq_cascade_handler, NULL,
                         IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_AUTO_ENABLE);
    arch_irq_enable_nr(child_irq);

    test_check(irq_child_mock_state.enable_hits == 1 &&
                   irq_child_mock_state.last_enable_irq == 47,
               "irq mapped cascade child enable hwirq");
    test_check(irq_parent_mock_state.enable_hits == 1 &&
                   irq_parent_mock_state.last_enable_irq == 342,
               "irq mapped cascade parent enabled");

    platform_irq_dispatch_nr((uint32_t)parent_irq);
    test_check(__atomic_load_n(&irq_cascade_hits, __ATOMIC_RELAXED) == 1,
               "irq mapped cascade dispatch");

    arch_irq_disable_nr(child_irq);
    test_check(irq_child_mock_state.disable_hits == 1 &&
                   irq_child_mock_state.last_disable_irq == 47,
               "irq mapped cascade child disable hwirq");
    test_check(irq_parent_mock_state.disable_hits == 1 &&
                   irq_parent_mock_state.last_disable_irq == 342,
               "irq mapped cascade parent disabled");

    ret = platform_irq_unregister_ex(child_irq, test_irq_cascade_handler, NULL);
    test_check(ret == 0, "irq mapped cascade unregister child");
    ret = platform_irq_domain_remove_fwnode(child_fwnode);
    test_check(ret == 0, "irq mapped cascade remove child");
    ret = platform_irq_domain_remove_fwnode(parent_fwnode);
    test_check(ret == 0, "irq mapped cascade remove parent");
}

static void test_irq_domain_lifecycle(void) {
    memset(&irq_parent_mock_state, 0, sizeof(irq_parent_mock_state));
    memset(&irq_child_mock_state, 0, sizeof(irq_child_mock_state));
    irq_parent_mock_state.last_enable_irq = -1;
    irq_parent_mock_state.last_disable_irq = -1;
    irq_parent_mock_state.last_type_irq = -1;
    irq_parent_mock_state.last_affinity_irq = -1;
    irq_child_mock_state.last_enable_irq = -1;
    irq_child_mock_state.last_disable_irq = -1;
    irq_child_mock_state.last_type_irq = -1;
    irq_child_mock_state.last_affinity_irq = -1;

    uint32_t parent_virq_base = 0;
    uint32_t child_virq_base = 0;
    int ret = platform_irq_domain_alloc_linear("test-lifecycle-parent",
                                               &test_irq_parent_mock_ops, 500,
                                               8, &parent_virq_base);
    test_check(ret == 0, "irq lifecycle parent domain alloc");
    if (ret < 0)
        return;

    int parent_irq = platform_irq_domain_map(&test_irq_parent_mock_ops, 503);
    test_check(parent_irq >= 0, "irq lifecycle parent virq");
    if (parent_irq < 0)
        return;

    struct test_irq_cascade_ctx ctx = {
        .fwnode = 0,
        .chip = &test_irq_child_mock_ops,
        .hwirq = 703,
    };
    ret = platform_irq_domain_setup_cascade("test-lifecycle-child",
                                            &test_irq_child_mock_ops, 700, 8,
                                            parent_irq,
                                            test_irq_cascade_parent_handler,
                                            &ctx, IRQ_FLAG_TRIGGER_LEVEL,
                                            &child_virq_base);
    test_check(ret == 0, "irq lifecycle child domain setup");
    if (ret < 0)
        return;

    int child_irq = platform_irq_domain_map(&test_irq_child_mock_ops, 703);
    test_check(child_irq >= 0, "irq lifecycle child virq");
    if (child_irq < 0)
        return;

    arch_irq_register_ex(child_irq, test_irq_cascade_handler, NULL,
                         IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_NO_AUTO_ENABLE);
    arch_irq_enable_nr(child_irq);
    test_check(irq_parent_mock_state.enable_hits == 1 &&
                   irq_parent_mock_state.last_enable_irq == 503,
               "irq lifecycle parent enabled");
    arch_irq_disable_nr(child_irq);
    test_check(irq_parent_mock_state.disable_hits == 1 &&
                   irq_parent_mock_state.last_disable_irq == 503,
               "irq lifecycle parent disabled");

    ret = platform_irq_domain_unset_cascade(child_virq_base);
    test_check(ret == 0, "irq lifecycle unset cascade");
    if (ret < 0)
        return;

    arch_irq_enable_nr(child_irq);
    test_check(irq_child_mock_state.enable_hits >= 2 &&
                   irq_parent_mock_state.enable_hits == 1,
               "irq lifecycle child enable without parent");
    arch_irq_disable_nr(child_irq);
    test_check(irq_child_mock_state.disable_hits >= 2 &&
                   irq_parent_mock_state.disable_hits == 1,
               "irq lifecycle child disable without parent");

    ret = platform_irq_domain_remove(child_virq_base);
    test_check(ret == -EBUSY, "irq lifecycle remove busy with handler");

    ret = platform_irq_unregister_ex(child_irq, test_irq_cascade_handler, NULL);
    test_check(ret == 0, "irq lifecycle unregister child handler");
    ret = platform_irq_domain_remove(child_virq_base);
    test_check(ret == 0, "irq lifecycle remove child domain");
    test_check(platform_irq_domain_map(&test_irq_child_mock_ops, 703) == -ENOENT,
               "irq lifecycle child mapping removed");

    ret = platform_irq_domain_remove(parent_virq_base);
    test_check(ret == 0, "irq lifecycle remove parent domain");
    test_check(platform_irq_domain_map(&test_irq_parent_mock_ops, 503) == -ENOENT,
               "irq lifecycle parent mapping removed");
}

static void test_irq_domain_dynamic_capacity(void) {
    enum { TEST_DYNAMIC_DOMAINS = 12 };
    uint32_t virq_bases[TEST_DYNAMIC_DOMAINS] = { 0 };

    for (int i = 0; i < TEST_DYNAMIC_DOMAINS; i++) {
        uint32_t hwirq_base = 820 + (uint32_t)(i * 2);
        int ret = platform_irq_domain_alloc_linear("test-dynamic-domain",
                                                   &test_irq_mock_ops,
                                                   hwirq_base, 1,
                                                   &virq_bases[i]);
        test_check(ret == 0, "irq dynamic domain alloc");
        if (ret < 0)
            return;
        int mapped = platform_irq_domain_map(&test_irq_mock_ops, hwirq_base);
        test_check(mapped == (int)virq_bases[i], "irq dynamic domain map");
    }

    for (int i = TEST_DYNAMIC_DOMAINS - 1; i >= 0; i--) {
        int ret = platform_irq_domain_remove(virq_bases[i]);
        test_check(ret == 0, "irq dynamic domain remove");
    }
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

static void run_driver_suite_once(void) {
    test_ringbuf();
    test_virtqueue();
    test_blkdev_registry();
    test_blkdev_partition_children();
    test_blkdev_gpt_partition_bounds();
    test_netdev_registry();
    test_dma_coherent_alloc_free();
    test_dma_constraints_direct_backend();
    test_iommu_domain_dma_ops();
    test_dma_constraints_iommu_backend();
    test_iommu_default_domain_attach();
    test_iommu_hw_ops_default_attach();
    test_iommu_attach_replaces_owned_domain();
    test_irq_deferred_dispatch();
    test_irq_shared_actions();
    test_irq_unregister_actions();
    test_irq_enable_disable_gate();
    test_irq_request_free_actions();
    test_platform_device_irq_helpers();
    test_irq_stats_export();
    test_irq_stats_snapshot_and_procfs();
    test_irq_unregister_dispatch_concurrency();
    test_irq_domain_remove_waits_reclaim();
    test_irq_free_sync_waits_handler();
    test_irq_free_sync_waits_after_async_free();
    test_irq_free_sync_waits_with_two_waiters();
    test_irq_cookie_lifecycle();
    test_irq_cookie_sync_waits_deferred_handler();
    test_irq_cookie_sync_waits_after_async_free();
    test_irq_domain_programming();
    test_irq_domain_custom_mapping();
    test_irq_domain_cascade();
    test_irq_domain_cascade_generic();
    test_irq_domain_cascade_mapped();
    test_irq_domain_lifecycle();
    test_irq_domain_dynamic_capacity();
#if CONFIG_KERNEL_TESTS
    test_virtio_net_rx_to_lwip_bridge();
#endif
    test_vfs_umount_busy_with_child_mount();
}

int run_driver_tests(void) {
    tests_failed = 0;
    pr_info("\n=== Driver Tests ===\n");

    run_driver_suite_once();
    int first_pass_failures = tests_failed;
    pr_info("driver tests: rerun suite for isolation check\n");
    run_driver_suite_once();
    test_check(tests_failed == first_pass_failures,
               "driver suite rerun in same kernel");

    if (tests_failed == 0)
        pr_info("driver tests: all passed\n");
    else
        pr_err("driver tests: %d failures\n", tests_failed);
    return tests_failed;
}
