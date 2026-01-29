/**
 * kernel/core/tests/driver_tests.c - Driver and helper tests
 */

#include <kairos/blkdev.h>
#include <kairos/net.h>
#include <kairos/printk.h>
#include <kairos/ringbuf.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/virtio.h>

static int tests_failed;

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("tests: %s failed\n", name);
        tests_failed++;
    }
}

static int dummy_blk_read(struct blkdev *dev, uint64_t lba, void *buf, size_t count) {
    (void)dev;
    (void)lba;
    (void)buf;
    (void)count;
    return 0;
}

static int dummy_blk_write(struct blkdev *dev, uint64_t lba, const void *buf, size_t count) {
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

void run_driver_tests(void) {
    tests_failed = 0;
    pr_info("\n=== Driver Tests ===\n");

    test_ringbuf();
    test_virtqueue();
    test_blkdev_registry();
    test_netdev_registry();

    if (tests_failed == 0)
        pr_info("driver tests: all passed\n");
    else
        pr_err("driver tests: %d failures\n", tests_failed);
}
