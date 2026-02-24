/**
 * kernel/core/tests/driver_tests.c - Driver and helper tests
 */

#include <kairos/blkdev.h>
#include <kairos/net.h>
#include <kairos/printk.h>
#include <kairos/ringbuf.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
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
    uint8_t mbr[512];
    uint64_t last_lba;
    size_t last_count;
};

static void write_le32(uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v & 0xff);
    dst[1] = (uint8_t)((v >> 8) & 0xff);
    dst[2] = (uint8_t)((v >> 16) & 0xff);
    dst[3] = (uint8_t)((v >> 24) & 0xff);
}

static int partition_img_read(struct blkdev *dev, uint64_t lba, void *buf, size_t count) {
    if (!dev || !buf || !count || !dev->private)
        return -EINVAL;

    struct partition_test_image *img = dev->private;
    memset(buf, 0, count * dev->sector_size);
    if (lba == 0 && count >= 1)
        memcpy(buf, img->mbr, sizeof(img->mbr));
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
    img.mbr[510] = 0x55;
    img.mbr[511] = 0xAA;
    /* First entry: Linux partition, lba=2048, sectors=1024 */
    uint8_t *entry = &img.mbr[446];
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
    test_netdev_registry();
    test_vfs_umount_busy_with_child_mount();

    if (tests_failed == 0)
        pr_info("driver tests: all passed\n");
    else
        pr_err("driver tests: %d failures\n", tests_failed);
    return tests_failed;
}
