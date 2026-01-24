/**
 * virtio_blk.c - VirtIO Block Device Driver
 *
 * Simple VirtIO block device driver for RISC-V (MMIO).
 * This is a basic implementation for Phase 5.
 */

#include <kairos/blkdev.h>
#include <kairos/printk.h>
#include <kairos/mm.h>
#include <kairos/types.h>

/* VirtIO MMIO Registers (offsets from base) */
#define VIRTIO_MMIO_MAGIC_VALUE         0x000
#define VIRTIO_MMIO_VERSION             0x004
#define VIRTIO_MMIO_DEVICE_ID           0x008
#define VIRTIO_MMIO_VENDOR_ID           0x00c
#define VIRTIO_MMIO_DEVICE_FEATURES     0x010
#define VIRTIO_MMIO_DRIVER_FEATURES     0x020
#define VIRTIO_MMIO_QUEUE_SEL           0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX       0x034
#define VIRTIO_MMIO_QUEUE_NUM           0x038
#define VIRTIO_MMIO_QUEUE_READY         0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY        0x050
#define VIRTIO_MMIO_INTERRUPT_STATUS    0x060
#define VIRTIO_MMIO_INTERRUPT_ACK       0x064
#define VIRTIO_MMIO_STATUS              0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW      0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH     0x084
#define VIRTIO_MMIO_QUEUE_DRIVER_LOW    0x090
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH   0x094
#define VIRTIO_MMIO_QUEUE_DEVICE_LOW    0x0a0
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH   0x0a4
#define VIRTIO_MMIO_CONFIG              0x100

/* VirtIO device IDs */
#define VIRTIO_ID_BLOCK                 2

/* VirtIO status bits */
#define VIRTIO_STATUS_ACKNOWLEDGE       1
#define VIRTIO_STATUS_DRIVER            2
#define VIRTIO_STATUS_DRIVER_OK         4
#define VIRTIO_STATUS_FEATURES_OK       8
#define VIRTIO_STATUS_FAILED            128

/* VirtIO queue size */
#define VIRTQ_SIZE                      8

/* VirtIO descriptor flags */
#define VIRTQ_DESC_F_NEXT               1
#define VIRTQ_DESC_F_WRITE              2

/* VirtIO block request types */
#define VIRTIO_BLK_T_IN                 0
#define VIRTIO_BLK_T_OUT                1

/* VirtIO block request status */
#define VIRTIO_BLK_S_OK                 0
#define VIRTIO_BLK_S_IOERR              1

/**
 * VirtIO structures
 */
struct virtq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __packed;

struct virtq_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[VIRTQ_SIZE];
    uint16_t used_event;
} __packed;

struct virtq_used_elem {
    uint32_t id;
    uint32_t len;
} __packed;

struct virtq_used {
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[VIRTQ_SIZE];
    uint16_t avail_event;
} __packed;

struct virtio_blk_req {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} __packed;

/**
 * VirtIO block device state
 */
struct virtio_blk_dev {
    volatile uint32_t *mmio_base;
    struct virtq_desc *desc;
    struct virtq_avail *avail;
    struct virtq_used *used;
    uint16_t last_used_idx;
    struct blkdev blkdev;
};

static struct virtio_blk_dev *virtio_disk;

/**
 * MMIO read/write helpers
 */
static inline uint32_t mmio_read32(volatile uint32_t *base, uint32_t offset)
{
    return *(volatile uint32_t *)((char *)base + offset);
}

static inline void mmio_write32(volatile uint32_t *base, uint32_t offset, uint32_t val)
{
    *(volatile uint32_t *)((char *)base + offset) = val;
}

/**
 * virtio_blk_read - Read sectors from virtio block device
 */
static int virtio_blk_read(struct blkdev *dev, uint64_t lba, void *buf, size_t count)
{
    struct virtio_blk_dev *vdev = dev->private;
    struct virtio_blk_req req;
    uint8_t status;
    int desc_idx;

    if (!vdev || !buf) {
        return -EINVAL;
    }

    /* Build request */
    req.type = VIRTIO_BLK_T_IN;
    req.reserved = 0;
    req.sector = lba;

    /* Allocate descriptors */
    desc_idx = 0;

    /* Descriptor 0: request header */
    vdev->desc[desc_idx].addr = (uint64_t)&req;
    vdev->desc[desc_idx].len = sizeof(req);
    vdev->desc[desc_idx].flags = VIRTQ_DESC_F_NEXT;
    vdev->desc[desc_idx].next = 1;

    /* Descriptor 1: data buffer */
    vdev->desc[1].addr = (uint64_t)buf;
    vdev->desc[1].len = count * dev->sector_size;
    vdev->desc[1].flags = VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT;
    vdev->desc[1].next = 2;

    /* Descriptor 2: status byte */
    status = 0xFF;
    vdev->desc[2].addr = (uint64_t)&status;
    vdev->desc[2].len = 1;
    vdev->desc[2].flags = VIRTQ_DESC_F_WRITE;
    vdev->desc[2].next = 0;

    /* Add to available ring */
    uint16_t avail_idx = vdev->avail->idx % VIRTQ_SIZE;
    vdev->avail->ring[avail_idx] = desc_idx;
    __sync_synchronize();
    vdev->avail->idx++;

    /* Notify device */
    mmio_write32(vdev->mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    /* Wait for completion with timeout */
    int timeout = 10000000;  /* ~10 second timeout */
    while (vdev->last_used_idx == vdev->used->idx && timeout > 0) {
        __sync_synchronize();
        timeout--;
    }

    if (timeout == 0) {
        pr_err("virtio-blk: read timeout (used_idx=%u, last=%u)\n",
               vdev->used->idx, vdev->last_used_idx);
        return -ETIMEDOUT;
    }

    vdev->last_used_idx++;

    /* Check status */
    if (status != VIRTIO_BLK_S_OK) {
        pr_err("virtio-blk: read error, status=%u\n", status);
        return -EIO;
    }

    return 0;
}

/**
 * virtio_blk_write - Write sectors to virtio block device
 */
static int virtio_blk_write(struct blkdev *dev, uint64_t lba, const void *buf, size_t count)
{
    struct virtio_blk_dev *vdev = dev->private;
    struct virtio_blk_req req;
    uint8_t status;
    int desc_idx;

    if (!vdev || !buf) {
        return -EINVAL;
    }

    /* Build request */
    req.type = VIRTIO_BLK_T_OUT;
    req.reserved = 0;
    req.sector = lba;

    /* Allocate descriptors */
    desc_idx = 0;

    /* Descriptor 0: request header */
    vdev->desc[desc_idx].addr = (uint64_t)&req;
    vdev->desc[desc_idx].len = sizeof(req);
    vdev->desc[desc_idx].flags = VIRTQ_DESC_F_NEXT;
    vdev->desc[desc_idx].next = 1;

    /* Descriptor 1: data buffer */
    vdev->desc[1].addr = (uint64_t)buf;
    vdev->desc[1].len = count * dev->sector_size;
    vdev->desc[1].flags = VIRTQ_DESC_F_NEXT;
    vdev->desc[1].next = 2;

    /* Descriptor 2: status byte */
    status = 0xFF;
    vdev->desc[2].addr = (uint64_t)&status;
    vdev->desc[2].len = 1;
    vdev->desc[2].flags = VIRTQ_DESC_F_WRITE;
    vdev->desc[2].next = 0;

    /* Add to available ring */
    uint16_t avail_idx = vdev->avail->idx % VIRTQ_SIZE;
    vdev->avail->ring[avail_idx] = desc_idx;
    __sync_synchronize();
    vdev->avail->idx++;

    /* Notify device */
    mmio_write32(vdev->mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    /* Wait for completion with timeout */
    int timeout = 10000000;  /* ~10 second timeout */
    while (vdev->last_used_idx == vdev->used->idx && timeout > 0) {
        __sync_synchronize();
        timeout--;
    }

    if (timeout == 0) {
        pr_err("virtio-blk: write timeout (used_idx=%u, last=%u)\n",
               vdev->used->idx, vdev->last_used_idx);
        return -ETIMEDOUT;
    }

    vdev->last_used_idx++;

    /* Check status */
    if (status != VIRTIO_BLK_S_OK) {
        pr_err("virtio-blk: write error, status=%u\n", status);
        return -EIO;
    }

    return 0;
}

static struct blkdev_ops virtio_blk_ops = {
    .read = virtio_blk_read,
    .write = virtio_blk_write,
    .flush = NULL,
};

/**
 * virtio_blk_init - Initialize VirtIO block device
 *
 * @mmio_addr: MMIO base address
 *
 * This is called during device discovery.
 */
int virtio_blk_init(uint64_t mmio_addr)
{
    struct virtio_blk_dev *vdev;
    uint32_t magic, version, device_id;
    uint64_t capacity;

    pr_info("virtio-blk: probing device at 0x%lx\n", mmio_addr);

    /* Map MMIO region */
    volatile uint32_t *base = (volatile uint32_t *)mmio_addr;

    /* Check magic value */
    magic = mmio_read32(base, VIRTIO_MMIO_MAGIC_VALUE);
    pr_info("virtio-blk: magic=0x%x\n", magic);
    if (magic != 0x74726976) {  /* 'virt' */
        pr_err("virtio-blk: invalid magic value: 0x%x\n", magic);
        return -ENODEV;
    }

    /* Check version (support both v1 and v2) */
    version = mmio_read32(base, VIRTIO_MMIO_VERSION);
    pr_info("virtio-blk: version=%u\n", version);
    if (version < 1 || version > 2) {
        pr_err("virtio-blk: unsupported version: %u\n", version);
        return -ENODEV;
    }

    /* Check device ID */
    device_id = mmio_read32(base, VIRTIO_MMIO_DEVICE_ID);
    pr_info("virtio-blk: device_id=%u\n", device_id);
    if (device_id != VIRTIO_ID_BLOCK) {
        pr_info("virtio: device ID %u is not block device\n", device_id);
        return -ENODEV;
    }

    /* Allocate device structure */
    vdev = kzalloc(sizeof(*vdev));
    if (!vdev) {
        return -ENOMEM;
    }

    vdev->mmio_base = base;
    vdev->last_used_idx = 0;

    /* Reset device */
    mmio_write32(base, VIRTIO_MMIO_STATUS, 0);

    /* Set ACKNOWLEDGE */
    mmio_write32(base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

    /* Set DRIVER */
    mmio_write32(base, VIRTIO_MMIO_STATUS,
                 VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    /* Read and acknowledge features */
    uint32_t features = mmio_read32(base, VIRTIO_MMIO_DEVICE_FEATURES);
    mmio_write32(base, VIRTIO_MMIO_DRIVER_FEATURES, 0);  /* No special features */

    /* Set FEATURES_OK */
    mmio_write32(base, VIRTIO_MMIO_STATUS,
                 VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
                 VIRTIO_STATUS_FEATURES_OK);

    /* Allocate virtqueue */
    mmio_write32(base, VIRTIO_MMIO_QUEUE_SEL, 0);

    uint32_t max_queue_size = mmio_read32(base, VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (max_queue_size < VIRTQ_SIZE) {
        pr_err("virtio-blk: queue too small: %u\n", max_queue_size);
        kfree(vdev);
        return -ENODEV;
    }

    /* Allocate queue memory */
    size_t desc_size = VIRTQ_SIZE * sizeof(struct virtq_desc);
    size_t avail_size = sizeof(struct virtq_avail);
    size_t used_size = sizeof(struct virtq_used);

    vdev->desc = kzalloc(desc_size);
    vdev->avail = kzalloc(avail_size);
    vdev->used = kzalloc(used_size);

    if (!vdev->desc || !vdev->avail || !vdev->used) {
        kfree(vdev->desc);
        kfree(vdev->avail);
        kfree(vdev->used);
        kfree(vdev);
        return -ENOMEM;
    }

    /* Configure queue */
    mmio_write32(base, VIRTIO_MMIO_QUEUE_NUM, VIRTQ_SIZE);
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DESC_LOW, (uint32_t)(uint64_t)vdev->desc);
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DESC_HIGH, (uint32_t)((uint64_t)vdev->desc >> 32));
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DRIVER_LOW, (uint32_t)(uint64_t)vdev->avail);
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DRIVER_HIGH, (uint32_t)((uint64_t)vdev->avail >> 32));
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DEVICE_LOW, (uint32_t)(uint64_t)vdev->used);
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DEVICE_HIGH, (uint32_t)((uint64_t)vdev->used >> 32));
    mmio_write32(base, VIRTIO_MMIO_QUEUE_READY, 1);

    /* Set DRIVER_OK */
    mmio_write32(base, VIRTIO_MMIO_STATUS,
                 VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
                 VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

    /* Read capacity from config space */
    capacity = mmio_read32(base, VIRTIO_MMIO_CONFIG);
    capacity |= (uint64_t)mmio_read32(base, VIRTIO_MMIO_CONFIG + 4) << 32;

    /* Register block device */
    vdev->blkdev.name[0] = 'v';
    vdev->blkdev.name[1] = 'd';
    vdev->blkdev.name[2] = 'a';
    vdev->blkdev.name[3] = '\0';
    vdev->blkdev.sector_count = capacity;
    vdev->blkdev.sector_size = 512;
    vdev->blkdev.ops = &virtio_blk_ops;
    vdev->blkdev.private = vdev;

    int ret = blkdev_register(&vdev->blkdev);
    if (ret < 0) {
        pr_err("virtio-blk: failed to register block device: %d\n", ret);
        kfree(vdev->desc);
        kfree(vdev->avail);
        kfree(vdev->used);
        kfree(vdev);
        return ret;
    }

    virtio_disk = vdev;
    pr_info("virtio-blk: initialized %s with %lu sectors\n",
            vdev->blkdev.name, capacity);

    return 0;
}

/**
 * virtio_blk_probe - Probe for VirtIO block devices
 *
 * This is called during kernel initialization.
 * For RISC-V QEMU virt machine, virtio-blk is at 0x10008000.
 */
void virtio_blk_probe(void)
{
    /* RISC-V QEMU virt machine VirtIO MMIO addresses */
    uint64_t virtio_addrs[] = {
        0x10001000, 0x10002000, 0x10003000, 0x10004000,
        0x10005000, 0x10006000, 0x10007000, 0x10008000,
    };

    for (size_t i = 0; i < ARRAY_SIZE(virtio_addrs); i++) {
        virtio_blk_init(virtio_addrs[i]);
    }
}
