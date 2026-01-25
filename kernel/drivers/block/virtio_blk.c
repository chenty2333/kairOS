/**
 * virtio_blk.c - VirtIO Block Device Driver (Interrupt Driven)
 */

#include <kairos/arch.h>
#include <kairos/blkdev.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/wait.h>

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
    struct mutex lock;
    struct wait_queue io_wait;
    int irq;
    struct blkdev blkdev;
};

static struct virtio_blk_dev *virtio_disk;

/**
 * MMIO read/write helpers
 */
static inline uint32_t mmio_read32(volatile uint32_t *base, uint32_t offset) {
    return *(volatile uint32_t *)((char *)base + offset);
}

static inline void mmio_write32(volatile uint32_t *base, uint32_t offset, uint32_t val) {
    *(volatile uint32_t *)((char *)base + offset) = val;
}

/**
 * virtio_blk_intr - Interrupt handler
 */
static void virtio_blk_intr(void *arg) {
    struct virtio_blk_dev *vdev = arg;
    
    /* Acknowledge interrupt */
    uint32_t status = mmio_read32(vdev->mmio_base, VIRTIO_MMIO_INTERRUPT_STATUS);
    mmio_write32(vdev->mmio_base, VIRTIO_MMIO_INTERRUPT_ACK, status);
    
    /* Wake up any waiting process */
    wait_queue_wakeup_all(&vdev->io_wait);
}

/**
 * virtio_blk_read - Read sectors from virtio block device
 */
static int virtio_blk_read(struct blkdev *dev, uint64_t lba, void *buf, size_t count) {
    struct virtio_blk_dev *vdev = dev->private;
    struct virtio_blk_req req;
    uint8_t status;

    if (!vdev || !buf) return -EINVAL;

    mutex_lock(&vdev->lock);

    /* Build request */
    req.type = VIRTIO_BLK_T_IN;
    req.reserved = 0;
    req.sector = lba;

    /* Descriptor 0: request header */
    vdev->desc[0].addr = (uint64_t)virt_to_phys(&req);
    vdev->desc[0].len = sizeof(req);
    vdev->desc[0].flags = VIRTQ_DESC_F_NEXT;
    vdev->desc[0].next = 1;

    /* Descriptor 1: data buffer */
    vdev->desc[1].addr = (uint64_t)virt_to_phys(buf);
    vdev->desc[1].len = count * dev->sector_size;
    vdev->desc[1].flags = VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT;
    vdev->desc[1].next = 2;

    /* Descriptor 2: status byte */
    status = 0xFF;
    vdev->desc[2].addr = (uint64_t)virt_to_phys(&status);
    vdev->desc[2].len = 1;
    vdev->desc[2].flags = VIRTQ_DESC_F_WRITE;
    vdev->desc[2].next = 0;

    /* Add to available ring */
    vdev->avail->ring[vdev->avail->idx % VIRTQ_SIZE] = 0;
    __sync_synchronize();
    vdev->avail->idx++;

    /* Notify device */
    mmio_write32(vdev->mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    /* Wait for interrupt (sleep!) */
    while (vdev->last_used_idx == vdev->used->idx) {
        struct process *curr = proc_current();
        wait_queue_add(&vdev->io_wait, curr);
        curr->state = PROC_SLEEPING;
        curr->wait_channel = &vdev->io_wait;
        
        mutex_unlock(&vdev->lock);
        schedule();
        mutex_lock(&vdev->lock);
    }

    vdev->last_used_idx++;
    int ret = (status == VIRTIO_BLK_S_OK) ? 0 : -EIO;
    
    mutex_unlock(&vdev->lock);
    return ret;
}

/**
 * virtio_blk_write - Write sectors to virtio block device
 */
static int virtio_blk_write(struct blkdev *dev, uint64_t lba, const void *buf, size_t count) {
    struct virtio_blk_dev *vdev = dev->private;
    struct virtio_blk_req req;
    uint8_t status;

    if (!vdev || !buf) return -EINVAL;

    mutex_lock(&vdev->lock);

    req.type = VIRTIO_BLK_T_OUT;
    req.reserved = 0;
    req.sector = lba;

    vdev->desc[0].addr = (uint64_t)virt_to_phys(&req);
    vdev->desc[0].len = sizeof(req);
    vdev->desc[0].flags = VIRTQ_DESC_F_NEXT;
    vdev->desc[0].next = 1;

    vdev->desc[1].addr = (uint64_t)virt_to_phys((void *)buf);
    vdev->desc[1].len = count * dev->sector_size;
    vdev->desc[1].flags = VIRTQ_DESC_F_NEXT;
    vdev->desc[1].next = 2;

    status = 0xFF;
    vdev->desc[2].addr = (uint64_t)virt_to_phys(&status);
    vdev->desc[2].len = 1;
    vdev->desc[2].flags = VIRTQ_DESC_F_WRITE;
    vdev->desc[2].next = 0;

    vdev->avail->ring[vdev->avail->idx % VIRTQ_SIZE] = 0;
    __sync_synchronize();
    vdev->avail->idx++;

    mmio_write32(vdev->mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    while (vdev->last_used_idx == vdev->used->idx) {
        struct process *curr = proc_current();
        wait_queue_add(&vdev->io_wait, curr);
        curr->state = PROC_SLEEPING;
        curr->wait_channel = &vdev->io_wait;
        
        mutex_unlock(&vdev->lock);
        schedule();
        mutex_lock(&vdev->lock);
    }

    vdev->last_used_idx++;
    int ret = (status == VIRTIO_BLK_S_OK) ? 0 : -EIO;
    
    mutex_unlock(&vdev->lock);
    return ret;
}

static struct blkdev_ops virtio_blk_ops = {
    .read = virtio_blk_read,
    .write = virtio_blk_write,
    .flush = NULL,
};

/**
 * virtio_blk_init - Initialize VirtIO block device
 */
int virtio_blk_init(uint64_t mmio_addr) {
    struct virtio_blk_dev *vdev;
    uint32_t magic, version, device_id;
    uint64_t capacity;
    int ret = 0;

    volatile uint32_t *base = (volatile uint32_t *)mmio_addr;

    magic = mmio_read32(base, VIRTIO_MMIO_MAGIC_VALUE);
    if (magic != 0x74726976) return -ENODEV;

    version = mmio_read32(base, VIRTIO_MMIO_VERSION);
    if (version < 1 || version > 2) return -ENODEV;

    device_id = mmio_read32(base, VIRTIO_MMIO_DEVICE_ID);
    if (device_id != VIRTIO_ID_BLOCK) return -ENODEV;

    vdev = kzalloc(sizeof(*vdev));
    if (!vdev) return -ENOMEM;

    vdev->mmio_base = base;
    vdev->last_used_idx = 0;
    mutex_init(&vdev->lock, "virtio_blk");
    wait_queue_init(&vdev->io_wait);
    
    /* Calculate IRQ based on address: 0x10001000 -> 1, 0x10008000 -> 8 */
    vdev->irq = (int)((mmio_addr - 0x10000000UL) >> 12);

    /* Reset device */
    mmio_write32(base, VIRTIO_MMIO_STATUS, 0);
    mmio_write32(base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    /* Allocate virtqueue */
    mmio_write32(base, VIRTIO_MMIO_QUEUE_SEL, 0);
    vdev->desc = kzalloc(VIRTQ_SIZE * sizeof(struct virtq_desc));
    vdev->avail = kzalloc(sizeof(struct virtq_avail));
    vdev->used = kzalloc(sizeof(struct virtq_used));

    if (!vdev->desc || !vdev->avail || !vdev->used) { ret = -ENOMEM; goto err; }

    mmio_write32(base, VIRTIO_MMIO_QUEUE_NUM, VIRTQ_SIZE);
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DESC_LOW, (uint32_t)(uint64_t)virt_to_phys(vdev->desc));
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DESC_HIGH, (uint32_t)((uint64_t)virt_to_phys(vdev->desc) >> 32));
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DRIVER_LOW, (uint32_t)(uint64_t)virt_to_phys(vdev->avail));
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DRIVER_HIGH, (uint32_t)((uint64_t)virt_to_phys(vdev->avail) >> 32));
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DEVICE_LOW, (uint32_t)(uint64_t)virt_to_phys(vdev->used));
    mmio_write32(base, VIRTIO_MMIO_QUEUE_DEVICE_HIGH, (uint32_t)((uint64_t)virt_to_phys(vdev->used) >> 32));
    mmio_write32(base, VIRTIO_MMIO_QUEUE_READY, 1);

    mmio_write32(base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

    capacity = mmio_read32(base, VIRTIO_MMIO_CONFIG);
    capacity |= (uint64_t)mmio_read32(base, VIRTIO_MMIO_CONFIG + 4) << 32;

    vdev->blkdev.sector_count = capacity;
    vdev->blkdev.sector_size = 512;
    vdev->blkdev.ops = &virtio_blk_ops;
    vdev->blkdev.private = vdev;
    strncpy(vdev->blkdev.name, "vda", sizeof(vdev->blkdev.name));
    vdev->blkdev.name[2] += (char)(vdev->irq - 1);

    /* Register IRQ */
    arch_irq_register(vdev->irq, virtio_blk_intr, vdev);

    ret = blkdev_register(&vdev->blkdev);
    if (ret < 0) goto err;

    if (!virtio_disk) virtio_disk = vdev;
    pr_info("virtio-blk: registered %s at IRQ %d\n", vdev->blkdev.name, vdev->irq);
    return 0;

err:
    kfree(vdev->desc); kfree(vdev->avail); kfree(vdev->used); kfree(vdev);
    return ret;
}

void virtio_blk_probe(void) {
    uint64_t addrs[] = { 0x10001000, 0x10008000 };
    for (size_t i = 0; i < ARRAY_SIZE(addrs); i++) virtio_blk_init(addrs[i]);
}