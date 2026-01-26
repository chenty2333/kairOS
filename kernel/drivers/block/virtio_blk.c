/**
 * kernel/drivers/block/virtio_blk.c - VirtIO Block Device Driver
 */

#include <kairos/virtio.h>
#include <kairos/blkdev.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/wait.h>
#include <kairos/dma.h>

#define VIRTQ_SIZE 16

#define VIRTIO_BLK_T_IN  0
#define VIRTIO_BLK_T_OUT 1
#define VIRTIO_BLK_S_OK  0

struct virtio_blk_req {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} __packed;

struct virtio_blk_dev {
    struct virtio_device *vdev;
    struct virtqueue *vq;
    struct mutex lock;
    struct wait_queue io_wait;
    struct blkdev blkdev;
};

static void virtio_blk_intr(struct virtio_device *vdev) {
    struct virtio_blk_dev *vb = vdev->priv;
    wait_queue_wakeup_all(&vb->io_wait);
}

static int virtio_blk_transfer(struct blkdev *dev, uint64_t lba, void *buf, size_t count, int write) {
    struct virtio_blk_dev *vb = dev->private;
    struct virtio_blk_req req;
    uint8_t status = 0xFF;

    mutex_lock(&vb->lock);

    req.type = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    req.reserved = 0;
    req.sector = lba;

    struct virtq_desc descs[3];
    descs[0].addr = dma_map_single(&req, sizeof(req), DMA_TO_DEVICE);
    descs[0].len = sizeof(req);
    descs[0].flags = VIRTQ_DESC_F_NEXT;
    descs[0].next = 1;

    descs[1].addr = dma_map_single(buf, count * 512, write ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
    descs[1].len = count * 512;
    descs[1].flags = (write ? 0 : VIRTQ_DESC_F_WRITE) | VIRTQ_DESC_F_NEXT;
    descs[1].next = 2;

    descs[2].addr = dma_map_single(&status, 1, DMA_FROM_DEVICE);
    descs[2].len = 1;
    descs[2].flags = VIRTQ_DESC_F_WRITE;
    descs[2].next = 0;

    virtqueue_add_buf(vb->vq, descs, 3, vb);
    virtqueue_kick(vb->vq);

    // Wait for completion
    while (vb->vq->last_used_idx == vb->vq->used->idx) {
        struct process *curr = proc_current();
        wait_queue_add(&vb->io_wait, curr);
        curr->state = PROC_SLEEPING;
        mutex_unlock(&vb->lock);
        schedule();
        mutex_lock(&vb->lock);
    }
    
    // Consume the used buffer
    virtqueue_get_buf(vb->vq, NULL);

    mutex_unlock(&vb->lock);
    return (status == VIRTIO_BLK_S_OK) ? 0 : -EIO;
}

static int virtio_blk_read(struct blkdev *dev, uint64_t lba, void *buf, size_t count) {
    return virtio_blk_transfer(dev, lba, buf, count, 0);
}

static int virtio_blk_write(struct blkdev *dev, uint64_t lba, const void *buf, size_t count) {
    return virtio_blk_transfer(dev, lba, (void *)buf, count, 1);
}

static struct blkdev_ops virtio_blk_ops = {
    .read = virtio_blk_read,
    .write = virtio_blk_write
};

struct virtio_blk_config {
    uint64_t capacity;
} __packed;

static int virtio_blk_probe(struct virtio_device *vdev) {
    struct virtio_blk_dev *vb = kzalloc(sizeof(*vb));
    if (!vb) return -ENOMEM;

    vb->vdev = vdev;
    vdev->priv = vb;
    vdev->handler = virtio_blk_intr;

    mutex_init(&vb->lock, "virtio_blk");
    wait_queue_init(&vb->io_wait);

    /* 1. Reset device */
    vdev->ops->set_status(vdev, 0);
    vdev->ops->set_status(vdev, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    /* 2. Setup VirtQueue */
    vb->vq = kzalloc(sizeof(struct virtqueue));
    vb->vq->vdev = vdev;
    vb->vq->index = 0;
    vb->vq->num = VIRTQ_SIZE;
    vb->vq->desc = kzalloc(VIRTQ_SIZE * sizeof(struct virtq_desc));
    vb->vq->avail = kzalloc(sizeof(struct virtq_avail) + VIRTQ_SIZE * sizeof(uint16_t));
    vb->vq->used = kzalloc(sizeof(struct virtq_used) + VIRTQ_SIZE * sizeof(struct virtq_used_elem));
    
    vdev->ops->setup_vq(vdev, 0, vb->vq);

    /* 3. Finalize features */
    vdev->ops->finalize_features(vdev, 0); // No special features for now
    vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_FEATURES_OK);
    vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_DRIVER_OK);

    /* 4. Get config */
    struct virtio_blk_config config;
    vdev->ops->get_config(vdev, 0, &config, sizeof(config));

    /* 5. Register block device */
    vb->blkdev.sector_count = config.capacity;
    vb->blkdev.sector_size = 512;
    vb->blkdev.ops = &virtio_blk_ops;
    vb->blkdev.private = vb;
    
    static int disk_count = 0;
    snprintf(vb->blkdev.name, sizeof(vb->blkdev.name), "vd%c", 'a' + disk_count++);

    blkdev_register(&vb->blkdev);
    pr_info("virtio-blk: registered %s, capacity %lu sectors\n", vb->blkdev.name, (unsigned long)config.capacity);

    return 0;
}

struct virtio_driver virtio_blk_driver = {
    .drv = { .name = "virtio-blk" },
    .device_id = 2, // Block device
    .probe = virtio_blk_probe,
};