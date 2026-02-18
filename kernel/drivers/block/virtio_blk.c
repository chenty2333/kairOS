/**
 * kernel/drivers/block/virtio_blk.c - VirtIO Block Device Driver
 */

#include <kairos/config.h>
#include <kairos/arch.h>
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

struct virtio_blk_req_ctx {
    struct virtio_blk_req hdr;
    uint8_t status;
    bool done;
    paddr_t dma_hdr;
    paddr_t dma_buf;
    paddr_t dma_status;
    size_t byte_len;
};

struct virtio_blk_dev {
    struct virtio_device *vdev;
    struct virtqueue *vq;
    struct mutex lock;
    struct wait_queue io_wait;
    struct blkdev blkdev;
    bool irq_seen;
};

static void virtio_blk_handle_used(struct virtio_blk_dev *vb) {
    if (!vb || !vb->vq)
        return;

    while (vb->vq->last_used_idx != virtqueue_used_idx(vb->vq)) {
        struct virtio_blk_req_ctx *ctx = virtqueue_get_buf(vb->vq, NULL);
        if (ctx)
            __atomic_store_n(&ctx->done, true, __ATOMIC_RELEASE);
    }
}

static void virtio_blk_intr(struct virtio_device *vdev) {
    struct virtio_blk_dev *vb = vdev->priv;
    if (!vb || !vb->vq)
        return;
    vb->irq_seen = true;
    virtio_blk_handle_used(vb);
    wait_queue_wakeup_all(&vb->io_wait);
}

static int virtio_blk_transfer(struct blkdev *dev, uint64_t lba, void *buf,
                               size_t count, int write) {
    struct virtio_blk_dev *vb = dev->private;
    if (!vb || !vb->vq || !buf || count == 0)
        return -EINVAL;

    if (lba + count > dev->sector_count)
        return -EINVAL;

    /* Heap-allocate ctx to avoid DMA from stack addresses */
    struct virtio_blk_req_ctx *ctx = kzalloc(sizeof(*ctx));
    if (!ctx)
        return -ENOMEM;
    ctx->hdr.type = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    ctx->hdr.reserved = 0;
    ctx->hdr.sector = lba;
    ctx->byte_len = count * dev->sector_size;

    struct virtq_desc descs[3];
    ctx->dma_hdr = dma_map_single(&ctx->hdr, sizeof(ctx->hdr), DMA_TO_DEVICE);
    descs[0].addr = ctx->dma_hdr;
    descs[0].len = sizeof(ctx->hdr);
    descs[0].flags = VIRTQ_DESC_F_NEXT;
    descs[0].next = 0;

    ctx->dma_buf = dma_map_single(buf, ctx->byte_len,
                                 write ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
    descs[1].addr = ctx->dma_buf;
    descs[1].len = (uint32_t)ctx->byte_len;
    descs[1].flags = (write ? 0 : VIRTQ_DESC_F_WRITE) | VIRTQ_DESC_F_NEXT;
    descs[1].next = 0;

    ctx->dma_status = dma_map_single(&ctx->status, 1, DMA_FROM_DEVICE);
    descs[2].addr = ctx->dma_status;
    descs[2].len = 1;
    descs[2].flags = VIRTQ_DESC_F_WRITE;
    descs[2].next = 0;

    mutex_lock(&vb->lock);
    int ret = virtqueue_add_buf(vb->vq, descs, 3, ctx);
    if (ret < 0) {
        mutex_unlock(&vb->lock);
        dma_unmap_single(ctx->dma_hdr, sizeof(ctx->hdr), DMA_TO_DEVICE);
        dma_unmap_single(ctx->dma_buf, ctx->byte_len,
                         write ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
        dma_unmap_single(ctx->dma_status, 1, DMA_FROM_DEVICE);
        kfree(ctx);
        return ret;
    }
    virtqueue_kick(vb->vq);

    struct process *curr = proc_current();
    bool can_sleep = arch_irq_enabled() &&
                     curr && curr != arch_get_percpu()->idle_proc &&
                     vb->irq_seen;
    if (!can_sleep) {
        while (!__atomic_load_n(&ctx->done, __ATOMIC_ACQUIRE)) {
            virtio_blk_handle_used(vb);
            arch_cpu_relax();
        }
    } else {
        while (!__atomic_load_n(&ctx->done, __ATOMIC_ACQUIRE)) {
            int rc = proc_sleep_on_mutex(&vb->io_wait, &vb->io_wait,
                                         &vb->lock, true);
            if (rc == -EINTR && !__atomic_load_n(&ctx->done, __ATOMIC_ACQUIRE))
                continue;
        }
    }

    mutex_unlock(&vb->lock);

    dma_unmap_single(ctx->dma_hdr, sizeof(ctx->hdr), DMA_TO_DEVICE);
    dma_unmap_single(ctx->dma_buf, ctx->byte_len,
                     write ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
    dma_unmap_single(ctx->dma_status, 1, DMA_FROM_DEVICE);

    int status = (ctx->status == VIRTIO_BLK_S_OK) ? 0 : -EIO;
    kfree(ctx);
    return status;
}

static int virtio_blk_read(struct blkdev *dev, uint64_t lba, void *buf,
                           size_t count) {
    return virtio_blk_transfer(dev, lba, buf, count, 0);
}

static int virtio_blk_write(struct blkdev *dev, uint64_t lba, const void *buf,
                            size_t count) {
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
    if (!vb)
        return -ENOMEM;

    vb->vdev = vdev;
    vdev->priv = vb;
    vdev->handler = virtio_blk_intr;

    mutex_init(&vb->lock, "virtio_blk");
    wait_queue_init(&vb->io_wait);
    vb->irq_seen = false;

    if (virtio_device_init(vdev, 0) < 0) {
        kfree(vb);
        return -EIO;
    }

    vb->vq = virtqueue_alloc(vdev, 0, VIRTQ_SIZE);
    if (!vb->vq) {
        virtio_device_set_failed(vdev);
        kfree(vb);
        return -ENOMEM;
    }
    if (vdev->ops->setup_vq(vdev, 0, vb->vq) < 0) {
        virtio_device_set_failed(vdev);
        virtqueue_free(vb->vq);
        kfree(vb);
        return -ENODEV;
    }

    if (virtio_device_ready(vdev) < 0) {
        virtio_device_set_failed(vdev);
        virtqueue_free(vb->vq);
        kfree(vb);
        return -EIO;
    }

    struct virtio_blk_config config;
    vdev->ops->get_config(vdev, 0, &config, sizeof(config));

    vb->blkdev.sector_count = config.capacity;
    vb->blkdev.sector_size = 512;
    vb->blkdev.ops = &virtio_blk_ops;
    vb->blkdev.private = vb;

    static int disk_count = 0;
    snprintf(vb->blkdev.name, sizeof(vb->blkdev.name), "vd%c",
             'a' + disk_count++);

    if (blkdev_register(&vb->blkdev) < 0) {
        virtqueue_free(vb->vq);
        kfree(vb);
        return -EIO;
    }

    pr_info("virtio-blk: registered %s, capacity %lu sectors\n", vb->blkdev.name,
            (unsigned long)config.capacity);

    return 0;
}

struct virtio_driver virtio_blk_driver = {
    .drv = { .name = "virtio-blk" },
    .device_id = 2,
    .probe = virtio_blk_probe,
};
