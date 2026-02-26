/**
 * kernel/drivers/virtio/virtio_mmio.c - VirtIO MMIO Transport
 */

#include <kairos/virtio.h>
#include <kairos/arch.h>
#include <kairos/platform.h>
#include <kairos/platform_irq.h>
#include <kairos/platform_core.h>
#include <kairos/io.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>

/* VirtIO MMIO Registers */
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
#define VIRTIO_MMIO_QUEUE_DESC_HIGH      0x084
#define VIRTIO_MMIO_QUEUE_DRIVER_LOW    0x090
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH   0x094
#define VIRTIO_MMIO_QUEUE_DEVICE_LOW    0x0a0
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH   0x0a4
#define VIRTIO_MMIO_CONFIG              0x100

struct virtio_mmio_device {
    struct virtio_device vdev;
    void *base;
    int irq;
};

#define to_mmio_vdev(v) container_of(v, struct virtio_mmio_device, vdev)

static uint8_t mmio_get_status(struct virtio_device *vdev) {
    return (uint8_t)readl(to_mmio_vdev(vdev)->base + VIRTIO_MMIO_STATUS);
}

static void mmio_set_status(struct virtio_device *vdev, uint8_t status) {
    writel(status, to_mmio_vdev(vdev)->base + VIRTIO_MMIO_STATUS);
}

static uint64_t mmio_get_features(struct virtio_device *vdev) {
    void *base = to_mmio_vdev(vdev)->base;
    writel(0, base + VIRTIO_MMIO_DEVICE_FEATURES); // Low 32 bits
    uint64_t features = readl(base + VIRTIO_MMIO_DEVICE_FEATURES);
    // For VirtIO 1.0+, we might need high bits, but let's keep it simple
    return features;
}

static void mmio_finalize_features(struct virtio_device *vdev, uint64_t features) {
    void *base = to_mmio_vdev(vdev)->base;
    writel(0, base + VIRTIO_MMIO_DRIVER_FEATURES);
    writel((uint32_t)features, base + VIRTIO_MMIO_DRIVER_FEATURES);
    // Set FEATURES_OK status here? No, driver does that.
}

static int mmio_setup_vq(struct virtio_device *vdev, uint32_t index, struct virtqueue *vq) {
    void *base = to_mmio_vdev(vdev)->base;
    
    writel(index, base + VIRTIO_MMIO_QUEUE_SEL);
    if (readl(base + VIRTIO_MMIO_QUEUE_READY)) return -EBUSY;

    uint32_t max_num = readl(base + VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (vq->num > max_num) vq->num = max_num;

    writel(vq->num, base + VIRTIO_MMIO_QUEUE_NUM);
    
    paddr_t desc_pa = virt_to_phys(vq->desc);
    paddr_t avail_pa = virt_to_phys(vq->avail);
    paddr_t used_pa = virt_to_phys(vq->used);

    writel((uint32_t)desc_pa, base + VIRTIO_MMIO_QUEUE_DESC_LOW);
    writel((uint32_t)(desc_pa >> 32), base + VIRTIO_MMIO_QUEUE_DESC_HIGH);
    writel((uint32_t)avail_pa, base + VIRTIO_MMIO_QUEUE_DRIVER_LOW);
    writel((uint32_t)(avail_pa >> 32), base + VIRTIO_MMIO_QUEUE_DRIVER_HIGH);
    writel((uint32_t)used_pa, base + VIRTIO_MMIO_QUEUE_DEVICE_LOW);
    writel((uint32_t)(used_pa >> 32), base + VIRTIO_MMIO_QUEUE_DEVICE_HIGH);
    
    writel(1, base + VIRTIO_MMIO_QUEUE_READY);
    return 0;
}

static void mmio_notify(struct virtqueue *vq) {
    struct virtio_mmio_device *mdev = to_mmio_vdev(vq->vdev);
    writel(vq->index, mdev->base + VIRTIO_MMIO_QUEUE_NOTIFY);
}

static void mmio_get_config(struct virtio_device *vdev, uint32_t offset, void *buf, uint32_t len) {
    void *base = to_mmio_vdev(vdev)->base + VIRTIO_MMIO_CONFIG;
    uint8_t *ptr = buf;
    for (uint32_t i = 0; i < len; i++) {
        ptr[i] = readb(base + offset + i);
    }
}

static struct virtio_config_ops mmio_ops = {
    .get_status = mmio_get_status,
    .set_status = mmio_set_status,
    .get_features = mmio_get_features,
    .finalize_features = mmio_finalize_features,
    .setup_vq = mmio_setup_vq,
    .notify = mmio_notify,
    .get_config = mmio_get_config,
};

static void virtio_mmio_intr(void *arg) {
    struct virtio_mmio_device *mdev = arg;
    void *base = mdev->base;

    /* Read and acknowledge interrupt */
    uint32_t status = readl(base + VIRTIO_MMIO_INTERRUPT_STATUS);
    writel(status, base + VIRTIO_MMIO_INTERRUPT_ACK);

    if (mdev->vdev.handler) {
        mdev->vdev.handler(&mdev->vdev);
    }
}

static int virtio_mmio_probe(struct device *dev) {
    void *base = dev_ioremap_resource(dev, 0);
    int irq = platform_device_get_irq(dev, 0);

    if (!base || irq < 0)
        return -ENODEV;
    if (readl(base + VIRTIO_MMIO_MAGIC_VALUE) != 0x74726976)
        return -ENODEV;
    
    uint32_t virtio_id = readl(base + VIRTIO_MMIO_DEVICE_ID);
    if (virtio_id == 0)
        return -ENODEV; /* Reserved */

    struct virtio_mmio_device *mdev = kzalloc(sizeof(*mdev));
    if (!mdev) return -ENOMEM;

    mdev->base = base;
    mdev->irq = irq;
    mdev->vdev.id = virtio_id;
    mdev->vdev.ops = &mmio_ops;
    dev_set_drvdata(dev, mdev);
    
    snprintf(mdev->vdev.dev.name, sizeof(mdev->vdev.dev.name), "virtio-mmio.%p", base);
    
    /* Register physical interrupt */
    (void)platform_device_request_irq(dev, 0, virtio_mmio_intr, mdev,
                                      IRQ_FLAG_TRIGGER_LEVEL);

    pr_info("virtio-mmio: found device %d at %p, irq %d\n", virtio_id, base, mdev->irq);

    int ret = virtio_device_register(&mdev->vdev);
    if (ret < 0) {
        dev_set_drvdata(dev, NULL);
        iounmap(base);
        kfree(mdev);
        return ret;
    }
    return 0;
}

static void virtio_mmio_remove(struct device *dev) {
    struct virtio_mmio_device *mdev = dev_get_drvdata(dev);
    if (!mdev)
        return;

    (void)platform_device_free_irq(dev, 0, virtio_mmio_intr, mdev);
    device_unregister(&mdev->vdev.dev);
    dev_set_drvdata(dev, NULL);
    iounmap(mdev->base);
    kfree(mdev);
}

struct driver virtio_mmio_driver = {
    .name = "virtio-mmio",
    .compatible = "virtio,mmio",
    .bus = &platform_bus_type,
    .probe = virtio_mmio_probe,
    .remove = virtio_mmio_remove,
};
