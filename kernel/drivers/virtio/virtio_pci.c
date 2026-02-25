/**
 * kernel/drivers/virtio/virtio_pci.c - VirtIO PCI transport (modern caps)
 */

#include <kairos/arch.h>
#include <kairos/io.h>
#include <kairos/mm.h>
#include <kairos/pci.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/virtio.h>

#define VIRTIO_PCI_VENDOR_ID 0x1af4

#define VIRTIO_PCI_CAP_COMMON_CFG 1
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_ISR_CFG    3
#define VIRTIO_PCI_CAP_DEVICE_CFG 4

#define VIRTIO_PCI_COMMON_DEVICE_FEATURE_SELECT 0x00
#define VIRTIO_PCI_COMMON_DEVICE_FEATURE        0x04
#define VIRTIO_PCI_COMMON_DRIVER_FEATURE_SELECT 0x08
#define VIRTIO_PCI_COMMON_DRIVER_FEATURE        0x0c
#define VIRTIO_PCI_COMMON_DEVICE_STATUS         0x14
#define VIRTIO_PCI_COMMON_QUEUE_SELECT          0x16
#define VIRTIO_PCI_COMMON_QUEUE_SIZE            0x18
#define VIRTIO_PCI_COMMON_QUEUE_ENABLE          0x1c
#define VIRTIO_PCI_COMMON_QUEUE_NOTIFY_OFF      0x1e
#define VIRTIO_PCI_COMMON_QUEUE_DESC            0x20
#define VIRTIO_PCI_COMMON_QUEUE_DRIVER          0x28
#define VIRTIO_PCI_COMMON_QUEUE_DEVICE          0x30

struct virtio_pci_transport {
    struct virtio_device vdev;
    struct pci_device *pdev;
    void *common_cfg;
    void *notify_cfg;
    void *isr_cfg;
    void *device_cfg;
    uint32_t notify_off_multiplier;
    int irq;
};

#define to_vp(v) container_of(v, struct virtio_pci_transport, vdev)

static uint32_t virtio_pci_to_device_id(uint16_t pci_device_id) {
    if (pci_device_id >= 0x1000 && pci_device_id <= 0x103f)
        return (uint32_t)pci_device_id - 0x0fff;
    if (pci_device_id >= 0x1040 && pci_device_id <= 0x107f)
        return (uint32_t)pci_device_id - 0x1040;
    return 0;
}

static void *virtio_pci_map_cap(struct pci_device *pdev, uint8_t bar,
                                uint32_t offset, uint32_t length) {
    if (!pdev || bar >= PCI_MAX_BAR || length == 0)
        return NULL;

    uint64_t bar_base = pdev->bar[bar];
    uint64_t bar_size = pdev->bar_size[bar];
    if (!bar_base || !bar_size || offset >= bar_size)
        return NULL;

    uint64_t avail = bar_size - offset;
    size_t map_len = (length < avail) ? (size_t)length : (size_t)avail;
    if (map_len == 0)
        return NULL;

    return ioremap((paddr_t)(bar_base + offset), map_len);
}

static int virtio_pci_read_cap(struct pci_device *pdev, uint8_t cap_ptr,
                               uint8_t *cfg_type, uint8_t *bar,
                               uint32_t *offset, uint32_t *length,
                               uint32_t *notify_mult) {
    uint8_t cap_len = 0;
    if (pci_dev_read_config_8(pdev, (uint16_t)(cap_ptr + 2), &cap_len) < 0)
        return -EIO;
    if (cap_len < 16)
        return -EINVAL;

    if (pci_dev_read_config_8(pdev, (uint16_t)(cap_ptr + 3), cfg_type) < 0)
        return -EIO;
    if (pci_dev_read_config_8(pdev, (uint16_t)(cap_ptr + 4), bar) < 0)
        return -EIO;
    if (pci_dev_read_config_32(pdev, (uint16_t)(cap_ptr + 8), offset) < 0)
        return -EIO;
    if (pci_dev_read_config_32(pdev, (uint16_t)(cap_ptr + 12), length) < 0)
        return -EIO;

    if (notify_mult)
        *notify_mult = 0;
    if (*cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG && notify_mult) {
        if (cap_len < 20)
            return -EINVAL;
        if (pci_dev_read_config_32(pdev, (uint16_t)(cap_ptr + 16),
                                   notify_mult) < 0) {
            return -EIO;
        }
    }

    return 0;
}

static int virtio_pci_find_caps(struct virtio_pci_transport *vp) {
    uint16_t status = 0;
    if (pci_dev_read_config_16(vp->pdev, PCI_STATUS, &status) < 0)
        return -EIO;
    if (!(status & PCI_STATUS_CAP_LIST))
        return -ENODEV;

    uint8_t cap = 0;
    if (pci_dev_read_config_8(vp->pdev, PCI_CAP_PTR, &cap) < 0)
        return -EIO;

    for (int guard = 0; guard < 64 && cap >= 0x40; guard++) {
        uint8_t cap_id = 0;
        uint8_t next = 0;
        if (pci_dev_read_config_8(vp->pdev, cap, &cap_id) < 0)
            return -EIO;
        if (pci_dev_read_config_8(vp->pdev, (uint16_t)(cap + 1), &next) < 0)
            return -EIO;

        if (cap_id == PCI_CAP_ID_VNDR) {
            uint8_t cfg_type = 0;
            uint8_t bar = 0;
            uint32_t offset = 0;
            uint32_t length = 0;
            uint32_t notify_mult = 0;

            if (virtio_pci_read_cap(vp->pdev, cap, &cfg_type, &bar, &offset,
                                    &length, &notify_mult) == 0) {
                void *mapped = virtio_pci_map_cap(vp->pdev, bar, offset, length);
                if (mapped) {
                    if (cfg_type == VIRTIO_PCI_CAP_COMMON_CFG &&
                        !vp->common_cfg) {
                        vp->common_cfg = mapped;
                    } else if (cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG &&
                               !vp->notify_cfg) {
                        vp->notify_cfg = mapped;
                        vp->notify_off_multiplier = notify_mult;
                    } else if (cfg_type == VIRTIO_PCI_CAP_ISR_CFG &&
                               !vp->isr_cfg) {
                        vp->isr_cfg = mapped;
                    } else if (cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG &&
                               !vp->device_cfg) {
                        vp->device_cfg = mapped;
                    }
                }
            }
        }
        if (!next || next == cap)
            break;
        cap = next;
    }

    if (!vp->common_cfg || !vp->notify_cfg || !vp->isr_cfg || !vp->device_cfg)
        return -ENODEV;
    if (vp->notify_off_multiplier == 0)
        return -EINVAL;

    return 0;
}

static uint8_t virtio_pci_get_status(struct virtio_device *vdev) {
    struct virtio_pci_transport *vp = to_vp(vdev);
    return readb((uint8_t *)vp->common_cfg + VIRTIO_PCI_COMMON_DEVICE_STATUS);
}

static void virtio_pci_set_status(struct virtio_device *vdev, uint8_t status) {
    struct virtio_pci_transport *vp = to_vp(vdev);
    writeb(status, (uint8_t *)vp->common_cfg + VIRTIO_PCI_COMMON_DEVICE_STATUS);
}

static uint64_t virtio_pci_get_features(struct virtio_device *vdev) {
    struct virtio_pci_transport *vp = to_vp(vdev);
    void *base = vp->common_cfg;

    writel(0, (uint8_t *)base + VIRTIO_PCI_COMMON_DEVICE_FEATURE_SELECT);
    uint64_t lo = readl((uint8_t *)base + VIRTIO_PCI_COMMON_DEVICE_FEATURE);
    writel(1, (uint8_t *)base + VIRTIO_PCI_COMMON_DEVICE_FEATURE_SELECT);
    uint64_t hi = readl((uint8_t *)base + VIRTIO_PCI_COMMON_DEVICE_FEATURE);

    return lo | (hi << 32);
}

static void virtio_pci_finalize_features(struct virtio_device *vdev,
                                         uint64_t features) {
    struct virtio_pci_transport *vp = to_vp(vdev);
    void *base = vp->common_cfg;

    writel(0, (uint8_t *)base + VIRTIO_PCI_COMMON_DRIVER_FEATURE_SELECT);
    writel((uint32_t)features, (uint8_t *)base + VIRTIO_PCI_COMMON_DRIVER_FEATURE);
    writel(1, (uint8_t *)base + VIRTIO_PCI_COMMON_DRIVER_FEATURE_SELECT);
    writel((uint32_t)(features >> 32),
           (uint8_t *)base + VIRTIO_PCI_COMMON_DRIVER_FEATURE);
}

static int virtio_pci_setup_vq(struct virtio_device *vdev, uint32_t index,
                               struct virtqueue *vq) {
    struct virtio_pci_transport *vp = to_vp(vdev);
    void *base = vp->common_cfg;

    writew((uint16_t)index, (uint8_t *)base + VIRTIO_PCI_COMMON_QUEUE_SELECT);
    uint16_t max = readw((uint8_t *)base + VIRTIO_PCI_COMMON_QUEUE_SIZE);
    if (!max)
        return -ENODEV;
    if (vq->num > max)
        vq->num = max;

    writew((uint16_t)vq->num, (uint8_t *)base + VIRTIO_PCI_COMMON_QUEUE_SIZE);

    paddr_t desc_pa = virt_to_phys(vq->desc);
    paddr_t avail_pa = virt_to_phys(vq->avail);
    paddr_t used_pa = virt_to_phys(vq->used);

    writeq(desc_pa, (uint8_t *)base + VIRTIO_PCI_COMMON_QUEUE_DESC);
    writeq(avail_pa, (uint8_t *)base + VIRTIO_PCI_COMMON_QUEUE_DRIVER);
    writeq(used_pa, (uint8_t *)base + VIRTIO_PCI_COMMON_QUEUE_DEVICE);
    writew(1, (uint8_t *)base + VIRTIO_PCI_COMMON_QUEUE_ENABLE);

    return 0;
}

static void virtio_pci_notify(struct virtqueue *vq) {
    struct virtio_pci_transport *vp = to_vp(vq->vdev);
    void *base = vp->common_cfg;

    writew((uint16_t)vq->index, (uint8_t *)base + VIRTIO_PCI_COMMON_QUEUE_SELECT);
    uint16_t off = readw((uint8_t *)base + VIRTIO_PCI_COMMON_QUEUE_NOTIFY_OFF);
    uint32_t byte_off = (uint32_t)off * vp->notify_off_multiplier;
    writel(vq->index, (uint8_t *)vp->notify_cfg + byte_off);
}

static void virtio_pci_get_config(struct virtio_device *vdev, uint32_t offset,
                                  void *buf, uint32_t len) {
    struct virtio_pci_transport *vp = to_vp(vdev);
    uint8_t *dst = buf;
    uint8_t *src = (uint8_t *)vp->device_cfg + offset;
    for (uint32_t i = 0; i < len; i++)
        dst[i] = readb(src + i);
}

static struct virtio_config_ops virtio_pci_ops = {
    .get_status = virtio_pci_get_status,
    .set_status = virtio_pci_set_status,
    .get_features = virtio_pci_get_features,
    .finalize_features = virtio_pci_finalize_features,
    .setup_vq = virtio_pci_setup_vq,
    .notify = virtio_pci_notify,
    .get_config = virtio_pci_get_config,
};

static void virtio_pci_intr(void *arg) {
    struct virtio_pci_transport *vp = arg;
    if (!vp)
        return;
    if (vp->isr_cfg && readb(vp->isr_cfg) == 0)
        return;
    if (vp->vdev.handler)
        vp->vdev.handler(&vp->vdev);
}

static int virtio_pci_probe(struct pci_device *pdev) {
    if (!pdev || pdev->vendor_id != VIRTIO_PCI_VENDOR_ID)
        return -ENODEV;

    uint32_t virtio_id = virtio_pci_to_device_id(pdev->device_id);
    if (virtio_id == 0)
        return -ENODEV;

    struct virtio_pci_transport *vp = kzalloc(sizeof(*vp));
    if (!vp)
        return -ENOMEM;

    vp->pdev = pdev;
    vp->irq = (int)pdev->irq_line;

    int ret = pci_dev_enable_bus_master(pdev);
    if (ret < 0) {
        pr_warn("virtio-pci: failed to enable bus master (%02x:%02x.%x, ret=%d)\n",
                pdev->bus, pdev->slot, pdev->func, ret);
    }

    ret = virtio_pci_find_caps(vp);
    if (ret < 0) {
        kfree(vp);
        return ret;
    }

    int msi_ret = pci_enable_msi(pdev);
    if (msi_ret == 0) {
        vp->irq = (int)pdev->irq_line;
    } else if (msi_ret != -ENOENT && msi_ret != -EOPNOTSUPP) {
        pr_warn("virtio-pci: MSI setup failed on %02x:%02x.%x (ret=%d), fallback INTx\n",
                pdev->bus, pdev->slot, pdev->func, msi_ret);
    }

    vp->vdev.id = virtio_id;
    vp->vdev.ops = &virtio_pci_ops;
    snprintf(vp->vdev.dev.name, sizeof(vp->vdev.dev.name), "virtio-pci-%02x:%02x.%x",
             pdev->bus, pdev->slot, pdev->func);

    if (vp->irq > 0) {
        arch_irq_register(vp->irq, virtio_pci_intr, vp);
    }

    dev_set_drvdata(&pdev->dev, vp);
    ret = virtio_device_register(&vp->vdev);
    if (ret < 0) {
        dev_set_drvdata(&pdev->dev, NULL);
        kfree(vp);
        return ret;
    }

    pr_info("virtio-pci: %02x:%02x.%x device_id=0x%04x virtio_id=%u irq=%d (%s)\n",
            pdev->bus, pdev->slot, pdev->func, pdev->device_id,
            virtio_id, vp->irq, pdev->msi_enabled ? "msi" : "intx");
    return 0;
}

static void virtio_pci_remove(struct pci_device *pdev) {
    if (!pdev)
        return;
    struct virtio_pci_transport *vp = dev_get_drvdata(&pdev->dev);
    if (!vp)
        return;
    if (vp->irq > 0)
        arch_irq_disable_nr(vp->irq);
    if (pdev->msi_enabled)
        (void)pci_disable_msi(pdev);
    device_unregister(&vp->vdev.dev);
    dev_set_drvdata(&pdev->dev, NULL);
    kfree(vp);
}

struct pci_driver virtio_pci_driver = {
    .drv = { .name = "virtio-pci" },
    .vendor_id = VIRTIO_PCI_VENDOR_ID,
    .device_id = PCI_ANY_ID,
    .probe = virtio_pci_probe,
    .remove = virtio_pci_remove,
};
