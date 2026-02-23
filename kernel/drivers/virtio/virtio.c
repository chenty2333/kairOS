/**
 * kernel/drivers/virtio/virtio.c - VirtIO Bus Implementation
 */

#include <kairos/virtio.h>
#include <kairos/string.h>
#include <kairos/printk.h>

static int virtio_bus_match(struct device *dev, struct driver *drv) {
    struct virtio_device *vdev = (struct virtio_device *)dev;
    struct virtio_driver *vdrv = container_of(drv, struct virtio_driver, drv);
    
    return vdev->id == vdrv->device_id;
}

/* 
 * Wrapper to translate generic device probe to virtio-specific probe 
 */
static int virtio_drv_probe(struct device *dev) {
    struct virtio_device *vdev = (struct virtio_device *)dev;
    struct virtio_driver *vdrv = container_of(dev->driver, struct virtio_driver, drv);
    
    return vdrv->probe(vdev);
}

static void virtio_drv_remove(struct device *dev) {
    struct virtio_device *vdev = (struct virtio_device *)dev;
    struct virtio_driver *vdrv = container_of(dev->driver, struct virtio_driver, drv);

    if (vdrv->remove)
        vdrv->remove(vdev);
}

struct bus_type virtio_bus_type = {
    .name = "virtio",
    .match = virtio_bus_match,
};

int virtio_register_driver(struct virtio_driver *vdrv) {
    vdrv->drv.bus = &virtio_bus_type;
    vdrv->drv.probe = virtio_drv_probe;
    vdrv->drv.remove = virtio_drv_remove;
    return driver_register(&vdrv->drv);
}

int virtio_device_register(struct virtio_device *vdev) {
    vdev->dev.bus = &virtio_bus_type;
    INIT_LIST_HEAD(&vdev->vqs);
    return device_register(&vdev->dev);
}

int virtio_device_init(struct virtio_device *vdev, uint64_t driver_features) {
    if (!vdev || !vdev->ops)
        return -EINVAL;

    vdev->ops->set_status(vdev, 0);
    vdev->ops->set_status(vdev, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    vdev->ops->finalize_features(vdev, driver_features);
    vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_FEATURES_OK);

    uint8_t status = vdev->ops->get_status(vdev);
    if (!(status & VIRTIO_STATUS_FEATURES_OK)) {
        vdev->ops->set_status(vdev, status | VIRTIO_STATUS_FAILED);
        return -EIO;
    }
    return 0;
}

int virtio_device_ready(struct virtio_device *vdev) {
    if (!vdev || !vdev->ops)
        return -EINVAL;
    vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_DRIVER_OK);
    return 0;
}

void virtio_device_set_failed(struct virtio_device *vdev) {
    if (!vdev || !vdev->ops)
        return;
    vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_FAILED);
}
