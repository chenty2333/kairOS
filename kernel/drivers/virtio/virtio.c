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

struct bus_type virtio_bus_type = {
    .name = "virtio",
    .match = virtio_bus_match,
};

int virtio_register_driver(struct virtio_driver *vdrv) {
    vdrv->drv.bus = &virtio_bus_type;
    vdrv->drv.probe = virtio_drv_probe;
    return driver_register(&vdrv->drv);
}

int virtio_device_register(struct virtio_device *vdev) {
    vdev->dev.bus = &virtio_bus_type;
    INIT_LIST_HEAD(&vdev->vqs);
    return device_register(&vdev->dev);
}