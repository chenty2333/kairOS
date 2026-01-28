/**
 * kernel/include/kairos/virtio.h - VirtIO Bus & Core Definitions
 */

#ifndef _KAIROS_VIRTIO_H
#define _KAIROS_VIRTIO_H

#include <kairos/device.h>
#include <kairos/io.h>
#include <kairos/types.h>
#include <kairos/list.h>

/* VirtQueue Structures */
struct virtq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __packed;

#define VIRTQ_DESC_F_NEXT    1
#define VIRTQ_DESC_F_WRITE   2
#define VIRTQ_DESC_F_INDIRECT 4

struct virtq_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
    /* uint16_t used_event; -- optional */
} __packed;

struct virtq_used_elem {
    uint32_t id;
    uint32_t len;
} __packed;

struct virtq_used {
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[];
    /* uint16_t avail_event; -- optional */
} __packed;

/* VirtQueue Object */
struct virtqueue {
    struct virtio_device *vdev;
    uint32_t index;
    uint32_t num;
    struct virtq_desc *desc;
    struct virtq_avail *avail;
    struct virtq_used *used;
    uint16_t last_used_idx;
    void *priv;
    struct list_head list;
};

static inline uint16_t virtqueue_used_idx(struct virtqueue *vq) {
    rmb();
    return *(volatile uint16_t *)&vq->used->idx;
}

/* VirtIO Device Configuration Operations */
struct virtio_device;
struct virtio_config_ops {
    uint8_t (*get_status)(struct virtio_device *vdev);
    void (*set_status)(struct virtio_device *vdev, uint8_t status);
    uint64_t (*get_features)(struct virtio_device *vdev);
    void (*finalize_features)(struct virtio_device *vdev, uint64_t features);
    int (*setup_vq)(struct virtio_device *vdev, uint32_t index, struct virtqueue *vq);
    void (*notify)(struct virtqueue *vq);
    void (*get_config)(struct virtio_device *vdev, uint32_t offset, void *buf, uint32_t len);
};

/* VirtIO Device */
struct virtio_device {
    struct device dev;          /* Base device */
    uint32_t id;                /* VirtIO device ID (e.g., 2 for block) */
    struct virtio_config_ops *ops;
    void (*handler)(struct virtio_device *vdev); /* Interrupt handler */
    void *priv;                 /* Transport private data */
    struct list_head vqs;       /* List of virtqueues */
};

#define to_virtio_device(d) container_of(d, struct virtio_device, dev)

/* VirtIO Driver */
struct virtio_driver {
    struct driver drv;
    uint32_t device_id;         /* ID this driver supports */
    int (*probe)(struct virtio_device *vdev);
    void (*remove)(struct virtio_device *vdev);
};

#define to_virtio_driver(d) container_of(d, struct virtio_driver, drv)

/* Bus and Registration */
extern struct bus_type virtio_bus_type;
int virtio_register_driver(struct virtio_driver *vdrv);
int virtio_device_register(struct virtio_device *vdev);

/* VirtQueue API */
int virtqueue_add_buf(struct virtqueue *vq, struct virtq_desc *descs, uint32_t count, void *data);
void virtqueue_kick(struct virtqueue *vq);
void *virtqueue_get_buf(struct virtqueue *vq, uint32_t *len);

/* Status bits */
#define VIRTIO_STATUS_ACKNOWLEDGE       1
#define VIRTIO_STATUS_DRIVER            2
#define VIRTIO_STATUS_DRIVER_OK         4
#define VIRTIO_STATUS_FEATURES_OK       8
#define VIRTIO_STATUS_NEEDS_RESET       64
#define VIRTIO_STATUS_FAILED            128

#endif
