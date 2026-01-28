/**
 * kernel/drivers/net/virtio_net.c - Minimal VirtIO network driver
 */

#include <kairos/dma.h>
#include <kairos/mm.h>
#include <kairos/net.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/virtio.h>
#include <kairos/wait.h>

#define VIRTQ_SIZE 16
#define NET_BUF_SIZE 2048

/* VirtIO net header (legacy 10-byte layout). */
struct virtio_net_hdr {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} __packed;

struct virtio_net_buf {
    struct virtio_net_hdr hdr;
    uint8_t data[NET_BUF_SIZE];
};

struct virtio_net_dev {
    struct virtio_device *vdev;
    struct virtqueue *rx_vq;
    struct virtqueue *tx_vq;
    struct mutex lock;
    struct wait_queue tx_wait;
    struct wait_queue rx_wait;
    struct virtio_net_buf rx_buf;
    struct virtio_net_hdr tx_hdr;
    uint8_t tx_data[NET_BUF_SIZE];
    struct netdev netdev;
};

static struct virtqueue *virtio_net_alloc_vq(struct virtio_device *vdev,
                                             uint32_t index) {
    struct virtqueue *vq = kzalloc(sizeof(*vq));
    if (!vq)
        return NULL;
    vq->vdev = vdev;
    vq->index = index;
    vq->num = VIRTQ_SIZE;
    vq->desc = kzalloc(VIRTQ_SIZE * sizeof(struct virtq_desc));
    vq->avail =
        kzalloc(sizeof(struct virtq_avail) + VIRTQ_SIZE * sizeof(uint16_t));
    vq->used = kzalloc(sizeof(struct virtq_used) +
                       VIRTQ_SIZE * sizeof(struct virtq_used_elem));
    if (!vq->desc || !vq->avail || !vq->used) {
        kfree(vq->desc);
        kfree(vq->avail);
        kfree(vq->used);
        kfree(vq);
        return NULL;
    }
    return vq;
}

static void virtio_net_free_vq(struct virtqueue *vq) {
    if (!vq)
        return;
    kfree(vq->desc);
    kfree(vq->avail);
    kfree(vq->used);
    kfree(vq);
}

static int virtio_net_post_rx(struct virtio_net_dev *vn) {
    struct virtq_desc desc;
    desc.addr = dma_map_single(&vn->rx_buf, sizeof(vn->rx_buf), DMA_FROM_DEVICE);
    desc.len = sizeof(vn->rx_buf);
    desc.flags = VIRTQ_DESC_F_WRITE;
    desc.next = 0;
    int ret = virtqueue_add_buf(vn->rx_vq, &desc, 1, vn);
    if (ret == 0)
        virtqueue_kick(vn->rx_vq);
    return ret;
}

static void virtio_net_intr(struct virtio_device *vdev) {
    struct virtio_net_dev *vn = vdev->priv;

    /* TX completion */
    while (vn->tx_vq->last_used_idx != virtqueue_used_idx(vn->tx_vq)) {
        virtqueue_get_buf(vn->tx_vq, NULL);
        wait_queue_wakeup_all(&vn->tx_wait);
    }

    /* RX completion: consume one buffer and repost it. */
    while (vn->rx_vq->last_used_idx != virtqueue_used_idx(vn->rx_vq)) {
        uint32_t len = 0;
        virtqueue_get_buf(vn->rx_vq, &len);
        wait_queue_wakeup_all(&vn->rx_wait);
        virtio_net_post_rx(vn);
        if (len > sizeof(struct virtio_net_hdr)) {
            pr_debug("virtio-net: rx packet len=%u\n",
                     len - (uint32_t)sizeof(struct virtio_net_hdr));
        }
    }
}

static int virtio_net_xmit(struct netdev *dev, const void *data, size_t len) {
    struct virtio_net_dev *vn = dev ? (struct virtio_net_dev *)dev->priv : NULL;
    if (!vn || !data || len == 0 || len > NET_BUF_SIZE)
        return -EINVAL;

    mutex_lock(&vn->lock);
    memset(&vn->tx_hdr, 0, sizeof(vn->tx_hdr));
    memcpy(vn->tx_data, data, len);

    struct virtq_desc descs[2];
    descs[0].addr = dma_map_single(&vn->tx_hdr, sizeof(vn->tx_hdr), DMA_TO_DEVICE);
    descs[0].len = sizeof(vn->tx_hdr);
    descs[0].flags = VIRTQ_DESC_F_NEXT;
    descs[0].next = 1;

    descs[1].addr = dma_map_single(vn->tx_data, len, DMA_TO_DEVICE);
    descs[1].len = (uint32_t)len;
    descs[1].flags = 0;
    descs[1].next = 0;

    virtqueue_add_buf(vn->tx_vq, descs, 2, vn);
    virtqueue_kick(vn->tx_vq);

    while (vn->tx_vq->last_used_idx == virtqueue_used_idx(vn->tx_vq)) {
        struct process *curr = proc_current();
        wait_queue_add(&vn->tx_wait, curr);
        curr->state = PROC_SLEEPING;
        curr->wait_channel = &vn->tx_wait;
        mutex_unlock(&vn->lock);
        schedule();
        mutex_lock(&vn->lock);
    }

    virtqueue_get_buf(vn->tx_vq, NULL);
    mutex_unlock(&vn->lock);
    return 0;
}

static const struct netdev_ops virtio_net_ops = {
    .xmit = virtio_net_xmit,
};

static int virtio_net_probe(struct virtio_device *vdev) {
    int ret = -ENOMEM;
    struct virtio_net_dev *vn = kzalloc(sizeof(*vn));
    if (!vn)
        return -ENOMEM;

    vn->vdev = vdev;
    vdev->priv = vn;
    vdev->handler = virtio_net_intr;

    mutex_init(&vn->lock, "virtio_net");
    wait_queue_init(&vn->tx_wait);
    wait_queue_init(&vn->rx_wait);

    vdev->ops->set_status(vdev, 0);
    vdev->ops->set_status(vdev, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    vn->rx_vq = virtio_net_alloc_vq(vdev, 0);
    vn->tx_vq = virtio_net_alloc_vq(vdev, 1);
    if (!vn->rx_vq || !vn->tx_vq) {
        vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_FAILED);
        ret = -ENOMEM;
        goto err;
    }

    if (vdev->ops->setup_vq(vdev, 0, vn->rx_vq) < 0) {
        vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_FAILED);
        ret = -ENODEV;
        goto err;
    }
    if (vdev->ops->setup_vq(vdev, 1, vn->tx_vq) < 0) {
        vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_FAILED);
        ret = -ENODEV;
        goto err;
    }

    vdev->ops->finalize_features(vdev, 0);
    vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_FEATURES_OK);
    vdev->ops->set_status(vdev, vdev->ops->get_status(vdev) | VIRTIO_STATUS_DRIVER_OK);

    uint8_t mac[6] = {0};
    vdev->ops->get_config(vdev, 0, mac, sizeof(mac));

    static int net_count = 0;
    snprintf(vn->netdev.name, sizeof(vn->netdev.name), "eth%d", net_count++);
    memcpy(vn->netdev.mac, mac, sizeof(mac));
    vn->netdev.mtu = 1500;
    vn->netdev.ops = &virtio_net_ops;
    vn->netdev.priv = vn;
    INIT_LIST_HEAD(&vn->netdev.list);
    netdev_register(&vn->netdev);

    virtio_net_post_rx(vn);
    pr_info("virtio-net: registered %s\n", vn->netdev.name);
    return 0;

err:
    if (vn->tx_vq)
        virtio_net_free_vq(vn->tx_vq);
    if (vn->rx_vq)
        virtio_net_free_vq(vn->rx_vq);
    kfree(vn);
    vdev->priv = NULL;
    return ret;
}

struct virtio_driver virtio_net_driver = {
    .drv = { .name = "virtio-net" },
    .device_id = 1,
    .probe = virtio_net_probe,
};
