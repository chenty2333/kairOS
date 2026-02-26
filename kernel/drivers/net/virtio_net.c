/**
 * kernel/drivers/net/virtio_net.c - Minimal VirtIO network driver
 */

#include <kairos/config.h>
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

void lwip_netif_input(const void *data, size_t len);

/* VirtIO net header (legacy 10-byte layout). */
struct virtio_net_hdr {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} __packed;

struct virtio_net_tx_slot {
    struct virtio_net_hdr hdr;
    uint8_t data[NET_BUF_SIZE];
    bool in_use;
    dma_addr_t dma_hdr;
    dma_addr_t dma_data;
    uint32_t len;
};

struct virtio_net_rx_slot {
    struct virtio_net_hdr hdr;
    uint8_t data[NET_BUF_SIZE];
    dma_addr_t dma_buf;
};

struct virtio_net_cookie {
    uint16_t idx;
    uint8_t type; /* 0 = TX, 1 = RX */
};

struct virtio_net_dev {
    struct virtio_device *vdev;
    struct virtqueue *rx_vq;
    struct virtqueue *tx_vq;
    struct mutex lock;
    struct wait_queue tx_wait;
    struct wait_queue rx_wait;
    struct virtio_net_tx_slot tx_slots[VIRTQ_SIZE];
    struct virtio_net_rx_slot rx_slots[VIRTQ_SIZE];
    struct virtio_net_cookie tx_cookie[VIRTQ_SIZE];
    struct virtio_net_cookie rx_cookie[VIRTQ_SIZE];
    struct netdev netdev;
};

static void virtio_net_rx_deliver(struct virtio_net_rx_slot *slot, uint32_t len) {
    if (!slot || len <= sizeof(struct virtio_net_hdr))
        return;

    uint32_t payload_len = len - (uint32_t)sizeof(struct virtio_net_hdr);
    if (payload_len > NET_BUF_SIZE) {
        pr_warn("virtio-net: rx payload too large (%u), truncating\n",
                payload_len);
        payload_len = NET_BUF_SIZE;
    }

    lwip_netif_input(slot->data, payload_len);
    pr_debug("virtio-net: rx packet len=%u\n", payload_len);
}

#if CONFIG_KERNEL_TESTS
int virtio_net_test_rx_deliver_len(uint32_t len) {
    struct virtio_net_rx_slot slot;
    memset(&slot, 0, sizeof(slot));
    if (len > sizeof(slot))
        len = sizeof(slot);
    if (len > sizeof(struct virtio_net_hdr))
        memset(slot.data, 0x5a, len - sizeof(struct virtio_net_hdr));
    virtio_net_rx_deliver(&slot, len);
    return 0;
}
#endif

static int virtio_net_post_rx(struct virtio_net_dev *vn, uint16_t idx) {
    struct virtq_desc desc;
    struct virtio_net_rx_slot *slot = &vn->rx_slots[idx];

    desc.addr = dma_map_single(&vn->vdev->dev, &slot->hdr, sizeof(*slot),
                               DMA_FROM_DEVICE);
    desc.len = sizeof(*slot);
    desc.flags = VIRTQ_DESC_F_WRITE;
    desc.next = 0;
    slot->dma_buf = desc.addr;

    vn->rx_cookie[idx].idx = idx;
    vn->rx_cookie[idx].type = 1;

    int ret = virtqueue_add_buf(vn->rx_vq, &desc, 1, &vn->rx_cookie[idx]);
    if (ret == 0) {
        virtqueue_kick(vn->rx_vq);
    } else {
        dma_unmap_single(&vn->vdev->dev, slot->dma_buf, sizeof(*slot),
                         DMA_FROM_DEVICE);
    }
    return ret;
}

static void virtio_net_intr(struct virtio_device *vdev) {
    struct virtio_net_dev *vn = vdev->priv;
    if (!vn)
        return;

    /* TX completion */
    while (vn->tx_vq->last_used_idx != virtqueue_used_idx(vn->tx_vq)) {
        struct virtio_net_cookie *cookie = virtqueue_get_buf(vn->tx_vq, NULL);
        if (cookie && cookie->type == 0 && cookie->idx < VIRTQ_SIZE) {
            struct virtio_net_tx_slot *slot = &vn->tx_slots[cookie->idx];
            if (slot->in_use) {
                dma_unmap_single(&vn->vdev->dev, slot->dma_hdr,
                                 sizeof(slot->hdr), DMA_TO_DEVICE);
                dma_unmap_single(&vn->vdev->dev, slot->dma_data, slot->len,
                                 DMA_TO_DEVICE);
                slot->in_use = false;
            }
        }
    }
    wait_queue_wakeup_all(&vn->tx_wait);

    /* RX completion */
    while (vn->rx_vq->last_used_idx != virtqueue_used_idx(vn->rx_vq)) {
        uint32_t len = 0;
        struct virtio_net_cookie *cookie = virtqueue_get_buf(vn->rx_vq, &len);
        if (cookie && cookie->type == 1 && cookie->idx < VIRTQ_SIZE) {
            struct virtio_net_rx_slot *slot = &vn->rx_slots[cookie->idx];
            dma_unmap_single(&vn->vdev->dev, slot->dma_buf, sizeof(*slot),
                             DMA_FROM_DEVICE);
            virtio_net_rx_deliver(slot, len);
            virtio_net_post_rx(vn, cookie->idx);
        }
    }
    wait_queue_wakeup_all(&vn->rx_wait);
}

static int virtio_net_xmit(struct netdev *dev, const void *data, size_t len) {
    struct virtio_net_dev *vn = dev ? (struct virtio_net_dev *)dev->priv : NULL;
    if (!vn || !data || len == 0 || len > NET_BUF_SIZE)
        return -EINVAL;

    mutex_lock(&vn->lock);

    uint16_t slot_idx = VIRTQ_SIZE;
    for (;;) {
        for (uint16_t i = 0; i < VIRTQ_SIZE; i++) {
            if (!vn->tx_slots[i].in_use) {
                slot_idx = i;
                vn->tx_slots[i].in_use = true;
                break;
            }
        }
        if (slot_idx < VIRTQ_SIZE)
            break;

        struct process *curr = proc_current();
        if (!curr) {
            mutex_unlock(&vn->lock);
            return -EAGAIN;
        }
        int rc = proc_sleep_on_mutex(&vn->tx_wait, &vn->tx_wait,
                                     &vn->lock, true);
        if (rc == -EINTR) {
            mutex_unlock(&vn->lock);
            return -EINTR;
        }
    }

    struct virtio_net_tx_slot *slot = &vn->tx_slots[slot_idx];
    memset(&slot->hdr, 0, sizeof(slot->hdr));
    memcpy(slot->data, data, len);
    slot->len = (uint32_t)len;

    struct virtq_desc descs[2];
    slot->dma_hdr = dma_map_single(&vn->vdev->dev, &slot->hdr,
                                   sizeof(slot->hdr), DMA_TO_DEVICE);
    descs[0].addr = slot->dma_hdr;
    descs[0].len = sizeof(slot->hdr);
    descs[0].flags = VIRTQ_DESC_F_NEXT;
    descs[0].next = 0;

    slot->dma_data = dma_map_single(&vn->vdev->dev, slot->data, len,
                                    DMA_TO_DEVICE);
    descs[1].addr = slot->dma_data;
    descs[1].len = (uint32_t)len;
    descs[1].flags = 0;
    descs[1].next = 0;

    vn->tx_cookie[slot_idx].idx = slot_idx;
    vn->tx_cookie[slot_idx].type = 0;

    int ret = virtqueue_add_buf(vn->tx_vq, descs, 2, &vn->tx_cookie[slot_idx]);
    if (ret < 0) {
        dma_unmap_single(&vn->vdev->dev, slot->dma_hdr, sizeof(slot->hdr),
                         DMA_TO_DEVICE);
        dma_unmap_single(&vn->vdev->dev, slot->dma_data, slot->len,
                         DMA_TO_DEVICE);
        slot->in_use = false;
        mutex_unlock(&vn->lock);
        return ret;
    }

    virtqueue_kick(vn->tx_vq);
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

    if (virtio_device_init(vdev, 0) < 0) {
        ret = -EIO;
        goto err;
    }

    vn->rx_vq = virtqueue_alloc(vdev, 0, VIRTQ_SIZE);
    vn->tx_vq = virtqueue_alloc(vdev, 1, VIRTQ_SIZE);
    if (!vn->rx_vq || !vn->tx_vq) {
        virtio_device_set_failed(vdev);
        ret = -ENOMEM;
        goto err;
    }

    if (vdev->ops->setup_vq(vdev, 0, vn->rx_vq) < 0) {
        virtio_device_set_failed(vdev);
        ret = -ENODEV;
        goto err;
    }
    if (vdev->ops->setup_vq(vdev, 1, vn->tx_vq) < 0) {
        virtio_device_set_failed(vdev);
        ret = -ENODEV;
        goto err;
    }

    if (virtio_device_ready(vdev) < 0) {
        virtio_device_set_failed(vdev);
        ret = -EIO;
        goto err;
    }

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

    for (uint16_t i = 0; i < VIRTQ_SIZE; i++) {
        if (virtio_net_post_rx(vn, i) < 0) {
            pr_warn("virtio-net: rx post failed on slot %u\n", i);
        }
    }

    pr_info("virtio-net: registered %s\n", vn->netdev.name);
    return 0;

err:
    if (vn->tx_vq)
        virtqueue_free(vn->tx_vq);
    if (vn->rx_vq)
        virtqueue_free(vn->rx_vq);
    kfree(vn);
    vdev->priv = NULL;
    return ret;
}

struct virtio_driver virtio_net_driver = {
    .drv = { .name = "virtio-net" },
    .device_id = 1,
    .probe = virtio_net_probe,
};
