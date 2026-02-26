/**
 * kernel/drivers/virtio/virtio_ring.c - VirtQueue Ring Management
 */

#include <kairos/virtio.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/io.h>
#include <kairos/printk.h>

static void virtqueue_init_free_list(struct virtqueue *vq) {
    vq->free_head = 0;
    vq->free_count = (uint16_t)vq->num;
    for (uint32_t i = 0; i < vq->num; i++) {
        vq->free_next[i] = (uint16_t)((i + 1) % vq->num);
    }
}

struct virtqueue *virtqueue_alloc(struct virtio_device *vdev, uint32_t index,
                                  uint32_t num) {
    if (!vdev || num == 0)
        return NULL;

    struct virtqueue *vq = kzalloc(sizeof(*vq));
    if (!vq)
        return NULL;

    vq->vdev = vdev;
    vq->index = index;
    vq->num = num;

    size_t desc_sz = ALIGN_UP(num * sizeof(struct virtq_desc), CONFIG_PAGE_SIZE);
    size_t avail_sz = ALIGN_UP(sizeof(struct virtq_avail) +
                                   num * sizeof(uint16_t),
                               CONFIG_PAGE_SIZE);
    size_t used_sz = ALIGN_UP(sizeof(struct virtq_used) +
                                  num * sizeof(struct virtq_used_elem),
                              CONFIG_PAGE_SIZE);

    vq->desc_size = desc_sz;
    vq->avail_size = avail_sz;
    vq->used_size = used_sz;
    vq->desc = dma_alloc_coherent(&vdev->dev, desc_sz, &vq->desc_dma);
    vq->avail = dma_alloc_coherent(&vdev->dev, avail_sz, &vq->avail_dma);
    vq->used = dma_alloc_coherent(&vdev->dev, used_sz, &vq->used_dma);
    vq->free_next = kzalloc(num * sizeof(uint16_t));
    vq->cookies = kzalloc(num * sizeof(void *));

    if (!vq->desc || !vq->avail || !vq->used || !vq->free_next || !vq->cookies) {
        if (vq->desc)
            dma_free_coherent(&vdev->dev, vq->desc, desc_sz, vq->desc_dma);
        if (vq->avail)
            dma_free_coherent(&vdev->dev, vq->avail, avail_sz, vq->avail_dma);
        if (vq->used)
            dma_free_coherent(&vdev->dev, vq->used, used_sz, vq->used_dma);
        kfree(vq->free_next);
        kfree(vq->cookies);
        kfree(vq);
        return NULL;
    }

    spin_init(&vq->lock);
    wait_queue_init(&vq->wq);
    virtqueue_init_free_list(vq);

    return vq;
}

void virtqueue_free(struct virtqueue *vq) {
    if (!vq)
        return;
    dma_free_coherent(&vq->vdev->dev, vq->desc, vq->desc_size, vq->desc_dma);
    dma_free_coherent(&vq->vdev->dev, vq->avail, vq->avail_size, vq->avail_dma);
    dma_free_coherent(&vq->vdev->dev, vq->used, vq->used_size, vq->used_dma);
    kfree(vq->free_next);
    kfree(vq->cookies);
    kfree(vq);
}

static int virtqueue_alloc_desc(struct virtqueue *vq, uint16_t *idx) {
    if (vq->free_count == 0)
        return -ENOSPC;
    *idx = vq->free_head;
    vq->free_head = vq->free_next[*idx];
    vq->free_count--;
    return 0;
}

static void virtqueue_free_desc_chain(struct virtqueue *vq, uint16_t head) {
    uint16_t idx = head;
    while (1) {
        uint16_t next = vq->desc[idx].next;
        vq->free_next[idx] = vq->free_head;
        vq->free_head = idx;
        vq->free_count++;
        if (!(vq->desc[idx].flags & VIRTQ_DESC_F_NEXT))
            break;
        idx = next;
    }
}

int virtqueue_add_buf(struct virtqueue *vq, struct virtq_desc *descs,
                      uint32_t count, void *cookie) {
    if (!vq || !descs || count == 0)
        return -EINVAL;

    spin_lock(&vq->lock);
    if (vq->free_count < count) {
        spin_unlock(&vq->lock);
        return -ENOSPC;
    }

    uint16_t head = 0;
    uint16_t prev = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint16_t idx;
        if (virtqueue_alloc_desc(vq, &idx) < 0) {
            spin_unlock(&vq->lock);
            return -ENOSPC;
        }
        vq->desc[idx] = descs[i];
        if (i == 0) {
            head = idx;
        } else {
            vq->desc[prev].flags |= VIRTQ_DESC_F_NEXT;
            vq->desc[prev].next = idx;
        }
        prev = idx;
    }
    vq->desc[prev].flags &= (uint16_t)~VIRTQ_DESC_F_NEXT;
    vq->desc[prev].next = 0;

    vq->cookies[head] = cookie;

    mb();
    vq->avail->ring[vq->avail->idx % vq->num] = head;
    mb();
    vq->avail->idx++;
    spin_unlock(&vq->lock);

    return 0;
}

void virtqueue_kick(struct virtqueue *vq) {
    mb();
    vq->vdev->ops->notify(vq);
}

void *virtqueue_get_buf(struct virtqueue *vq, uint32_t *len) {
    if (!vq)
        return NULL;
    if (vq->last_used_idx == virtqueue_used_idx(vq))
        return NULL;

    struct virtq_used_elem *uep = &vq->used->ring[vq->last_used_idx % vq->num];
    if (len)
        *len = uep->len;

    uint16_t head = (uint16_t)uep->id;
    void *cookie = vq->cookies[head];
    vq->cookies[head] = NULL;

    spin_lock(&vq->lock);
    virtqueue_free_desc_chain(vq, head);
    spin_unlock(&vq->lock);

    vq->last_used_idx++;
    return cookie;
}
