/**
 * kernel/drivers/virtio/virtio_ring.c - VirtQueue Ring Management
 */

#include <kairos/virtio.h>
#include <kairos/mm.h>
#include <kairos/io.h>

int virtqueue_add_buf(struct virtqueue *vq, struct virtq_desc *descs, uint32_t count, void *data) {
    (void)data;
    // For simplicity, we assume we use descriptors starting from 0 
    // and that the driver handles descriptor management.
    // In a full implementation, we'd have a free list of descriptors.
    
    for (uint32_t i = 0; i < count; i++) {
        vq->desc[i] = descs[i];
    }

    vq->avail->ring[vq->avail->idx % vq->num] = 0; // Head of chain
    mb();
    vq->avail->idx++;
    return 0;
}

void virtqueue_kick(struct virtqueue *vq) {
    mb();
    vq->vdev->ops->notify(vq);
}

void *virtqueue_get_buf(struct virtqueue *vq, uint32_t *len) {
    if (vq->last_used_idx == vq->used->idx) {
        return NULL;
    }

    struct virtq_used_elem *uep = &vq->used->ring[vq->last_used_idx % vq->num];
    if (len) *len = uep->len;
    
    vq->last_used_idx++;
    return (void *)0x1; // Return dummy non-NULL for now, real drivers need the cookie
}
