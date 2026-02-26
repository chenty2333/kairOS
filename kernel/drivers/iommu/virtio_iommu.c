/**
 * kernel/drivers/iommu/virtio_iommu.c - VirtIO IOMMU backend provider
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/dma.h>
#include <kairos/iommu.h>
#include <kairos/mm.h>
#include <kairos/pci.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/virtio.h>

#define VIRTIO_ID_IOMMU 23U

#define VIRTIO_IOMMU_F_INPUT_RANGE  0
#define VIRTIO_IOMMU_F_DOMAIN_RANGE 1
#define VIRTIO_IOMMU_F_MAP_UNMAP    2

#define VIRTIO_IOMMU_T_ATTACH 1U
#define VIRTIO_IOMMU_T_DETACH 2U
#define VIRTIO_IOMMU_T_MAP    3U
#define VIRTIO_IOMMU_T_UNMAP  4U

#define VIRTIO_IOMMU_S_OK    0U
#define VIRTIO_IOMMU_S_INVAL 1U
#define VIRTIO_IOMMU_S_RANGE 2U
#define VIRTIO_IOMMU_S_NOENT 3U
#define VIRTIO_IOMMU_S_IOERR 4U

#define VIRTIO_IOMMU_MAP_F_READ  1U
#define VIRTIO_IOMMU_MAP_F_WRITE 2U

#define VIRTIO_IOMMU_REQ_VQ    0U
#define VIRTIO_IOMMU_REQ_DEPTH 16U
#define VIRTIO_IOMMU_REQ_TIMEOUT_NS (2ULL * 1000ULL * 1000ULL * 1000ULL)

struct virtio_iommu_config {
    uint64_t page_size_mask;
    uint64_t input_range_start;
    uint64_t input_range_end;
    uint32_t domain_range_start;
    uint32_t domain_range_end;
    uint32_t probe_size;
    uint8_t bypass;
    uint8_t reserved[3];
} __packed;

struct virtio_iommu_req_head {
    uint8_t type;
    uint8_t reserved[3];
} __packed;

struct virtio_iommu_req_tail {
    uint8_t status;
    uint8_t reserved[3];
} __packed;

struct virtio_iommu_req_attach {
    struct virtio_iommu_req_head head;
    uint32_t domain;
    uint32_t endpoint;
    uint32_t reserved;
    struct virtio_iommu_req_tail tail;
} __packed;

struct virtio_iommu_req_detach {
    struct virtio_iommu_req_head head;
    uint32_t domain;
    uint32_t endpoint;
    uint32_t reserved;
    struct virtio_iommu_req_tail tail;
} __packed;

struct virtio_iommu_req_map {
    struct virtio_iommu_req_head head;
    uint32_t domain;
    uint32_t flags;
    uint64_t virt_start;
    uint64_t virt_end;
    uint64_t phys_start;
    struct virtio_iommu_req_tail tail;
} __packed;

struct virtio_iommu_req_unmap {
    struct virtio_iommu_req_head head;
    uint32_t domain;
    uint32_t reserved;
    uint64_t virt_start;
    uint64_t virt_end;
    struct virtio_iommu_req_tail tail;
} __packed;

struct virtio_iommu_req_cookie {
    struct device *dma_dev;
    void *req_buf;
    dma_addr_t req_dma;
    size_t req_size;
    uint32_t refs;
    volatile uint32_t done;
    uint32_t used_len;
};

struct virtio_iommu_state;

struct virtio_iommu_domain_ctx {
    struct list_head list;
    struct virtio_iommu_state *state;
    uint32_t domain_id;
    uint32_t endpoint;
};

struct virtio_iommu_state {
    struct virtio_device *vdev;
    struct virtqueue *req_vq;
    uint64_t page_size_mask;
    uint64_t input_start;
    uint64_t input_end;
    uint32_t domain_start;
    uint32_t domain_end;
    uint32_t next_domain;
    size_t granule;
    bool map_unmap;
    bool input_range;
    bool faulted;
    bool ready;
    uint64_t req_submit_count;
    uint64_t req_complete_count;
    uint64_t req_timeout_count;
    uint64_t req_error_count;
    uint8_t last_req_type;
    int32_t last_req_ret;
    uint8_t last_fault_req_type;
    int32_t last_fault_ret;
    uint64_t last_fault_ticks;
    spinlock_t req_lock;
    spinlock_t domain_lock;
    struct list_head domains;
};

static struct virtio_iommu_state virtio_iommu_state;
static const struct iommu_hw_ops virtio_iommu_hw_ops;

struct virtio_iommu_rebind_ctx {
    struct virtio_iommu_state *state;
    uint32_t attempted;
    uint32_t attached;
    uint32_t failed;
};

int virtio_iommu_health_snapshot(struct virtio_iommu_health *out) {
    if (!out)
        return -EINVAL;

    struct virtio_iommu_state *state = &virtio_iommu_state;
    memset(out, 0, sizeof(*out));
    out->ready = __atomic_load_n(&state->ready, __ATOMIC_ACQUIRE);
    out->faulted = __atomic_load_n(&state->faulted, __ATOMIC_ACQUIRE);
    out->req_submit_count =
        __atomic_load_n(&state->req_submit_count, __ATOMIC_RELAXED);
    out->req_complete_count =
        __atomic_load_n(&state->req_complete_count, __ATOMIC_RELAXED);
    out->req_timeout_count =
        __atomic_load_n(&state->req_timeout_count, __ATOMIC_RELAXED);
    out->req_error_count =
        __atomic_load_n(&state->req_error_count, __ATOMIC_RELAXED);
    out->last_req_type = __atomic_load_n(&state->last_req_type, __ATOMIC_RELAXED);
    out->last_req_ret = __atomic_load_n(&state->last_req_ret, __ATOMIC_RELAXED);
    out->last_fault_req_type =
        __atomic_load_n(&state->last_fault_req_type, __ATOMIC_RELAXED);
    out->last_fault_ret =
        __atomic_load_n(&state->last_fault_ret, __ATOMIC_RELAXED);
    out->last_fault_ticks =
        __atomic_load_n(&state->last_fault_ticks, __ATOMIC_RELAXED);
    return 0;
}

static size_t virtio_iommu_pick_granule(uint64_t page_size_mask) {
    for (uint64_t sz = CONFIG_PAGE_SIZE; sz != 0; sz <<= 1U) {
        if (page_size_mask & sz)
            return (size_t)sz;
        if (sz >= (1ULL << 52))
            break;
    }
    return 0;
}

static void virtio_iommu_req_cookie_put(struct virtio_iommu_req_cookie *cookie) {
    if (!cookie)
        return;
    if (__atomic_sub_fetch(&cookie->refs, 1, __ATOMIC_ACQ_REL) != 0)
        return;
    if (cookie->dma_dev && cookie->req_dma && cookie->req_size)
        dma_unmap_single(cookie->dma_dev, cookie->req_dma, cookie->req_size,
                         DMA_BIDIRECTIONAL);
    kfree(cookie->req_buf);
    kfree(cookie);
}

static int virtio_iommu_status_to_errno(uint8_t status) {
    switch (status) {
    case VIRTIO_IOMMU_S_OK:
        return 0;
    case VIRTIO_IOMMU_S_INVAL:
        return -EINVAL;
    case VIRTIO_IOMMU_S_RANGE:
        return -ERANGE;
    case VIRTIO_IOMMU_S_NOENT:
        return -ENOENT;
    case VIRTIO_IOMMU_S_IOERR:
    default:
        return -EIO;
    }
}

static void virtio_iommu_mark_faulted(struct virtio_iommu_state *state,
                                      uint8_t req_type, int ret) {
    if (!state)
        return;
    __atomic_store_n(&state->last_fault_req_type, req_type, __ATOMIC_RELAXED);
    __atomic_store_n(&state->last_fault_ret, ret, __ATOMIC_RELAXED);
    __atomic_store_n(&state->last_fault_ticks, arch_timer_ticks(),
                     __ATOMIC_RELAXED);
    if (__atomic_exchange_n(&state->faulted, true, __ATOMIC_ACQ_REL))
        return;

    iommu_unregister_hw_ops(&virtio_iommu_hw_ops);
    pr_warn("virtio-iommu: backend faulted req_type=%u ret=%d, provider disabled\n",
            req_type, ret);
}

static int virtio_iommu_endpoint_from_dev(struct device *dev, uint32_t *endpoint) {
    if (!dev || !endpoint)
        return -EINVAL;
    if (dev->bus != &pci_bus_type)
        return -ENODEV;

    struct pci_device *pdev = to_pci_device(dev);
    uint8_t base_class = (uint8_t)(pdev->class_code >> 16);
    if (base_class == 0x06)
        return -ENODEV;

    *endpoint = ((uint32_t)pdev->bus << 8) |
                ((uint32_t)pdev->slot << 3) |
                (uint32_t)pdev->func;
    return 0;
}

static bool virtio_iommu_domain_id_in_use_locked(struct virtio_iommu_state *state,
                                                  uint32_t domain_id) {
    struct virtio_iommu_domain_ctx *ctx;
    list_for_each_entry(ctx, &state->domains, list) {
        if (ctx->domain_id == domain_id)
            return true;
    }
    return false;
}

static int virtio_iommu_domain_id_alloc(struct virtio_iommu_state *state,
                                        struct virtio_iommu_domain_ctx *ctx) {
    if (!state || !ctx)
        return -EINVAL;
    if (state->domain_end < state->domain_start)
        return -EINVAL;

    uint32_t id = state->next_domain;
    if (id < state->domain_start || id > state->domain_end)
        id = state->domain_start;
    const uint32_t first = id;

    do {
        if (!virtio_iommu_domain_id_in_use_locked(state, id)) {
            ctx->domain_id = id;
            list_add_tail(&ctx->list, &state->domains);
            state->next_domain =
                (id == state->domain_end) ? state->domain_start : (id + 1U);
            return 0;
        }
        id = (id == state->domain_end) ? state->domain_start : (id + 1U);
    } while (id != first);

    return -ENOSPC;
}

static void virtio_iommu_domain_id_free(struct virtio_iommu_domain_ctx *ctx) {
    if (!ctx || !ctx->state)
        return;

    bool irq_flags;
    spin_lock_irqsave(&ctx->state->domain_lock, &irq_flags);
    if (!list_empty(&ctx->list)) {
        list_del(&ctx->list);
        INIT_LIST_HEAD(&ctx->list);
    }
    spin_unlock_irqrestore(&ctx->state->domain_lock, irq_flags);
}

static void virtio_iommu_drain_used_locked(struct virtio_iommu_state *state) {
    struct virtio_iommu_req_cookie *cookie;
    uint32_t len = 0;

    while ((cookie = virtqueue_get_buf(state->req_vq, &len)) != NULL) {
        cookie->used_len = len;
        __atomic_store_n(&cookie->done, 1, __ATOMIC_RELEASE);
        virtio_iommu_req_cookie_put(cookie);
    }
}

static int virtio_iommu_submit_req(struct virtio_iommu_state *state, void *req,
                                   size_t req_size, size_t write_desc_offset,
                                   uint8_t *status_out) {
    if (!state || !state->ready || state->faulted || !state->vdev ||
        !state->req_vq || !req || !req_size || write_desc_offset >= req_size) {
        return -EINVAL;
    }
    uint8_t req_type = *((uint8_t *)req);
    __atomic_add_fetch(&state->req_submit_count, 1, __ATOMIC_RELAXED);

    struct virtio_iommu_req_cookie *cookie = kzalloc(sizeof(*cookie));
    if (!cookie)
        return -ENOMEM;
    cookie->dma_dev = &state->vdev->dev;
    cookie->req_buf = kmalloc(req_size);
    if (!cookie->req_buf) {
        kfree(cookie);
        return -ENOMEM;
    }
    cookie->req_size = req_size;
    cookie->refs = 1;
    memcpy(cookie->req_buf, req, req_size);

    cookie->req_dma = dma_map_single(cookie->dma_dev, cookie->req_buf, req_size,
                                     DMA_BIDIRECTIONAL);
    if (!cookie->req_dma) {
        virtio_iommu_req_cookie_put(cookie);
        return -EIO;
    }

    struct virtq_desc desc[2];
    memset(desc, 0, sizeof(desc));
    desc[0].addr = cookie->req_dma;
    desc[0].len = (uint32_t)write_desc_offset;
    desc[0].flags = VIRTQ_DESC_F_NEXT;

    desc[1].addr = cookie->req_dma + (dma_addr_t)write_desc_offset;
    desc[1].len = (uint32_t)(req_size - write_desc_offset);
    desc[1].flags = VIRTQ_DESC_F_WRITE;

    int ret;
    int wait_ret = 0;
    uint64_t wait_start = arch_timer_ticks();
    uint64_t timeout_ticks = arch_timer_ns_to_ticks(VIRTIO_IOMMU_REQ_TIMEOUT_NS);
    if (timeout_ticks == 0)
        timeout_ticks = 1;
    bool irq_flags;
    spin_lock_irqsave(&state->req_lock, &irq_flags);

    virtio_iommu_drain_used_locked(state);
    while ((ret = virtqueue_add_buf(state->req_vq, desc, ARRAY_SIZE(desc),
                                    cookie)) == -ENOSPC) {
        virtio_iommu_drain_used_locked(state);
        arch_cpu_relax();
    }

    if (ret == 0) {
        __atomic_add_fetch(&cookie->refs, 1, __ATOMIC_ACQ_REL);
        virtqueue_kick(state->req_vq);
        while (!__atomic_load_n(&cookie->done, __ATOMIC_ACQUIRE)) {
            virtio_iommu_drain_used_locked(state);
            if ((arch_timer_ticks() - wait_start) > timeout_ticks) {
                wait_ret = -ETIMEDOUT;
                break;
            }
            arch_cpu_relax();
        }
    }

    spin_unlock_irqrestore(&state->req_lock, irq_flags);
    if (ret < 0) {
        __atomic_add_fetch(&state->req_error_count, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&state->last_req_type, req_type, __ATOMIC_RELAXED);
        __atomic_store_n(&state->last_req_ret, ret, __ATOMIC_RELAXED);
        virtio_iommu_req_cookie_put(cookie);
        return ret;
    }

    if (wait_ret < 0) {
        __atomic_add_fetch(&state->req_timeout_count, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&state->req_error_count, 1, __ATOMIC_RELAXED);
        pr_warn("virtio-iommu: request timeout type=%u\n",
                *((uint8_t *)cookie->req_buf));
        __atomic_store_n(&state->last_req_type, req_type, __ATOMIC_RELAXED);
        __atomic_store_n(&state->last_req_ret, wait_ret, __ATOMIC_RELAXED);
        virtio_iommu_mark_faulted(state, req_type, wait_ret);
        virtio_iommu_req_cookie_put(cookie);
        return wait_ret;
    }

    uint8_t status = *((uint8_t *)cookie->req_buf + req_size -
                       sizeof(struct virtio_iommu_req_tail));
    if (status_out)
        *status_out = status;
    __atomic_add_fetch(&state->req_complete_count, 1, __ATOMIC_RELAXED);
    virtio_iommu_req_cookie_put(cookie);
    int req_ret = virtio_iommu_status_to_errno(status);
    if (req_ret < 0)
        __atomic_add_fetch(&state->req_error_count, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&state->last_req_type, req_type, __ATOMIC_RELAXED);
    __atomic_store_n(&state->last_req_ret, req_ret, __ATOMIC_RELAXED);
    return req_ret;
}

static int virtio_iommu_send_attach(struct virtio_iommu_domain_ctx *ctx) {
    struct virtio_iommu_req_attach req;
    memset(&req, 0, sizeof(req));
    req.head.type = VIRTIO_IOMMU_T_ATTACH;
    req.domain = ctx->domain_id;
    req.endpoint = ctx->endpoint;
    return virtio_iommu_submit_req(
        ctx->state, &req, sizeof(req),
        offsetof(struct virtio_iommu_req_attach, tail), NULL);
}

static int virtio_iommu_send_detach(struct virtio_iommu_domain_ctx *ctx) {
    struct virtio_iommu_req_detach req;
    memset(&req, 0, sizeof(req));
    req.head.type = VIRTIO_IOMMU_T_DETACH;
    req.domain = ctx->domain_id;
    req.endpoint = ctx->endpoint;
    return virtio_iommu_submit_req(
        ctx->state, &req, sizeof(req),
        offsetof(struct virtio_iommu_req_detach, tail), NULL);
}

static int virtio_iommu_domain_map(struct iommu_domain *domain, dma_addr_t iova,
                                   paddr_t paddr, size_t size, uint32_t prot) {
    if (!domain || !size)
        return -EINVAL;

    struct virtio_iommu_domain_ctx *ctx = domain->ops_priv;
    if (!ctx || !ctx->state)
        return -EINVAL;

    dma_addr_t iova_end = iova + (dma_addr_t)size - 1U;
    if (iova_end < iova)
        return -ERANGE;

    uint32_t flags = 0;
    if (prot & IOMMU_PROT_READ)
        flags |= VIRTIO_IOMMU_MAP_F_READ;
    if (prot & IOMMU_PROT_WRITE)
        flags |= VIRTIO_IOMMU_MAP_F_WRITE;

    struct virtio_iommu_req_map req;
    memset(&req, 0, sizeof(req));
    req.head.type = VIRTIO_IOMMU_T_MAP;
    req.domain = ctx->domain_id;
    req.flags = flags;
    req.virt_start = iova;
    req.virt_end = iova_end;
    req.phys_start = paddr;

    return virtio_iommu_submit_req(
        ctx->state, &req, sizeof(req),
        offsetof(struct virtio_iommu_req_map, tail), NULL);
}

static void virtio_iommu_domain_unmap(struct iommu_domain *domain, dma_addr_t iova,
                                      size_t size) {
    if (!domain || !size)
        return;

    struct virtio_iommu_domain_ctx *ctx = domain->ops_priv;
    if (!ctx || !ctx->state)
        return;

    dma_addr_t iova_end = iova + (dma_addr_t)size - 1U;
    if (iova_end < iova)
        return;

    struct virtio_iommu_req_unmap req;
    memset(&req, 0, sizeof(req));
    req.head.type = VIRTIO_IOMMU_T_UNMAP;
    req.domain = ctx->domain_id;
    req.virt_start = iova;
    req.virt_end = iova_end;

    int ret = virtio_iommu_submit_req(
        ctx->state, &req, sizeof(req),
        offsetof(struct virtio_iommu_req_unmap, tail), NULL);
    if (ret < 0) {
        pr_warn("virtio-iommu: unmap failed domain=%u endpoint=0x%x ret=%d\n",
                ctx->domain_id, ctx->endpoint, ret);
    }
}

static void virtio_iommu_domain_release(struct iommu_domain *domain) {
    if (!domain)
        return;

    struct virtio_iommu_domain_ctx *ctx = domain->ops_priv;
    if (!ctx)
        return;

    if (ctx->state && ctx->state->ready && !ctx->state->faulted) {
        int ret = virtio_iommu_send_detach(ctx);
        if (ret < 0) {
            pr_warn("virtio-iommu: detach failed domain=%u endpoint=0x%x ret=%d\n",
                    ctx->domain_id, ctx->endpoint, ret);
        }
    }

    virtio_iommu_domain_id_free(ctx);
    if (ctx->state && !ctx->state->ready) {
        bool irq_flags;
        spin_lock_irqsave(&ctx->state->domain_lock, &irq_flags);
        bool no_domains = list_empty(&ctx->state->domains);
        spin_unlock_irqrestore(&ctx->state->domain_lock, irq_flags);
        if (no_domains && ctx->state->req_vq) {
            virtqueue_free(ctx->state->req_vq);
            ctx->state->req_vq = NULL;
        }
    }
    domain->ops_priv = NULL;
    kfree(ctx);
}

static const struct iommu_domain_ops virtio_iommu_domain_ops = {
    .map = virtio_iommu_domain_map,
    .unmap = virtio_iommu_domain_unmap,
    .release = virtio_iommu_domain_release,
};

static int virtio_iommu_provider_match(struct device *dev, void *priv) {
    struct virtio_iommu_state *state = priv;
    if (!state || !state->ready || state->faulted || !state->map_unmap ||
        !state->vdev || !dev)
        return 0;

    if (dev == &state->vdev->dev)
        return 0;

    uint32_t endpoint = 0;
    return virtio_iommu_endpoint_from_dev(dev, &endpoint) == 0 ? 1 : 0;
}

static struct iommu_domain *virtio_iommu_provider_alloc(struct device *dev,
                                                         bool *owned,
                                                         void *priv) {
    struct virtio_iommu_state *state = priv;
    if (!state || !state->ready || state->faulted || !state->map_unmap || !dev)
        return NULL;

    uint32_t endpoint = 0;
    if (virtio_iommu_endpoint_from_dev(dev, &endpoint) < 0)
        return NULL;

    dma_addr_t iova_base = 0;
    size_t iova_size = 0;
    if (state->input_range) {
        if (state->input_end < state->input_start)
            return NULL;
        uint64_t span = (state->input_end - state->input_start) + 1ULL;
        if (!span || span > (uint64_t)SIZE_MAX)
            return NULL;
        iova_base = (dma_addr_t)state->input_start;
        iova_size = (size_t)span;
    }

    struct iommu_domain *domain =
        iommu_domain_create(IOMMU_DOMAIN_DMA, iova_base, iova_size);
    if (!domain)
        return NULL;

    if (iommu_domain_set_granule(domain, state->granule) < 0) {
        iommu_domain_destroy(domain);
        return NULL;
    }

    struct virtio_iommu_domain_ctx *ctx = kzalloc(sizeof(*ctx));
    if (!ctx) {
        iommu_domain_destroy(domain);
        return NULL;
    }

    INIT_LIST_HEAD(&ctx->list);
    ctx->state = state;
    ctx->endpoint = endpoint;

    bool irq_flags;
    spin_lock_irqsave(&state->domain_lock, &irq_flags);
    int ret = virtio_iommu_domain_id_alloc(state, ctx);
    spin_unlock_irqrestore(&state->domain_lock, irq_flags);
    if (ret < 0) {
        kfree(ctx);
        iommu_domain_destroy(domain);
        return NULL;
    }

    iommu_domain_set_ops(domain, &virtio_iommu_domain_ops, ctx);
    ret = virtio_iommu_send_attach(ctx);
    if (ret < 0) {
        virtio_iommu_domain_id_free(ctx);
        kfree(ctx);
        iommu_domain_destroy(domain);
        return NULL;
    }

    if (owned)
        *owned = true;
    return domain;
}

static const struct iommu_hw_ops virtio_iommu_hw_ops = {
    .name = "virtio-iommu",
    .priority = 700,
    .match = virtio_iommu_provider_match,
    .alloc_default_domain = virtio_iommu_provider_alloc,
};

static int virtio_iommu_rebind_pci_dev(struct device *dev, void *arg) {
    struct virtio_iommu_rebind_ctx *ctx = arg;
    if (!ctx || !ctx->state || !ctx->state->ready || ctx->state->faulted || !dev)
        return 0;
    if (dev->bus != &pci_bus_type)
        return 0;

    struct iommu_domain *domain = iommu_get_domain(dev);
    if (domain && domain != iommu_get_passthrough_domain())
        return 0;

    ctx->attempted++;
    int ret = iommu_attach_default_domain(dev);
    if (ret < 0) {
        ctx->failed++;
        pr_warn("virtio-iommu: reattach failed for %s ret=%d\n", dev->name,
                ret);
        return 0;
    }
    ctx->attached++;
    return 0;
}

static void virtio_iommu_intr(struct virtio_device *vdev) {
    (void)vdev;
    struct virtio_iommu_state *state = &virtio_iommu_state;
    if (!state->ready || !state->req_vq)
        return;

    bool irq_flags;
    spin_lock_irqsave(&state->req_lock, &irq_flags);
    virtio_iommu_drain_used_locked(state);
    spin_unlock_irqrestore(&state->req_lock, irq_flags);
}

static int virtio_iommu_probe(struct virtio_device *vdev) {
    struct virtio_iommu_state *state = &virtio_iommu_state;
    if (!vdev || !vdev->ops)
        return -EINVAL;
    if (state->ready)
        return -EBUSY;

    uint64_t features = vdev->ops->get_features(vdev);
    if (!(features & (1ULL << VIRTIO_IOMMU_F_MAP_UNMAP))) {
        pr_warn("virtio-iommu: map/unmap not supported, backend disabled\n");
        return -ENOTSUP;
    }

    uint64_t driver_features = 0;
    if (features & (1ULL << VIRTIO_IOMMU_F_INPUT_RANGE))
        driver_features |= (1ULL << VIRTIO_IOMMU_F_INPUT_RANGE);
    if (features & (1ULL << VIRTIO_IOMMU_F_DOMAIN_RANGE))
        driver_features |= (1ULL << VIRTIO_IOMMU_F_DOMAIN_RANGE);
    driver_features |= (1ULL << VIRTIO_IOMMU_F_MAP_UNMAP);

    vdev->handler = virtio_iommu_intr;
    int ret = virtio_device_init(vdev, driver_features);
    if (ret < 0) {
        virtio_device_set_failed(vdev);
        return ret;
    }

    struct virtqueue *req_vq = virtqueue_alloc(vdev, VIRTIO_IOMMU_REQ_VQ,
                                               VIRTIO_IOMMU_REQ_DEPTH);
    if (!req_vq) {
        virtio_device_set_failed(vdev);
        return -ENOMEM;
    }

    ret = vdev->ops->setup_vq(vdev, VIRTIO_IOMMU_REQ_VQ, req_vq);
    if (ret < 0) {
        virtqueue_free(req_vq);
        virtio_device_set_failed(vdev);
        return ret;
    }

    struct virtio_iommu_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    vdev->ops->get_config(vdev, 0, &cfg, sizeof(cfg));

    size_t granule = virtio_iommu_pick_granule(cfg.page_size_mask);
    if (!granule) {
        pr_warn("virtio-iommu: unsupported page_size_mask=0x%llx\n",
                (unsigned long long)cfg.page_size_mask);
        virtqueue_free(req_vq);
        virtio_device_set_failed(vdev);
        return -ENOTSUP;
    }

    uint64_t input_start = 0;
    uint64_t input_end = 0;
    bool input_range = false;
    if (driver_features & (1ULL << VIRTIO_IOMMU_F_INPUT_RANGE)) {
        if (cfg.input_range_end < cfg.input_range_start) {
            virtqueue_free(req_vq);
            virtio_device_set_failed(vdev);
            return -ERANGE;
        }
        input_start = cfg.input_range_start;
        input_end = cfg.input_range_end;
        input_range = true;
    }

    uint32_t domain_start = 1;
    uint32_t domain_end = 0xffffU;
    if (driver_features & (1ULL << VIRTIO_IOMMU_F_DOMAIN_RANGE)) {
        domain_start = cfg.domain_range_start;
        domain_end = cfg.domain_range_end;
    }
    if (domain_end < domain_start) {
        virtqueue_free(req_vq);
        virtio_device_set_failed(vdev);
        return -ERANGE;
    }

    memset(state, 0, sizeof(*state));
    state->vdev = vdev;
    state->req_vq = req_vq;
    state->page_size_mask = cfg.page_size_mask;
    state->input_start = input_start;
    state->input_end = input_end;
    state->domain_start = domain_start;
    state->domain_end = domain_end;
    state->next_domain = domain_start;
    state->granule = granule;
    state->map_unmap = true;
    state->input_range = input_range;
    __atomic_store_n(&state->faulted, false, __ATOMIC_RELEASE);
    spin_init(&state->req_lock);
    spin_init(&state->domain_lock);
    INIT_LIST_HEAD(&state->domains);

    ret = iommu_register_hw_ops(&virtio_iommu_hw_ops, state);
    if (ret < 0) {
        virtqueue_free(req_vq);
        memset(state, 0, sizeof(*state));
        virtio_device_set_failed(vdev);
        return ret;
    }

    ret = virtio_device_ready(vdev);
    if (ret < 0) {
        iommu_unregister_hw_ops(&virtio_iommu_hw_ops);
        virtqueue_free(req_vq);
        memset(state, 0, sizeof(*state));
        virtio_device_set_failed(vdev);
        return ret;
    }

    __atomic_store_n(&state->ready, true, __ATOMIC_RELEASE);
    vdev->priv = state;

    struct virtio_iommu_rebind_ctx rebind = {
        .state = state,
    };
    ret = device_for_each(virtio_iommu_rebind_pci_dev, &rebind);
    if (ret < 0)
        pr_warn("virtio-iommu: rebind walk failed ret=%d\n", ret);

    pr_info("virtio-iommu: backend online granule=%zu page_mask=0x%llx domain=[%u,%u] input=[0x%llx,0x%llx] rebind=%u/%u fail=%u\n",
            state->granule, (unsigned long long)state->page_size_mask,
            state->domain_start, state->domain_end,
            (unsigned long long)state->input_start,
            (unsigned long long)state->input_end, rebind.attached,
            rebind.attempted, rebind.failed);
    return 0;
}

static void virtio_iommu_remove(struct virtio_device *vdev) {
    struct virtio_iommu_state *state = vdev ? vdev->priv : NULL;
    if (!state)
        return;

    iommu_unregister_hw_ops(&virtio_iommu_hw_ops);
    __atomic_store_n(&state->faulted, true, __ATOMIC_RELEASE);
    __atomic_store_n(&state->ready, false, __ATOMIC_RELEASE);

    bool irq_flags;
    bool domains_active;
    spin_lock_irqsave(&state->domain_lock, &irq_flags);
    domains_active = !list_empty(&state->domains);
    spin_unlock_irqrestore(&state->domain_lock, irq_flags);

    if (!domains_active) {
        if (state->req_vq) {
            virtqueue_free(state->req_vq);
            state->req_vq = NULL;
        }
        memset(state, 0, sizeof(*state));
    }
    vdev->priv = NULL;
}

struct virtio_driver virtio_iommu_driver = {
    .drv = { .name = "virtio-iommu" },
    .device_id = VIRTIO_ID_IOMMU,
    .probe = virtio_iommu_probe,
    .remove = virtio_iommu_remove,
};
