/**
 * kernel/core/mm/iommu.c - IOMMU domain and DMA backend
 */

#include <kairos/device.h>
#include <kairos/dma.h>
#include <kairos/iommu.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>

struct iommu_mapping {
    struct list_head list;
    struct list_head hash_node;
    struct device *dev;
    dma_addr_t dma_addr;
    dma_addr_t iova_base;
    paddr_t cpu_pa;
    size_t map_size;
    size_t req_size;
    int direction;
};

static struct iommu_domain iommu_passthrough_domain;
static bool iommu_passthrough_domain_init_done;
static spinlock_t iommu_passthrough_domain_init_lock = SPINLOCK_INIT;
struct iommu_hw_provider_entry {
    const struct iommu_hw_ops *ops;
    void *priv;
};

#define IOMMU_HW_PROVIDERS_MAX 8
static struct iommu_hw_provider_entry iommu_hw_providers[IOMMU_HW_PROVIDERS_MAX];
static size_t iommu_hw_provider_count;
static spinlock_t iommu_hw_ops_lock = SPINLOCK_INIT;
static spinlock_t iommu_device_domain_lock = SPINLOCK_INIT;

int arch_iommu_init(void);

__attribute__((weak)) int
virtio_iommu_health_snapshot(struct virtio_iommu_health *out) {
    if (!out)
        return -EINVAL;
    memset(out, 0, sizeof(*out));
    return -ENODEV;
}

static bool iommu_granule_valid(size_t granule) {
    if (granule < CONFIG_PAGE_SIZE)
        return false;
    return (granule & (granule - 1U)) == 0;
}

static size_t iommu_domain_granule(const struct iommu_domain *domain) {
    if (!domain || !iommu_granule_valid(domain->granule))
        return CONFIG_PAGE_SIZE;
    return domain->granule;
}

static uint32_t iommu_dma_dir_to_prot(int direction) {
    if (direction == DMA_TO_DEVICE)
        return IOMMU_PROT_READ;
    if (direction == DMA_FROM_DEVICE)
        return IOMMU_PROT_WRITE;
    return IOMMU_PROT_READ | IOMMU_PROT_WRITE;
}

static void iommu_direct_unmap_rollback(const struct dma_ops *direct,
                                        struct device *dev, dma_addr_t phys_dma,
                                        size_t size, int direction) {
    if (!direct || !direct->unmap_single || !phys_dma)
        return;
    direct->unmap_single(dev, phys_dma, size, direction);
}

static size_t iommu_mapping_hash_bucket(dma_addr_t dma_addr) {
    return (size_t)(((uint64_t)dma_addr) & (IOMMU_MAPPING_HASH_SIZE - 1U));
}

static void iommu_mapping_hash_insert_locked(struct iommu_domain *domain,
                                             struct iommu_mapping *mapping) {
    if (!domain || !mapping)
        return;
    size_t idx = iommu_mapping_hash_bucket(mapping->dma_addr);
    list_add_tail(&mapping->hash_node, &domain->mapping_hash[idx]);
}

static void iommu_mapping_hash_remove_locked(struct iommu_mapping *mapping) {
    if (!mapping || list_empty(&mapping->hash_node))
        return;
    list_del(&mapping->hash_node);
    INIT_LIST_HEAD(&mapping->hash_node);
}

static struct iommu_mapping *
iommu_mapping_find_locked(struct iommu_domain *domain, struct device *dev,
                          dma_addr_t dma_addr) {
    if (!domain || !dev || dma_addr == 0)
        return NULL;
    size_t idx = iommu_mapping_hash_bucket(dma_addr);
    struct iommu_mapping *iter = NULL;
    list_for_each_entry(iter, &domain->mapping_hash[idx], hash_node) {
        if (iter->dev == dev && iter->dma_addr == dma_addr)
            return iter;
    }
    return NULL;
}

static bool iommu_iova_conflict_locked(struct iommu_domain *domain, dma_addr_t start,
                                       dma_addr_t end, dma_addr_t *next_start) {
    struct iommu_mapping *m;
    bool conflict = false;

    list_for_each_entry(m, &domain->mappings, list) {
        dma_addr_t ms = m->iova_base;
        dma_addr_t me = ms + (dma_addr_t)m->map_size;
        if (me < ms)
            me = ~(dma_addr_t)0;
        if (end <= ms || start >= me)
            continue;
        conflict = true;
        if (me > *next_start)
            *next_start = me;
    }
    return conflict;
}

static dma_addr_t iommu_iova_find_locked(struct iommu_domain *domain,
                                         struct device *dev, size_t size) {
    size_t granule = iommu_domain_granule(domain);

    if (!size || domain->iova_limit <= domain->iova_base)
        return 0;
    if (size > (size_t)(domain->iova_limit - domain->iova_base))
        return 0;

    dma_addr_t starts[2] = {
        ALIGN_UP(domain->iova_cursor, granule),
        ALIGN_UP(domain->iova_base, granule),
    };
    dma_addr_t ends[2] = {
        domain->iova_limit,
        domain->iova_cursor,
    };

    for (size_t pass = 0; pass < ARRAY_SIZE(starts); pass++) {
        dma_addr_t cand = starts[pass];
        dma_addr_t end_limit = ends[pass];

        while (cand < end_limit) {
            if ((size_t)(end_limit - cand) < size)
                break;
            dma_addr_t cand_end = cand + (dma_addr_t)size;
            if (cand_end < cand)
                break;
            if (!dma_addr_allowed(dev, cand, size)) {
                dma_addr_t next = cand + granule;
                if (next < cand)
                    break;
                cand = ALIGN_UP(next, granule);
                continue;
            }
            dma_addr_t next = cand + granule;
            if (!iommu_iova_conflict_locked(domain, cand, cand_end, &next))
                return cand;
            cand = ALIGN_UP(next, granule);
        }
    }
    return 0;
}

static dma_addr_t iommu_dma_map_single_impl(struct device *dev, void *ptr, size_t size,
                                            int direction) {
    const struct dma_ops *direct = dma_get_direct_ops();
    struct iommu_domain *domain = iommu_get_domain(dev);

    if (!domain || domain->type == IOMMU_DOMAIN_BYPASS)
        return direct->map_single(dev, ptr, size, direction);
    if (!ptr || !size)
        return 0;

    dma_addr_t phys_dma = direct->map_single(dev, ptr, size, direction);
    if (!phys_dma)
        return 0;

    size_t granule = iommu_domain_granule(domain);
    paddr_t pa = (paddr_t)phys_dma;
    paddr_t pa_base = ALIGN_DOWN(pa, granule);
    size_t offset = (size_t)(pa - pa_base);
    if (offset > SIZE_MAX - size) {
        iommu_direct_unmap_rollback(direct, dev, phys_dma, size, direction);
        return 0;
    }
    size_t req_span = size + offset;
    size_t map_size = ALIGN_UP(req_span, granule);
    if (!map_size || map_size < req_span) {
        iommu_direct_unmap_rollback(direct, dev, phys_dma, size, direction);
        return 0;
    }

    struct iommu_mapping *mapping = kzalloc(sizeof(*mapping));
    if (!mapping) {
        iommu_direct_unmap_rollback(direct, dev, phys_dma, size, direction);
        return 0;
    }
    INIT_LIST_HEAD(&mapping->hash_node);

    bool irq_flags;
    spin_lock_irqsave(&domain->lock, &irq_flags);
    dma_addr_t iova_base = iommu_iova_find_locked(domain, dev, map_size);
    if (!iova_base) {
        spin_unlock_irqrestore(&domain->lock, irq_flags);
        kfree(mapping);
        iommu_direct_unmap_rollback(direct, dev, phys_dma, size, direction);
        return 0;
    }
    if ((dma_addr_t)offset > (~(dma_addr_t)0 - iova_base)) {
        spin_unlock_irqrestore(&domain->lock, irq_flags);
        kfree(mapping);
        iommu_direct_unmap_rollback(direct, dev, phys_dma, size, direction);
        return 0;
    }

    if (domain->ops && domain->ops->map) {
        int ret = domain->ops->map(domain, iova_base, pa_base, map_size,
                                   iommu_dma_dir_to_prot(direction));
        if (ret < 0) {
            spin_unlock_irqrestore(&domain->lock, irq_flags);
            kfree(mapping);
            iommu_direct_unmap_rollback(direct, dev, phys_dma, size, direction);
            return 0;
        }
    }

    mapping->dma_addr = iova_base + offset;
    mapping->dev = dev;
    mapping->iova_base = iova_base;
    mapping->cpu_pa = pa;
    mapping->map_size = map_size;
    mapping->req_size = size;
    mapping->direction = direction;
    list_add_tail(&mapping->list, &domain->mappings);
    iommu_mapping_hash_insert_locked(domain, mapping);

    domain->iova_cursor = iova_base + (dma_addr_t)map_size;
    if (domain->iova_cursor >= domain->iova_limit)
        domain->iova_cursor = domain->iova_base;

    spin_unlock_irqrestore(&domain->lock, irq_flags);
    return mapping->dma_addr;
}

static void iommu_dma_unmap_single_impl(struct device *dev, dma_addr_t addr, size_t size,
                                        int direction) {
    (void)size;
    const struct dma_ops *direct = dma_get_direct_ops();
    struct iommu_domain *domain = iommu_get_domain(dev);

    if (!domain || domain->type == IOMMU_DOMAIN_BYPASS) {
        direct->unmap_single(dev, addr, size, direction);
        return;
    }

    bool irq_flags;
    struct iommu_mapping *mapping = NULL;
    spin_lock_irqsave(&domain->lock, &irq_flags);
    mapping = iommu_mapping_find_locked(domain, dev, addr);
    if (mapping) {
        iommu_mapping_hash_remove_locked(mapping);
        list_del(&mapping->list);
    }
    if (mapping && domain->ops && domain->ops->unmap)
        domain->ops->unmap(domain, mapping->iova_base, mapping->map_size);
    spin_unlock_irqrestore(&domain->lock, irq_flags);

    if (!mapping) {
        pr_warn("iommu: missing mapping for dma addr=%llx\n",
                (unsigned long long)addr);
        return;
    }

    direct->unmap_single(dev, (dma_addr_t)mapping->cpu_pa, mapping->req_size,
                         direction);
    kfree(mapping);
}

static void *iommu_dma_alloc_coherent_impl(struct device *dev, size_t size,
                                           dma_addr_t *dma_handle) {
    const struct dma_ops *direct = dma_get_direct_ops();
    struct iommu_domain *domain = iommu_get_domain(dev);
    dma_addr_t phys_dma = 0;
    void *cpu_addr = direct->alloc_coherent(dev, size, &phys_dma);
    if (!cpu_addr)
        return NULL;

    if (!domain || domain->type == IOMMU_DOMAIN_BYPASS) {
        if (dma_handle)
            *dma_handle = phys_dma;
        return cpu_addr;
    }

    dma_addr_t iova = iommu_dma_map_single_impl(dev, cpu_addr, size,
                                                DMA_BIDIRECTIONAL);
    if (!iova) {
        direct->free_coherent(dev, cpu_addr, size, phys_dma);
        return NULL;
    }
    if (dma_handle)
        *dma_handle = iova;
    return cpu_addr;
}

static void iommu_dma_free_coherent_impl(struct device *dev, void *cpu_addr, size_t size,
                                         dma_addr_t dma_handle) {
    const struct dma_ops *direct = dma_get_direct_ops();
    struct iommu_domain *domain = iommu_get_domain(dev);
    if (domain && domain->type == IOMMU_DOMAIN_DMA && dma_handle) {
        iommu_dma_unmap_single_impl(dev, dma_handle, size, DMA_BIDIRECTIONAL);
        direct->free_coherent(dev, cpu_addr, size, 0);
        return;
    }
    direct->free_coherent(dev, cpu_addr, size, dma_handle);
}

static const struct dma_ops iommu_dma_ops = {
    .map_single = iommu_dma_map_single_impl,
    .unmap_single = iommu_dma_unmap_single_impl,
    .alloc_coherent = iommu_dma_alloc_coherent_impl,
    .free_coherent = iommu_dma_free_coherent_impl,
};

struct iommu_domain *iommu_domain_create(enum iommu_domain_type type,
                                         dma_addr_t iova_base,
                                         size_t iova_size) {
    const size_t granule = CONFIG_PAGE_SIZE;
    if (type != IOMMU_DOMAIN_BYPASS && type != IOMMU_DOMAIN_DMA)
        return NULL;

    if (!iova_base)
        iova_base = IOMMU_IOVA_DEFAULT_BASE;
    if (!iova_size)
        iova_size = IOMMU_IOVA_DEFAULT_SIZE;
    iova_base = ALIGN_UP(iova_base, granule);
    iova_size = ALIGN_UP(iova_size, granule);
    if (!iova_size)
        return NULL;

    dma_addr_t iova_limit = iova_base + (dma_addr_t)iova_size;
    if (iova_limit <= iova_base)
        return NULL;

    struct iommu_domain *domain = kzalloc(sizeof(*domain));
    if (!domain)
        return NULL;

    domain->type = type;
    domain->iova_base = iova_base;
    domain->iova_limit = iova_limit;
    domain->iova_cursor = iova_base;
    domain->granule = granule;
    domain->caps = (type == IOMMU_DOMAIN_DMA) ? IOMMU_CAP_MAP_UNMAP : 0;
    domain->fault_policy = IOMMU_FAULT_POLICY_REPORT;
    spin_init(&domain->lock);
    INIT_LIST_HEAD(&domain->mappings);
    for (size_t i = 0; i < IOMMU_MAPPING_HASH_SIZE; i++)
        INIT_LIST_HEAD(&domain->mapping_hash[i]);
    return domain;
}

struct iommu_domain *iommu_get_passthrough_domain(void) {
    if (__atomic_load_n(&iommu_passthrough_domain_init_done, __ATOMIC_ACQUIRE))
        return &iommu_passthrough_domain;

    spin_lock(&iommu_passthrough_domain_init_lock);
    if (!iommu_passthrough_domain_init_done) {
        memset(&iommu_passthrough_domain, 0, sizeof(iommu_passthrough_domain));
        iommu_passthrough_domain.type = IOMMU_DOMAIN_BYPASS;
        iommu_passthrough_domain.iova_base = IOMMU_IOVA_DEFAULT_BASE;
        iommu_passthrough_domain.iova_limit =
            IOMMU_IOVA_DEFAULT_BASE + IOMMU_IOVA_DEFAULT_SIZE;
        iommu_passthrough_domain.iova_cursor = iommu_passthrough_domain.iova_base;
        iommu_passthrough_domain.granule = CONFIG_PAGE_SIZE;
        iommu_passthrough_domain.caps = 0;
        iommu_passthrough_domain.fault_policy = IOMMU_FAULT_POLICY_REPORT;
        spin_init(&iommu_passthrough_domain.lock);
        INIT_LIST_HEAD(&iommu_passthrough_domain.mappings);
        for (size_t i = 0; i < IOMMU_MAPPING_HASH_SIZE; i++)
            INIT_LIST_HEAD(&iommu_passthrough_domain.mapping_hash[i]);
        __atomic_store_n(&iommu_passthrough_domain_init_done, true,
                         __ATOMIC_RELEASE);
    }
    spin_unlock(&iommu_passthrough_domain_init_lock);

    return &iommu_passthrough_domain;
}

int iommu_init(void) {
    int ret = arch_iommu_init();
    if (ret == 0)
        pr_info("iommu: arch backend initialized\n");
    else if (ret == -ENOTSUP)
        pr_info("iommu: arch backend discoverable but not implemented, using passthrough\n");
    else
        pr_info("iommu: no arch backend (ret=%d), using passthrough\n", ret);
    return 0;
}

void iommu_domain_destroy(struct iommu_domain *domain) {
    if (!domain)
        return;
    if (domain == &iommu_passthrough_domain)
        return;

    bool irq_flags;
    spin_lock_irqsave(&domain->lock, &irq_flags);
    if (!list_empty(&domain->mappings))
        pr_warn("iommu: destroying domain with active mappings\n");

    struct list_head *pos, *n;
    list_for_each_safe(pos, n, &domain->mappings) {
        struct iommu_mapping *m = list_entry(pos, struct iommu_mapping, list);
        iommu_mapping_hash_remove_locked(m);
        list_del(&m->list);
        if (domain->ops && domain->ops->unmap)
            domain->ops->unmap(domain, m->iova_base, m->map_size);
        kfree(m);
    }
    spin_unlock_irqrestore(&domain->lock, irq_flags);
    if (domain->ops && domain->ops->release)
        domain->ops->release(domain);
    kfree(domain);
}

void iommu_domain_set_ops(struct iommu_domain *domain,
                          const struct iommu_domain_ops *ops, void *ops_priv) {
    if (!domain)
        return;
    bool irq_flags;
    spin_lock_irqsave(&domain->lock, &irq_flags);
    domain->ops = ops;
    domain->ops_priv = ops_priv;
    spin_unlock_irqrestore(&domain->lock, irq_flags);
}

int iommu_domain_set_granule(struct iommu_domain *domain, size_t granule) {
    if (!domain)
        return -EINVAL;
    if (!iommu_granule_valid(granule))
        return -EINVAL;
    if (domain == &iommu_passthrough_domain)
        return -EBUSY;

    bool irq_flags;
    spin_lock_irqsave(&domain->lock, &irq_flags);
    if (!list_empty(&domain->mappings)) {
        spin_unlock_irqrestore(&domain->lock, irq_flags);
        return -EBUSY;
    }

    dma_addr_t base = ALIGN_UP(domain->iova_base, granule);
    dma_addr_t limit = ALIGN_DOWN(domain->iova_limit, granule);
    if (limit <= base) {
        spin_unlock_irqrestore(&domain->lock, irq_flags);
        return -EINVAL;
    }
    domain->granule = granule;
    domain->iova_base = base;
    domain->iova_limit = limit;
    domain->iova_cursor = base;
    spin_unlock_irqrestore(&domain->lock, irq_flags);
    return 0;
}

size_t iommu_domain_get_granule(const struct iommu_domain *domain) {
    return iommu_domain_granule(domain);
}

void iommu_domain_set_caps(struct iommu_domain *domain, uint64_t caps) {
    if (!domain)
        return;
    __atomic_store_n(&domain->caps, caps, __ATOMIC_RELEASE);
}

uint64_t iommu_domain_get_caps(const struct iommu_domain *domain) {
    if (!domain)
        return 0;
    return __atomic_load_n(&domain->caps, __ATOMIC_ACQUIRE);
}

bool iommu_domain_has_cap(const struct iommu_domain *domain, uint64_t cap) {
    return (iommu_domain_get_caps(domain) & cap) != 0;
}

int iommu_domain_bind_pasid(struct iommu_domain *domain, struct device *dev,
                            uint32_t pasid, uint32_t flags) {
    if (!domain || !dev)
        return -EINVAL;
    if (!iommu_domain_has_cap(domain, IOMMU_CAP_PASID))
        return -EOPNOTSUPP;
    if (!domain->ops || !domain->ops->bind_pasid)
        return -EOPNOTSUPP;
    return domain->ops->bind_pasid(domain, dev, pasid, flags);
}

int iommu_domain_unbind_pasid(struct iommu_domain *domain, struct device *dev,
                              uint32_t pasid) {
    if (!domain || !dev)
        return -EINVAL;
    if (!iommu_domain_has_cap(domain, IOMMU_CAP_PASID))
        return -EOPNOTSUPP;
    if (!domain->ops || !domain->ops->unbind_pasid)
        return -EOPNOTSUPP;
    return domain->ops->unbind_pasid(domain, dev, pasid);
}

int iommu_domain_enable_pri(struct iommu_domain *domain, struct device *dev,
                            uint32_t queue_depth) {
    if (!domain || !dev || queue_depth == 0)
        return -EINVAL;
    if (!iommu_domain_has_cap(domain, IOMMU_CAP_PRI))
        return -EOPNOTSUPP;
    if (!domain->ops || !domain->ops->enable_pri)
        return -EOPNOTSUPP;
    return domain->ops->enable_pri(domain, dev, queue_depth);
}

int iommu_domain_enable_ats(struct iommu_domain *domain, struct device *dev,
                            uint32_t flags) {
    if (!domain || !dev)
        return -EINVAL;
    if (!iommu_domain_has_cap(domain, IOMMU_CAP_ATS))
        return -EOPNOTSUPP;
    if (!domain->ops || !domain->ops->enable_ats)
        return -EOPNOTSUPP;
    return domain->ops->enable_ats(domain, dev, flags);
}

int iommu_domain_set_fault_policy(struct iommu_domain *domain,
                                  enum iommu_fault_policy policy) {
    if (!domain)
        return -EINVAL;
    if (policy < IOMMU_FAULT_POLICY_REPORT ||
        policy > IOMMU_FAULT_POLICY_RECOVER)
        return -EINVAL;

    if (policy == IOMMU_FAULT_POLICY_DISABLE &&
        !iommu_domain_has_cap(domain, IOMMU_CAP_FAULT_DISABLE))
        return -EOPNOTSUPP;
    if (policy == IOMMU_FAULT_POLICY_RECOVER &&
        !iommu_domain_has_cap(domain, IOMMU_CAP_FAULT_RECOVER))
        return -EOPNOTSUPP;

    if (domain->ops && domain->ops->set_fault_policy) {
        int ret = domain->ops->set_fault_policy(domain, policy);
        if (ret < 0)
            return ret;
    } else if (policy != IOMMU_FAULT_POLICY_REPORT) {
        return -EOPNOTSUPP;
    }

    __atomic_store_n(&domain->fault_policy, policy, __ATOMIC_RELEASE);
    return 0;
}

enum iommu_fault_policy
iommu_domain_get_fault_policy(const struct iommu_domain *domain) {
    if (!domain)
        return IOMMU_FAULT_POLICY_REPORT;
    return __atomic_load_n(&domain->fault_policy, __ATOMIC_ACQUIRE);
}

int iommu_domain_recover_faults(struct iommu_domain *domain, uint32_t budget,
                                uint32_t *recovered) {
    if (!domain || budget == 0)
        return -EINVAL;
    if (recovered)
        *recovered = 0;
    if (!iommu_domain_has_cap(domain, IOMMU_CAP_FAULT_RECOVER))
        return -EOPNOTSUPP;
    if (!domain->ops || !domain->ops->recover_faults)
        return -EOPNOTSUPP;
    return domain->ops->recover_faults(domain, budget, recovered);
}

static void iommu_release_detached_domain(struct iommu_domain *domain, bool owned,
                                          struct device *dev) {
    if (!domain || !dev)
        return;

    const struct dma_ops *direct = dma_get_direct_ops();
    if (domain->type == IOMMU_DOMAIN_DMA) {
        struct list_head reclaimed;
        INIT_LIST_HEAD(&reclaimed);

        bool irq_flags;
        spin_lock_irqsave(&domain->lock, &irq_flags);
        struct list_head *pos, *n;
        list_for_each_safe(pos, n, &domain->mappings) {
            struct iommu_mapping *m = list_entry(pos, struct iommu_mapping, list);
            if (m->dev != dev)
                continue;
            iommu_mapping_hash_remove_locked(m);
            list_del(&m->list);
            list_add_tail(&m->list, &reclaimed);
        }
        spin_unlock_irqrestore(&domain->lock, irq_flags);

        list_for_each_safe(pos, n, &reclaimed) {
            struct iommu_mapping *m = list_entry(pos, struct iommu_mapping, list);
            list_del(&m->list);
            if (domain->ops && domain->ops->unmap)
                domain->ops->unmap(domain, m->iova_base, m->map_size);
            if (direct && direct->unmap_single) {
                direct->unmap_single(dev, (dma_addr_t)m->cpu_pa, m->req_size,
                                     m->direction);
            }
            kfree(m);
        }
    }

    if (owned)
        iommu_domain_destroy(domain);
}

static int iommu_domain_validate_attach(struct iommu_domain *domain) {
    if (!domain)
        return -EINVAL;
    if (domain->type != IOMMU_DOMAIN_DMA)
        return 0;
    if (!iommu_domain_has_cap(domain, IOMMU_CAP_MAP_UNMAP))
        return -EOPNOTSUPP;

    bool irq_flags;
    bool has_map = false;
    bool has_unmap = false;
    spin_lock_irqsave(&domain->lock, &irq_flags);
    has_map = domain->ops && domain->ops->map;
    has_unmap = domain->ops && domain->ops->unmap;
    spin_unlock_irqrestore(&domain->lock, irq_flags);
    if (!has_map || !has_unmap)
        return -EOPNOTSUPP;
    return 0;
}

static int iommu_attach_device_internal(struct iommu_domain *domain,
                                        struct device *dev, bool owned) {
    if (!domain || !dev)
        return -EINVAL;
    int ret = iommu_domain_validate_attach(domain);
    if (ret < 0)
        return ret;

    struct iommu_domain *prev_domain = NULL;
    bool prev_owned = false;

    spin_lock(&iommu_device_domain_lock);
    prev_domain = dev->iommu_domain;
    prev_owned = dev->iommu_domain_owned;
    if (prev_domain == domain) {
        dma_set_ops(dev, iommu_get_dma_ops());
        spin_unlock(&iommu_device_domain_lock);
        return 0;
    }
    dev->iommu_domain = domain;
    dev->iommu_domain_owned = owned;
    dma_set_ops(dev, iommu_get_dma_ops());
    spin_unlock(&iommu_device_domain_lock);

    if (prev_domain)
        iommu_release_detached_domain(prev_domain, prev_owned, dev);
    return 0;
}

int iommu_attach_device(struct iommu_domain *domain, struct device *dev) {
    return iommu_attach_device_internal(domain, dev, false);
}

int iommu_attach_default_domain(struct device *dev) {
    if (!dev)
        return -EINVAL;

    struct iommu_hw_provider_entry providers[IOMMU_HW_PROVIDERS_MAX];
    size_t provider_count = 0;
    spin_lock(&iommu_hw_ops_lock);
    provider_count = iommu_hw_provider_count;
    if (provider_count > ARRAY_SIZE(providers))
        provider_count = ARRAY_SIZE(providers);
    for (size_t i = 0; i < provider_count; i++)
        providers[i] = iommu_hw_providers[i];
    spin_unlock(&iommu_hw_ops_lock);

    struct iommu_domain *domain = NULL;
    bool owned = false;
    for (size_t i = 0; i < provider_count; i++) {
        const struct iommu_hw_ops *ops = providers[i].ops;
        if (!ops || !ops->alloc_default_domain)
            continue;
        if (ops->match) {
            int match = ops->match(dev, providers[i].priv);
            if (match <= 0)
                continue;
        }
        domain = ops->alloc_default_domain(dev, &owned, providers[i].priv);
        if (domain)
            break;
    }

    if (!domain) {
        domain = iommu_get_passthrough_domain();
        owned = false;
    }
    int ret = iommu_attach_device_internal(domain, dev, owned);
    if (ret < 0 && owned)
        iommu_domain_destroy(domain);
    return ret;
}

void iommu_detach_device(struct device *dev) {
    if (!dev)
        return;
    struct iommu_domain *domain = NULL;
    bool owned = false;

    spin_lock(&iommu_device_domain_lock);
    domain = dev->iommu_domain;
    owned = dev->iommu_domain_owned;
    dev->iommu_domain = NULL;
    dev->iommu_domain_owned = false;
    dma_set_ops(dev, NULL);
    spin_unlock(&iommu_device_domain_lock);

    iommu_release_detached_domain(domain, owned, dev);
}

struct iommu_domain *iommu_get_domain(struct device *dev) {
    return dev ? dev->iommu_domain : NULL;
}

int iommu_register_hw_ops(const struct iommu_hw_ops *ops, void *priv) {
    if (!ops || !ops->alloc_default_domain)
        return -EINVAL;

    spin_lock(&iommu_hw_ops_lock);
    for (size_t i = 0; i < iommu_hw_provider_count; i++) {
        if (iommu_hw_providers[i].ops == ops) {
            spin_unlock(&iommu_hw_ops_lock);
            return -EBUSY;
        }
    }
    if (iommu_hw_provider_count >= ARRAY_SIZE(iommu_hw_providers)) {
        spin_unlock(&iommu_hw_ops_lock);
        pr_warn("iommu: too many hardware backends (max=%u)\n",
                (unsigned int)ARRAY_SIZE(iommu_hw_providers));
        return -EBUSY;
    }

    size_t insert = iommu_hw_provider_count;
    for (size_t i = 0; i < iommu_hw_provider_count; i++) {
        if (ops->priority > iommu_hw_providers[i].ops->priority) {
            insert = i;
            break;
        }
    }
    for (size_t i = iommu_hw_provider_count; i > insert; i--)
        iommu_hw_providers[i] = iommu_hw_providers[i - 1];

    iommu_hw_providers[insert].ops = ops;
    iommu_hw_providers[insert].priv = priv;
    iommu_hw_provider_count++;
    spin_unlock(&iommu_hw_ops_lock);
    return 0;
}

void iommu_unregister_hw_ops(const struct iommu_hw_ops *ops) {
    if (!ops)
        return;

    spin_lock(&iommu_hw_ops_lock);
    for (size_t i = 0; i < iommu_hw_provider_count; i++) {
        if (iommu_hw_providers[i].ops != ops)
            continue;
        for (size_t j = i + 1; j < iommu_hw_provider_count; j++)
            iommu_hw_providers[j - 1] = iommu_hw_providers[j];
        iommu_hw_provider_count--;
        iommu_hw_providers[iommu_hw_provider_count].ops = NULL;
        iommu_hw_providers[iommu_hw_provider_count].priv = NULL;
        break;
    }
    spin_unlock(&iommu_hw_ops_lock);
}

const struct dma_ops *iommu_get_dma_ops(void) {
    return &iommu_dma_ops;
}
