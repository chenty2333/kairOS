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
    dma_addr_t dma_addr;
    dma_addr_t iova_base;
    paddr_t cpu_pa;
    size_t map_size;
    size_t req_size;
};

static struct iommu_domain iommu_passthrough_domain;
static bool iommu_passthrough_domain_init_done;
static spinlock_t iommu_passthrough_domain_init_lock = SPINLOCK_INIT;
static const struct iommu_hw_ops *iommu_hw_ops;
static void *iommu_hw_ops_priv;
static spinlock_t iommu_hw_ops_lock = SPINLOCK_INIT;

static uint32_t iommu_dma_dir_to_prot(int direction) {
    if (direction == DMA_TO_DEVICE)
        return IOMMU_PROT_READ;
    if (direction == DMA_FROM_DEVICE)
        return IOMMU_PROT_WRITE;
    return IOMMU_PROT_READ | IOMMU_PROT_WRITE;
}

static bool iommu_iova_conflict_locked(struct iommu_domain *domain, dma_addr_t start,
                                       dma_addr_t end, dma_addr_t *next_start) {
    struct iommu_mapping *m;
    bool conflict = false;

    list_for_each_entry(m, &domain->mappings, list) {
        dma_addr_t ms = m->iova_base;
        dma_addr_t me = ms + (dma_addr_t)m->map_size;
        if (end <= ms || start >= me)
            continue;
        conflict = true;
        if (me > *next_start)
            *next_start = me;
    }
    return conflict;
}

static dma_addr_t iommu_iova_find_locked(struct iommu_domain *domain, size_t size) {
    if (!size || domain->iova_limit <= domain->iova_base)
        return 0;
    if (size > (size_t)(domain->iova_limit - domain->iova_base))
        return 0;

    dma_addr_t starts[2] = {
        ALIGN_UP(domain->iova_cursor, CONFIG_PAGE_SIZE),
        ALIGN_UP(domain->iova_base, CONFIG_PAGE_SIZE),
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
            dma_addr_t next = cand + CONFIG_PAGE_SIZE;
            if (!iommu_iova_conflict_locked(domain, cand, cand_end, &next))
                return cand;
            cand = ALIGN_UP(next, CONFIG_PAGE_SIZE);
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

    paddr_t pa = (paddr_t)phys_dma;
    paddr_t pa_base = ALIGN_DOWN(pa, CONFIG_PAGE_SIZE);
    size_t offset = (size_t)(pa - pa_base);
    size_t map_size = ALIGN_UP(size + offset, CONFIG_PAGE_SIZE);

    struct iommu_mapping *mapping = kzalloc(sizeof(*mapping));
    if (!mapping)
        return 0;

    bool irq_flags;
    spin_lock_irqsave(&domain->lock, &irq_flags);
    dma_addr_t iova_base = iommu_iova_find_locked(domain, map_size);
    if (!iova_base) {
        spin_unlock_irqrestore(&domain->lock, irq_flags);
        kfree(mapping);
        return 0;
    }

    if (domain->ops && domain->ops->map) {
        int ret = domain->ops->map(domain, iova_base, pa_base, map_size,
                                   iommu_dma_dir_to_prot(direction));
        if (ret < 0) {
            spin_unlock_irqrestore(&domain->lock, irq_flags);
            kfree(mapping);
            return 0;
        }
    }

    mapping->dma_addr = iova_base + offset;
    mapping->iova_base = iova_base;
    mapping->cpu_pa = pa;
    mapping->map_size = map_size;
    mapping->req_size = size;
    list_add_tail(&mapping->list, &domain->mappings);

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
    struct iommu_mapping *iter;
    list_for_each_entry(iter, &domain->mappings, list) {
        if (iter->dma_addr == addr) {
            mapping = iter;
            list_del(&iter->list);
            break;
        }
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
    if (type != IOMMU_DOMAIN_BYPASS && type != IOMMU_DOMAIN_DMA)
        return NULL;

    if (!iova_base)
        iova_base = IOMMU_IOVA_DEFAULT_BASE;
    if (!iova_size)
        iova_size = IOMMU_IOVA_DEFAULT_SIZE;
    iova_base = ALIGN_UP(iova_base, CONFIG_PAGE_SIZE);
    iova_size = ALIGN_UP(iova_size, CONFIG_PAGE_SIZE);
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
    spin_init(&domain->lock);
    INIT_LIST_HEAD(&domain->mappings);
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
        spin_init(&iommu_passthrough_domain.lock);
        INIT_LIST_HEAD(&iommu_passthrough_domain.mappings);
        __atomic_store_n(&iommu_passthrough_domain_init_done, true,
                         __ATOMIC_RELEASE);
    }
    spin_unlock(&iommu_passthrough_domain_init_lock);

    return &iommu_passthrough_domain;
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
        list_del(&m->list);
        if (domain->ops && domain->ops->unmap)
            domain->ops->unmap(domain, m->iova_base, m->map_size);
        kfree(m);
    }
    spin_unlock_irqrestore(&domain->lock, irq_flags);
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

static int iommu_attach_device_internal(struct iommu_domain *domain,
                                        struct device *dev, bool owned) {
    if (!domain || !dev)
        return -EINVAL;
    dev->iommu_domain = domain;
    dev->iommu_domain_owned = owned;
    dma_set_ops(dev, iommu_get_dma_ops());
    return 0;
}

int iommu_attach_device(struct iommu_domain *domain, struct device *dev) {
    return iommu_attach_device_internal(domain, dev, false);
}

int iommu_attach_default_domain(struct device *dev) {
    if (!dev)
        return -EINVAL;

    const struct iommu_hw_ops *ops = NULL;
    void *priv = NULL;
    spin_lock(&iommu_hw_ops_lock);
    ops = iommu_hw_ops;
    priv = iommu_hw_ops_priv;
    spin_unlock(&iommu_hw_ops_lock);

    struct iommu_domain *domain = NULL;
    bool owned = false;
    if (ops && ops->alloc_default_domain)
        domain = ops->alloc_default_domain(dev, &owned, priv);
    if (!domain) {
        domain = iommu_get_passthrough_domain();
        owned = false;
    }
    return iommu_attach_device_internal(domain, dev, owned);
}

void iommu_detach_device(struct device *dev) {
    if (!dev)
        return;
    struct iommu_domain *domain = dev->iommu_domain;
    bool owned = dev->iommu_domain_owned;
    dev->iommu_domain = NULL;
    dev->iommu_domain_owned = false;
    dma_set_ops(dev, NULL);
    if (owned)
        iommu_domain_destroy(domain);
}

struct iommu_domain *iommu_get_domain(struct device *dev) {
    return dev ? dev->iommu_domain : NULL;
}

int iommu_register_hw_ops(const struct iommu_hw_ops *ops, void *priv) {
    if (!ops || !ops->alloc_default_domain)
        return -EINVAL;
    spin_lock(&iommu_hw_ops_lock);
    if (iommu_hw_ops) {
        spin_unlock(&iommu_hw_ops_lock);
        return -EBUSY;
    }
    iommu_hw_ops = ops;
    iommu_hw_ops_priv = priv;
    spin_unlock(&iommu_hw_ops_lock);
    return 0;
}

void iommu_unregister_hw_ops(const struct iommu_hw_ops *ops) {
    if (!ops)
        return;
    spin_lock(&iommu_hw_ops_lock);
    if (iommu_hw_ops == ops) {
        iommu_hw_ops = NULL;
        iommu_hw_ops_priv = NULL;
    }
    spin_unlock(&iommu_hw_ops_lock);
}

const struct dma_ops *iommu_get_dma_ops(void) {
    return &iommu_dma_ops;
}
