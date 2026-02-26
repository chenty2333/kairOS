/**
 * kernel/include/kairos/iommu.h - IOMMU core interfaces
 */

#ifndef _KAIROS_IOMMU_H
#define _KAIROS_IOMMU_H

#include <kairos/dma.h>
#include <kairos/list.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>

struct device;

#define IOMMU_IOVA_DEFAULT_BASE 0x0000000100000000ULL
#define IOMMU_IOVA_DEFAULT_SIZE (1ULL << 30)

enum iommu_domain_type {
    IOMMU_DOMAIN_BYPASS = 0,
    IOMMU_DOMAIN_DMA = 1,
};

#define IOMMU_PROT_READ  (1U << 0)
#define IOMMU_PROT_WRITE (1U << 1)

struct iommu_domain;

struct iommu_domain_ops {
    int (*map)(struct iommu_domain *domain, dma_addr_t iova, paddr_t paddr,
               size_t size, uint32_t prot);
    void (*unmap)(struct iommu_domain *domain, dma_addr_t iova, size_t size);
    void (*release)(struct iommu_domain *domain);
};

struct iommu_hw_ops {
    const char *name;
    int priority;
    int (*match)(struct device *dev, void *priv);
    struct iommu_domain *(*alloc_default_domain)(struct device *dev, bool *owned,
                                                 void *priv);
};

struct iommu_domain {
    enum iommu_domain_type type;
    const struct iommu_domain_ops *ops;
    void *ops_priv;
    spinlock_t lock;
    struct list_head mappings;
    dma_addr_t iova_base;
    dma_addr_t iova_limit;
    dma_addr_t iova_cursor;
    size_t granule;
};

struct iommu_domain *iommu_domain_create(enum iommu_domain_type type,
                                         dma_addr_t iova_base,
                                         size_t iova_size);
int iommu_init(void);
struct iommu_domain *iommu_get_passthrough_domain(void);
void iommu_domain_destroy(struct iommu_domain *domain);
void iommu_domain_set_ops(struct iommu_domain *domain,
                          const struct iommu_domain_ops *ops, void *ops_priv);
int iommu_domain_set_granule(struct iommu_domain *domain, size_t granule);
size_t iommu_domain_get_granule(const struct iommu_domain *domain);

int iommu_attach_device(struct iommu_domain *domain, struct device *dev);
int iommu_attach_default_domain(struct device *dev);
void iommu_detach_device(struct device *dev);
struct iommu_domain *iommu_get_domain(struct device *dev);

int iommu_register_hw_ops(const struct iommu_hw_ops *ops, void *priv);
void iommu_unregister_hw_ops(const struct iommu_hw_ops *ops);

const struct dma_ops *iommu_get_dma_ops(void);

#endif
