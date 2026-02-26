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

#define IOMMU_CAP_MAP_UNMAP      (1ULL << 0)
#define IOMMU_CAP_PASID          (1ULL << 1)
#define IOMMU_CAP_PRI            (1ULL << 2)
#define IOMMU_CAP_ATS            (1ULL << 3)
#define IOMMU_CAP_INT_REMAP      (1ULL << 4)
#define IOMMU_CAP_FAULT_REPORT   (1ULL << 5)
#define IOMMU_CAP_FAULT_DISABLE  (1ULL << 6)
#define IOMMU_CAP_FAULT_RECOVER  (1ULL << 7)

enum iommu_fault_policy {
    IOMMU_FAULT_POLICY_REPORT = 0,
    IOMMU_FAULT_POLICY_DISABLE = 1,
    IOMMU_FAULT_POLICY_RECOVER = 2,
};

struct iommu_domain;

struct iommu_domain_ops {
    int (*map)(struct iommu_domain *domain, dma_addr_t iova, paddr_t paddr,
               size_t size, uint32_t prot);
    void (*unmap)(struct iommu_domain *domain, dma_addr_t iova, size_t size);
    int (*bind_pasid)(struct iommu_domain *domain, struct device *dev,
                      uint32_t pasid, uint32_t flags);
    int (*unbind_pasid)(struct iommu_domain *domain, struct device *dev,
                        uint32_t pasid);
    int (*enable_pri)(struct iommu_domain *domain, struct device *dev,
                      uint32_t queue_depth);
    int (*enable_ats)(struct iommu_domain *domain, struct device *dev,
                      uint32_t flags);
    int (*set_fault_policy)(struct iommu_domain *domain,
                            enum iommu_fault_policy policy);
    int (*recover_faults)(struct iommu_domain *domain, uint32_t budget,
                          uint32_t *recovered);
    void (*release)(struct iommu_domain *domain);
};

struct iommu_hw_ops {
    const char *name;
    int priority;
    int (*match)(struct device *dev, void *priv);
    struct iommu_domain *(*alloc_default_domain)(struct device *dev, bool *owned,
                                                 void *priv);
};

struct virtio_iommu_health {
    bool ready;
    bool faulted;
    uint64_t req_submit_count;
    uint64_t req_complete_count;
    uint64_t req_timeout_count;
    uint64_t req_error_count;
    uint8_t last_req_type;
    int32_t last_req_ret;
    uint8_t last_fault_req_type;
    int32_t last_fault_ret;
    uint64_t last_fault_ticks;
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
    uint64_t caps;
    enum iommu_fault_policy fault_policy;
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
void iommu_domain_set_caps(struct iommu_domain *domain, uint64_t caps);
uint64_t iommu_domain_get_caps(const struct iommu_domain *domain);
bool iommu_domain_has_cap(const struct iommu_domain *domain, uint64_t cap);
int iommu_domain_bind_pasid(struct iommu_domain *domain, struct device *dev,
                            uint32_t pasid, uint32_t flags);
int iommu_domain_unbind_pasid(struct iommu_domain *domain, struct device *dev,
                              uint32_t pasid);
int iommu_domain_enable_pri(struct iommu_domain *domain, struct device *dev,
                            uint32_t queue_depth);
int iommu_domain_enable_ats(struct iommu_domain *domain, struct device *dev,
                            uint32_t flags);
int iommu_domain_set_fault_policy(struct iommu_domain *domain,
                                  enum iommu_fault_policy policy);
enum iommu_fault_policy
iommu_domain_get_fault_policy(const struct iommu_domain *domain);
int iommu_domain_recover_faults(struct iommu_domain *domain, uint32_t budget,
                                uint32_t *recovered);

int iommu_attach_device(struct iommu_domain *domain, struct device *dev);
int iommu_attach_default_domain(struct device *dev);
void iommu_detach_device(struct device *dev);
struct iommu_domain *iommu_get_domain(struct device *dev);

int iommu_register_hw_ops(const struct iommu_hw_ops *ops, void *priv);
void iommu_unregister_hw_ops(const struct iommu_hw_ops *ops);

const struct dma_ops *iommu_get_dma_ops(void);
int virtio_iommu_health_snapshot(struct virtio_iommu_health *out);

#endif
