/**
 * kernel/core/mm/dma.c - DMA backend dispatch
 */

#include <kairos/config.h>
#include <kairos/device.h>
#include <kairos/dma.h>
#include <kairos/mm.h>
#include <kairos/string.h>

static bool dma_addr_end_inclusive(dma_addr_t addr, size_t size, dma_addr_t *end_out) {
    if (!size || !end_out)
        return false;
    if ((dma_addr_t)(size - 1) > (DMA_MASK_FULL - addr))
        return false;
    *end_out = addr + (dma_addr_t)(size - 1);
    return true;
}

void dma_set_mask(struct device *dev, dma_addr_t mask) {
    if (!dev)
        return;
    dev->dma_mask = mask;
    dev->dma_mask_valid = true;
}

dma_addr_t dma_get_mask(struct device *dev) {
    if (dev && dev->dma_mask_valid)
        return dev->dma_mask;
    return DMA_MASK_FULL;
}

int dma_set_aperture(struct device *dev, dma_addr_t start, dma_addr_t end) {
    if (!dev)
        return -EINVAL;
    if (end < start)
        return -EINVAL;
    dev->dma_aperture_start = start;
    dev->dma_aperture_end = end;
    dev->dma_aperture_valid = true;
    return 0;
}

void dma_clear_aperture(struct device *dev) {
    if (!dev)
        return;
    dev->dma_aperture_start = 0;
    dev->dma_aperture_end = 0;
    dev->dma_aperture_valid = false;
}

bool dma_addr_allowed(struct device *dev, dma_addr_t addr, size_t size) {
    dma_addr_t end = 0;
    if (!dma_addr_end_inclusive(addr, size, &end))
        return false;

    dma_addr_t mask = dma_get_mask(dev);
    if ((addr & ~mask) != 0 || (end & ~mask) != 0)
        return false;

    if (dev && dev->dma_aperture_valid) {
        if (addr < dev->dma_aperture_start || end > dev->dma_aperture_end)
            return false;
    }
    return true;
}

static dma_addr_t dma_direct_map_single(struct device *dev, void *ptr, size_t size,
                                        int direction) {
    (void)dev;
    if (!ptr || !size)
        return 0;
#ifdef ARCH_aarch64
    if (direction == DMA_TO_DEVICE) {
        dma_cache_clean_range(ptr, size);
    } else if (direction == DMA_FROM_DEVICE ||
               direction == DMA_BIDIRECTIONAL) {
        dma_cache_clean_inval_range(ptr, size);
    }
#else
    (void)size;
    (void)direction;
#endif
    return (dma_addr_t)virt_to_phys(ptr);
}

static void dma_direct_unmap_single(struct device *dev, dma_addr_t addr, size_t size,
                                    int direction) {
    (void)dev;
    void *ptr = phys_to_virt((paddr_t)addr);
#ifdef ARCH_aarch64
    if (direction == DMA_FROM_DEVICE) {
        dma_cache_inval_range(ptr, size);
    } else if (direction == DMA_BIDIRECTIONAL) {
        dma_cache_clean_inval_range(ptr, size);
    } else {
        (void)ptr;
    }
#else
    (void)ptr;
    (void)size;
    (void)direction;
#endif
}

static void *dma_direct_alloc_coherent(struct device *dev, size_t size,
                                       dma_addr_t *dma_handle) {
    (void)dev;
    if (!size)
        return NULL;

    size_t alloc_size = ALIGN_UP(size, CONFIG_PAGE_SIZE);
    size_t page_count = alloc_size / CONFIG_PAGE_SIZE;
    paddr_t pa = pmm_alloc_pages(page_count);
    if (!pa)
        return NULL;

    void *ptr = phys_to_virt(pa);
    memset(ptr, 0, alloc_size);
#ifdef ARCH_aarch64
    dma_cache_clean_inval_range(ptr, alloc_size);
#endif
    if (dma_handle)
        *dma_handle = (dma_addr_t)pa;
    return ptr;
}

static void dma_direct_free_coherent(struct device *dev, void *cpu_addr, size_t size,
                                     dma_addr_t dma_handle) {
    (void)dev;
    if (!cpu_addr || !size)
        return;

    size_t alloc_size = ALIGN_UP(size, CONFIG_PAGE_SIZE);
    size_t page_count = alloc_size / CONFIG_PAGE_SIZE;
    paddr_t pa = dma_handle ? (paddr_t)dma_handle : virt_to_phys(cpu_addr);
    if (!pa)
        return;
    pmm_free_pages(pa, page_count);
}

static const struct dma_ops dma_direct_ops = {
    .map_single = dma_direct_map_single,
    .unmap_single = dma_direct_unmap_single,
    .alloc_coherent = dma_direct_alloc_coherent,
    .free_coherent = dma_direct_free_coherent,
};

const struct dma_ops *dma_get_direct_ops(void) {
    return &dma_direct_ops;
}

void dma_set_ops(struct device *dev, const struct dma_ops *ops) {
    if (!dev)
        return;
    dev->dma_ops = ops;
}

const struct dma_ops *dma_get_ops(struct device *dev) {
    if (dev && dev->dma_ops)
        return dev->dma_ops;
    return dma_get_direct_ops();
}

dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size, int direction) {
    const struct dma_ops *ops = dma_get_ops(dev);
    dma_addr_t dma = ops->map_single(dev, ptr, size, direction);
    if (!dma)
        return 0;
    if (!dma_addr_allowed(dev, dma, size)) {
        ops->unmap_single(dev, dma, size, direction);
        return 0;
    }
    return dma;
}

void dma_unmap_single(struct device *dev, dma_addr_t addr, size_t size, int direction) {
    const struct dma_ops *ops = dma_get_ops(dev);
    ops->unmap_single(dev, addr, size, direction);
}

void *dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle) {
    const struct dma_ops *ops = dma_get_ops(dev);
    dma_addr_t local_handle = 0;
    dma_addr_t *handle_ptr = dma_handle ? dma_handle : &local_handle;
    void *cpu = ops->alloc_coherent(dev, size, handle_ptr);
    if (!cpu)
        return NULL;
    if (!dma_addr_allowed(dev, *handle_ptr, size)) {
        ops->free_coherent(dev, cpu, size, *handle_ptr);
        if (dma_handle)
            *dma_handle = 0;
        return NULL;
    }
    return cpu;
}

void dma_free_coherent(struct device *dev, void *cpu_addr, size_t size,
                       dma_addr_t dma_handle) {
    const struct dma_ops *ops = dma_get_ops(dev);
    ops->free_coherent(dev, cpu_addr, size, dma_handle);
}
