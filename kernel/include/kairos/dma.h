/**
 * kernel/include/kairos/dma.h - Direct Memory Access (DMA) Abstraction
 *
 * Minimal DMA mapping layer.
 * Future-proofs against IOMMUs and non-coherent cache architectures.
 */

#ifndef _KAIROS_DMA_H
#define _KAIROS_DMA_H

#include <kairos/types.h>
#include <kairos/mm.h>
#include <kairos/string.h>

/* DMA directions */
#define DMA_BIDIRECTIONAL 0
#define DMA_TO_DEVICE     1
#define DMA_FROM_DEVICE   2

typedef paddr_t dma_addr_t;
struct device;

struct dma_ops {
    dma_addr_t (*map_single)(struct device *dev, void *ptr, size_t size,
                             int direction);
    void (*unmap_single)(struct device *dev, dma_addr_t addr, size_t size,
                         int direction);
    void *(*alloc_coherent)(struct device *dev, size_t size,
                            dma_addr_t *dma_handle);
    void (*free_coherent)(struct device *dev, void *cpu_addr, size_t size,
                          dma_addr_t dma_handle);
};

#ifdef ARCH_aarch64
static inline size_t dma_cache_line_size(void) {
    uint64_t ctr_el0;
    __asm__ __volatile__("mrs %0, ctr_el0" : "=r"(ctr_el0));
    /* CTR_EL0.DminLine encodes log2(words); cache line bytes = 4 << DminLine. */
    return (size_t)(4U << ((ctr_el0 >> 16) & 0xFU));
}

static inline void dma_cache_clean_range(void *ptr, size_t size) {
    if (!ptr || size == 0)
        return;
    size_t line = dma_cache_line_size();
    uintptr_t start = ALIGN_DOWN((uintptr_t)ptr, line);
    uintptr_t end = ALIGN_UP((uintptr_t)ptr + size, line);
    for (uintptr_t addr = start; addr < end; addr += line) {
        __asm__ __volatile__("dc cvac, %0" :: "r"(addr) : "memory");
    }
    __asm__ __volatile__("dsb ish" ::: "memory");
}

static inline void dma_cache_clean_inval_range(void *ptr, size_t size) {
    if (!ptr || size == 0)
        return;
    size_t line = dma_cache_line_size();
    uintptr_t start = ALIGN_DOWN((uintptr_t)ptr, line);
    uintptr_t end = ALIGN_UP((uintptr_t)ptr + size, line);
    for (uintptr_t addr = start; addr < end; addr += line) {
        __asm__ __volatile__("dc civac, %0" :: "r"(addr) : "memory");
    }
    __asm__ __volatile__("dsb ish" ::: "memory");
}

static inline void dma_cache_inval_range(void *ptr, size_t size) {
    if (!ptr || size == 0)
        return;
    size_t line = dma_cache_line_size();
    uintptr_t start = ALIGN_DOWN((uintptr_t)ptr, line);
    uintptr_t end = ALIGN_UP((uintptr_t)ptr + size, line);
    for (uintptr_t addr = start; addr < end; addr += line) {
        __asm__ __volatile__("dc ivac, %0" :: "r"(addr) : "memory");
    }
    __asm__ __volatile__("dsb ish" ::: "memory");
}
#endif

void dma_set_ops(struct device *dev, const struct dma_ops *ops);
const struct dma_ops *dma_get_ops(struct device *dev);
const struct dma_ops *dma_get_direct_ops(void);

dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size, int direction);
void dma_unmap_single(struct device *dev, dma_addr_t addr, size_t size, int direction);
void *dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle);
void dma_free_coherent(struct device *dev, void *cpu_addr, size_t size,
                       dma_addr_t dma_handle);

#endif
