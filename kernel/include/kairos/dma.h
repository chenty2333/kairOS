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

/**
 * dma_map_single - Map a virtual address for DMA
 * @ptr: Virtual address of the buffer
 * @size: Size of the buffer
 * @direction: Data direction
 *
 * Returns physical address (dma_addr_t) accessible by the device.
 */
static inline dma_addr_t dma_map_single(void *ptr, size_t size, int direction) {
#ifdef ARCH_aarch64
    if (direction == DMA_TO_DEVICE) {
        dma_cache_clean_range(ptr, size);
    } else if (direction == DMA_FROM_DEVICE) {
        dma_cache_clean_inval_range(ptr, size);
    } else if (direction == DMA_BIDIRECTIONAL) {
        dma_cache_clean_inval_range(ptr, size);
    }
#else
    (void)size;
    (void)direction;
#endif
    return (dma_addr_t)virt_to_phys(ptr);
}

/**
 * dma_unmap_single - Unmap a DMA buffer
 * @addr: Physical address returned by dma_map_single
 * @size: Size of the buffer
 * @direction: Data direction
 */
static inline void dma_unmap_single(dma_addr_t addr, size_t size, int direction) {
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

static inline void *dma_alloc_coherent(size_t size, dma_addr_t *dma_handle) {
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

static inline void dma_free_coherent(void *cpu_addr, size_t size) {
    if (!cpu_addr || !size)
        return;

    size_t alloc_size = ALIGN_UP(size, CONFIG_PAGE_SIZE);
    size_t page_count = alloc_size / CONFIG_PAGE_SIZE;
    paddr_t pa = virt_to_phys(cpu_addr);
    if (!pa)
        return;
    pmm_free_pages(pa, page_count);
}

#endif
