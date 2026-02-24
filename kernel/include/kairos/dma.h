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

/* DMA directions */
#define DMA_BIDIRECTIONAL 0
#define DMA_TO_DEVICE     1
#define DMA_FROM_DEVICE   2

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
static inline paddr_t dma_map_single(void *ptr, size_t size, int direction) {
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
    return virt_to_phys(ptr);
}

/**
 * dma_unmap_single - Unmap a DMA buffer
 * @addr: Physical address returned by dma_map_single
 * @size: Size of the buffer
 * @direction: Data direction
 */
static inline void dma_unmap_single(paddr_t addr, size_t size, int direction) {
    void *ptr = phys_to_virt(addr);
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

#endif
