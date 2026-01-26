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

/**
 * dma_map_single - Map a virtual address for DMA
 * @ptr: Virtual address of the buffer
 * @size: Size of the buffer
 * @direction: Data direction
 *
 * Returns physical address (dma_addr_t) accessible by the device.
 */
static inline paddr_t dma_map_single(void *ptr, size_t size, int direction) {
    (void)size;      /* Unused in direct-map systems */
    (void)direction; /* Unused in cache-coherent systems */
    
    return virt_to_phys(ptr);
}

/**
 * dma_unmap_single - Unmap a DMA buffer
 * @addr: Physical address returned by dma_map_single
 * @size: Size of the buffer
 * @direction: Data direction
 */
static inline void dma_unmap_single(paddr_t addr, size_t size, int direction) {
    (void)addr;
    (void)size;
    (void)direction;
    /* 
     * TODO: On non-coherent architectures (like some ARM/RISC-V boards),
     * this is where we would invalidate/flush CPU caches.
     */
}

#endif
