/**
 * kernel/arch/common/mmu_common.h - Shared MMU helpers
 *
 * Provides a parameterized page table walker and common utility functions
 * shared across all architectures. Each architecture supplies an mmu_ops
 * struct describing its page table format.
 */

#ifndef _KAIROS_MMU_COMMON_H
#define _KAIROS_MMU_COMMON_H

#include <kairos/mm.h>
#include <kairos/types.h>

struct mmu_ops {
    int levels;                              /* page table levels */
    bool (*pte_valid)(uint64_t pte);         /* is PTE valid? */
    paddr_t (*pte_addr)(uint64_t pte);       /* extract next-level PA */
    uint64_t (*make_branch)(paddr_t pa);     /* construct branch PTE */
    size_t (*va_index)(vaddr_t va, int lvl); /* VA index for level */
};

/**
 * mmu_walk_pgtable - Walk a page table to find the leaf PTE for a VA.
 * @ops:    Architecture-specific page table operations
 * @table:  Physical address of the root page table
 * @va:     Virtual address to look up
 * @create: If true, allocate intermediate tables as needed
 *
 * Returns pointer to the leaf PTE, or NULL if not found/allocation failed.
 */
uint64_t *mmu_walk_pgtable(const struct mmu_ops *ops, paddr_t table,
                           vaddr_t va, bool create);

/**
 * mmu_pt_alloc - Allocate and zero a page table page.
 * Shared by all architectures.
 */
paddr_t mmu_pt_alloc(void);

/**
 * mmu_map_region - Map a contiguous physical region page-by-page.
 */
int mmu_map_region(paddr_t root, vaddr_t va, paddr_t pa, size_t sz,
                   uint64_t flags);

#endif /* _KAIROS_MMU_COMMON_H */
