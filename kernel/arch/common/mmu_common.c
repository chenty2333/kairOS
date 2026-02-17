/**
 * kernel/arch/common/mmu_common.c - Shared MMU helpers
 */

#include "mmu_common.h"

#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>

#define PAGE_SIZE 4096

paddr_t mmu_pt_alloc(void) {
    paddr_t pa = pmm_alloc_page();
    if (!pa)
        return 0;
    memset(phys_to_virt(pa), 0, PAGE_SIZE);
    return pa;
}

uint64_t *mmu_walk_pgtable(const struct mmu_ops *ops, paddr_t table,
                           vaddr_t va, bool create) {
    uint64_t *pt = (uint64_t *)phys_to_virt(table);
    for (int level = ops->levels - 1; level > 0; level--) {
        size_t idx = ops->va_index(va, level);
        if (!ops->pte_valid(pt[idx])) {
            if (!create)
                return NULL;
            paddr_t next = mmu_pt_alloc();
            if (!next)
                return NULL;
            pt[idx] = ops->make_branch(next);
        }
        pt = (uint64_t *)phys_to_virt(ops->pte_addr(pt[idx]));
    }
    return &pt[ops->va_index(va, 0)];
}

int mmu_map_region(paddr_t root, vaddr_t va, paddr_t pa, size_t sz,
                   uint64_t flags) {
    for (size_t off = 0; off < sz; off += PAGE_SIZE) {
        if (arch_mmu_map(root, va + off, pa + off, flags) < 0)
            return -1;
    }
    return 0;
}
