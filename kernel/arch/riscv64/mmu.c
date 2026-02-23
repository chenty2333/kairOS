/**
 * kernel/arch/riscv64/mmu.c - RISC-V 64 MMU (Sv39) Implementation
 */

#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include "../../arch/common/mmu_common.h"

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define PTES_PER_PAGE 512
#define VPN_BITS 9
#define VPN_MASK (PTES_PER_PAGE - 1)
#define LEVELS 3

#define PTE_V (1UL << 0)
#define PTE_R (1UL << 1)
#define PTE_W (1UL << 2)
#define PTE_X (1UL << 3)
#define PTE_U (1UL << 4)
#define PTE_G (1UL << 5)
#define PTE_A (1UL << 6)
#define PTE_D (1UL << 7)
#define PTE_PPN_SHIFT 10
#define PTE_RSW0 (1UL << 8)

#define SATP_MODE_SV39 (8UL << 60)
static paddr_t kernel_pgdir;
extern char _kernel_start[], _kernel_end[];

/* --- Internal Helpers --- */

static inline size_t va_to_vpn(vaddr_t va, int level) {
    return (va >> (PAGE_SHIFT + (level * VPN_BITS))) & VPN_MASK;
}

static inline uint64_t *pte_to_pa(uint64_t pte) {
    return (uint64_t *)((pte >> PTE_PPN_SHIFT) << PAGE_SHIFT);
}

static inline uint64_t pa_to_pte(paddr_t pa) {
    return ((pa >> PAGE_SHIFT) << PTE_PPN_SHIFT);
}

static inline bool pte_is_leaf(uint64_t pte) {
    return (pte & (PTE_R | PTE_W | PTE_X)) != 0;
}

static inline bool pte_is_branch(uint64_t pte) {
    return (pte & PTE_V) && !pte_is_leaf(pte);
}

/* --- mmu_ops callbacks for common walker --- */

static bool riscv_pte_valid(uint64_t pte) {
    return (pte & PTE_V) != 0;
}

static paddr_t riscv_pte_addr(uint64_t pte) {
    return (paddr_t)pte_to_pa(pte);
}

static uint64_t riscv_make_branch(paddr_t pa) {
    return pa_to_pte(pa) | PTE_V;
}

static size_t riscv_va_index(vaddr_t va, int level) {
    return va_to_vpn(va, level);
}

static const struct mmu_ops riscv_mmu_ops = {
    .levels      = LEVELS,
    .pte_valid   = riscv_pte_valid,
    .pte_addr    = riscv_pte_addr,
    .make_branch = riscv_make_branch,
    .va_index    = riscv_va_index,
};

/* Convenience wrapper */
static uint64_t *walk_pgtable(paddr_t table, vaddr_t va, bool create) {
    return mmu_walk_pgtable(&riscv_mmu_ops, table, va, create);
}

static paddr_t pt_alloc(void) {
    paddr_t pa = pmm_alloc_page();
    if (!pa) {
        return 0;
    }
    /* Validate that pa is in the valid RAM region */
    if (!phys_to_page(pa)) {
        pr_err("pt_alloc: pmm returned invalid address %p\n", (void *)pa);
        return 0;
    }
    memset(phys_to_virt(pa), 0, PAGE_SIZE);
    return pa;
}

static void destroy_pt(paddr_t table, int level) {
    if (!table || table == kernel_pgdir) {
        return;
    }

    uint64_t *pt = (uint64_t *)phys_to_virt(table);
    if (level > 0) {
        for (size_t i = 0; i < PTES_PER_PAGE; i++) {
            uint64_t pte = pt[i];
            if (pte_is_branch(pte)) {
                destroy_pt((paddr_t)pte_to_pa(pte), level - 1);
            }
        }
    }

    pmm_free_page(table);
}

static paddr_t copy_pt(paddr_t src, int level) {
    paddr_t dst = pt_alloc();
    if (!dst) {
        return 0;
    }

    uint64_t *src_pt = (uint64_t *)phys_to_virt(src);
    uint64_t *dst_pt = (uint64_t *)phys_to_virt(dst);
    memcpy(dst_pt, src_pt, PAGE_SIZE);

    for (size_t i = 0; i < PTES_PER_PAGE; i++) {
        uint64_t pte = dst_pt[i];
        if (!(pte & PTE_V)) {
            continue;
        }

        /* Strip any user mapping that leaked into the kernel tables. */
        if (pte & PTE_U) {
            dst_pt[i] = 0;
            continue;
        }

        if (level > 0 && pte_is_branch(pte)) {
            paddr_t child_src = (paddr_t)pte_to_pa(pte);
            paddr_t child_dst = copy_pt(child_src, level - 1);
            if (!child_dst) {
                destroy_pt(dst, level);
                return 0;
            }
            uint64_t flags = pte & ((1UL << PTE_PPN_SHIFT) - 1);
            dst_pt[i] = pa_to_pte(child_dst) | flags;
        }
    }

    return dst;
}

static uint64_t flags_to_pte(uint64_t f) {
    uint64_t p = PTE_V | PTE_A | PTE_D;
    if (f & PTE_READ) {
        p |= PTE_R;
    }
    if (f & PTE_WRITE) {
        p |= PTE_W;
    }
    if (f & PTE_EXEC) {
        p |= PTE_X;
    }
    if (f & PTE_USER) {
        p |= PTE_U;
    }
    if (f & PTE_GLOBAL) {
        p |= PTE_G;
    }
    if (f & PTE_COW) {
        p |= PTE_RSW0;
    }
    return p;
}

static uint64_t pte_to_flags(uint64_t pte) {
    if (!(pte & PTE_V))
        return 0;
    uint64_t f = PTE_VALID;
    if (pte & PTE_R)
        f |= PTE_READ;
    if (pte & PTE_W)
        f |= PTE_WRITE;
    if (pte & PTE_X)
        f |= PTE_EXEC;
    if (pte & PTE_U)
        f |= PTE_USER;
    if (pte & PTE_G)
        f |= PTE_GLOBAL;
    if (pte & PTE_RSW0)
        f |= PTE_COW;
    return f;
}

/* --- Public Interface --- */

void arch_mmu_init(const struct boot_info *bi) {
    if (!bi) {
        panic("mmu: missing boot info");
    }
    pr_info("MMU: init start (hhdm=%p)\n", (void *)bi->hhdm_offset);
    if (!(kernel_pgdir = pt_alloc())) {
        panic("mmu: init failed");
    }

    /* 1. Map HHDM for all RAM-backed memory regions */
    for (uint32_t i = 0; i < bi->memmap_count; i++) {
        const struct boot_memmap_entry *e = &bi->memmap[i];
        if (!boot_mem_is_ram(e->type))
            continue;
        mmu_map_region(kernel_pgdir, bi->hhdm_offset + e->base, e->base,
                   e->length, PTE_READ | PTE_WRITE);
    }

    /* 1b. Map framebuffer MMIO into HHDM */
    if (bi->framebuffer_count == 0) {
        pr_warn("MMU: no framebuffers to map\n");
    }
    for (uint32_t i = 0; i < bi->framebuffer_count; i++) {
        paddr_t phys = (paddr_t)bi->framebuffers[i].phys;
        if (!phys || !bi->framebuffers[i].size)
            continue;
        if (bi->hhdm_offset && phys >= bi->hhdm_offset)
            phys -= bi->hhdm_offset;
        size_t size = ALIGN_UP((size_t)bi->framebuffers[i].size, PAGE_SIZE);
        pr_info("MMU: map fb%u phys=%p size=%zu -> %p\n", i, (void *)phys,
                size, (void *)(bi->hhdm_offset + phys));
        if (mmu_map_region(kernel_pgdir, bi->hhdm_offset + phys, phys, size,
                       PTE_READ | PTE_WRITE) < 0) {
            pr_warn("MMU: map fb%u failed\n", i);
        }
    }

    /* 2. Map kernel high half */
    paddr_t kphys = bi->kernel_phys_base;
    vaddr_t kvirt = bi->kernel_virt_base;
    size_t ksize = ALIGN_UP((paddr_t)_kernel_end - (paddr_t)_kernel_start,
                            PAGE_SIZE);
    mmu_map_region(kernel_pgdir, kvirt, kphys, ksize,
               PTE_READ | PTE_WRITE | PTE_EXEC);

    const struct platform_desc *plat = platform_get();
    if (plat) {
        for (int i = 0; i < plat->num_early_mmio; i++) {
            paddr_t base = plat->early_mmio[i].base;
            size_t  size = plat->early_mmio[i].size;
            mmu_map_region(kernel_pgdir, base, base, size,
                           PTE_READ | PTE_WRITE);
        }
    }

    arch_mmu_switch(kernel_pgdir);
    pr_info("MMU: Sv39 paging enabled (HHDM=%p)\n",
            (void *)bi->hhdm_offset);
}

paddr_t arch_mmu_create_table(void) {
    return copy_pt(kernel_pgdir, LEVELS - 1);
}

void arch_mmu_destroy_table(paddr_t table) {
    destroy_pt(table, LEVELS - 1);
}

int arch_mmu_map(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags) {
    uint64_t *pte = walk_pgtable(table, va, true);
    if (!pte) {
        return -ENOMEM;
    }
    *pte = pa_to_pte(pa) | flags_to_pte(flags);
    return 0;
}

int arch_mmu_map_merge(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags) {
    uint64_t *pte = walk_pgtable(table, va, true);
    if (!pte) {
        return -ENOMEM;
    }
    uint64_t new_flags = flags_to_pte(flags);
    if (*pte & PTE_V) {
        paddr_t existing = (paddr_t)pte_to_pa(*pte);
        if (existing != pa) {
            return -EEXIST;
        }
        *pte |= new_flags;
        return 0;
    }
    *pte = pa_to_pte(pa) | new_flags;
    return 0;
}

int arch_mmu_unmap(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & PTE_V)) {
        return -ENOENT;
    }
    *pte = 0;
    arch_mmu_flush_tlb_page(va);
    return 0;
}

paddr_t arch_mmu_translate(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    return (pte && (*pte & PTE_V))
               ? (paddr_t)pte_to_pa(*pte) | (va & (PAGE_SIZE - 1))
               : 0;
}

uint64_t arch_mmu_get_pte(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & PTE_V))
        return 0;
    paddr_t pa = (paddr_t)pte_to_pa(*pte);
    return ((pa >> PAGE_SHIFT) << 10) | pte_to_flags(*pte);
}

int arch_mmu_set_pte(paddr_t table, vaddr_t va, uint64_t pte) {
    uint64_t *entry = walk_pgtable(table, va, false);
    if (!entry)
        return -ENOENT;
    paddr_t pa = (paddr_t)((pte >> 10) << PAGE_SHIFT);
    uint64_t flags = pte & ((1ULL << 10) - 1);
    if (!(flags & PTE_VALID)) {
        *entry = 0;
        return 0;
    }
    *entry = pa_to_pte(pa) | flags_to_pte(flags);
    return 0;
}

void arch_mmu_switch(paddr_t table) {
    uint64_t satp = SATP_MODE_SV39 | (table >> PAGE_SHIFT);
    __asm__ __volatile__("csrw satp, %0\nsfence.vma" : : "r"(satp) : "memory");
}

paddr_t arch_mmu_current(void) {
    uint64_t satp;
    __asm__ __volatile__("csrr %0, satp" : "=r"(satp));
    return (satp & ((1UL << 44) - 1)) << PAGE_SHIFT;
}

void arch_mmu_flush_tlb(void) {
    __asm__ __volatile__("sfence.vma" ::: "memory");
}

void arch_mmu_flush_tlb_page(vaddr_t va) {
    __asm__ __volatile__("sfence.vma %0" ::"r"(va) : "memory");
}

paddr_t arch_mmu_get_kernel_pgdir(void) {
    return kernel_pgdir;
}

/* --- KVM Helpers --- */

void *phys_to_virt(paddr_t addr) {
    const struct boot_info *bi = boot_info_get();
    if (bi && bi->hhdm_offset) {
        return (void *)(addr + bi->hhdm_offset);
    }
    return (void *)addr;
}

paddr_t virt_to_phys(void *addr) {
    const struct boot_info *bi = boot_info_get();
    if (!bi) {
        return (paddr_t)addr;
    }
    uint64_t va = (uint64_t)addr;
    if (bi->hhdm_offset &&
        va >= bi->hhdm_offset &&
        va < bi->hhdm_offset + bi->phys_mem_max) {
        return (paddr_t)(va - bi->hhdm_offset);
    }
    if (bi->kernel_virt_base &&
        va >= bi->kernel_virt_base) {
        uint64_t ksize = (uint64_t)_kernel_end - (uint64_t)_kernel_start;
        if (va <= bi->kernel_virt_base + ksize) {
            return (paddr_t)(va - bi->kernel_virt_base + bi->kernel_phys_base);
        }
    }
    return (paddr_t)addr;
}

void *ioremap(paddr_t phys, size_t size) {
    paddr_t base = ALIGN_DOWN(phys, PAGE_SIZE);
    size_t offset = phys - base;
    size_t map_size = ALIGN_UP(offset + size, PAGE_SIZE);
    vaddr_t va = (vaddr_t)phys_to_virt(base);

    if (mmu_map_region(arch_mmu_get_kernel_pgdir(), va, base, map_size,
                       PTE_READ | PTE_WRITE | PTE_DEVICE) < 0) {
        pr_err("ioremap: failed to map %p size %zu\n", (void *)phys, size);
        return NULL;
    }
    arch_mmu_flush_tlb();

    return (void *)(va + offset);
}

void iounmap(void *virt __attribute__((unused))) {}
