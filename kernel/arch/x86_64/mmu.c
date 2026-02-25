/**
 * kernel/arch/x86_64/mmu.c - x86_64 MMU implementation
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

#define PTE_P (1ULL << 0)
#define PTE_W (1ULL << 1)
#define PTE_U (1ULL << 2)
#define PTE_G (1ULL << 8)
#define PTE_SW_COW (1ULL << 9) /* software-defined bit for COW */
#define PTE_PCD (1ULL << 4)  /* Page Cache Disable */
#define PTE_NX (1ULL << 63)
#define PTE_ADDR_MASK 0x000ffffffffff000ULL

static paddr_t kernel_pgdir;
extern char _kernel_start[], _kernel_end[];

/* --- mmu_ops callbacks for common walker --- */

static bool x86_pte_valid(uint64_t pte) {
    return (pte & PTE_P) != 0;
}

static paddr_t x86_pte_addr(uint64_t pte) {
    return (paddr_t)(pte & ~0xfffULL);
}

static uint64_t x86_make_branch(paddr_t pa) {
    return pa | PTE_P | PTE_W;
}

static size_t x86_va_index(vaddr_t va, int level) {
    return (va >> (PAGE_SHIFT + level * 9)) & 0x1ff;
}

static const struct mmu_ops x86_mmu_ops = {
    .levels      = 4,
    .pte_valid   = x86_pte_valid,
    .pte_addr    = x86_pte_addr,
    .make_branch = x86_make_branch,
    .va_index    = x86_va_index,
};

static uint64_t *walk_pgtable(paddr_t table, vaddr_t va, bool create) {
    return mmu_walk_pgtable(&x86_mmu_ops, table, va, create);
}

static uint64_t flags_to_pte(uint64_t f) {
    uint64_t p = PTE_P;
    if (f & PTE_WRITE)
        p |= PTE_W;
    if (f & PTE_USER)
        p |= PTE_U;
    if (f & PTE_GLOBAL)
        p |= PTE_G;
    if (f & PTE_COW)
        p |= PTE_SW_COW;
    if (!(f & PTE_EXEC))
        p |= PTE_NX;
    if (f & PTE_DEVICE)
        p |= PTE_PCD;
    return p;
}

static uint64_t pte_to_flags(uint64_t pte) {
    if (!(pte & PTE_P))
        return 0;
    uint64_t f = PTE_VALID | PTE_READ;
    if (pte & PTE_W)
        f |= PTE_WRITE;
    if (pte & PTE_U)
        f |= PTE_USER;
    if (pte & PTE_G)
        f |= PTE_GLOBAL;
    if (pte & PTE_SW_COW)
        f |= PTE_COW;
    if (!(pte & PTE_NX))
        f |= PTE_EXEC;
    if (pte & PTE_PCD)
        f |= PTE_DEVICE;
    return f;
}

void arch_mmu_init(const struct boot_info *bi) {
    if (!bi)
        panic("mmu: missing boot info");

    kernel_pgdir = mmu_pt_alloc();
    if (!kernel_pgdir)
        panic("mmu: init failed");

    for (uint32_t i = 0; i < bi->memmap_count; i++) {
        const struct boot_memmap_entry *e = &bi->memmap[i];
        if (!boot_mem_is_ram(e->type))
            continue;
        if (e->length == 0)
            continue;
        if (mmu_map_region(kernel_pgdir, bi->hhdm_offset + e->base, e->base,
                       e->length, PTE_READ | PTE_WRITE | PTE_GLOBAL) < 0) {
            panic("mmu: HHDM map failed (base=%p len=%p)",
                  (void *)e->base, (void *)e->length);
        }
    }

    size_t ksize = ALIGN_UP((paddr_t)_kernel_end - (paddr_t)_kernel_start,
                            PAGE_SIZE);
    if (mmu_map_region(kernel_pgdir, bi->kernel_virt_base, bi->kernel_phys_base,
                   ksize, PTE_READ | PTE_WRITE | PTE_EXEC | PTE_GLOBAL) < 0) {
        panic("mmu: kernel map failed");
    }

    const struct platform_desc *plat = platform_get();
    if (plat) {
        for (int i = 0; i < plat->num_early_mmio; i++) {
            paddr_t base = plat->early_mmio[i].base;
            size_t  size = plat->early_mmio[i].size;
            if (mmu_map_region(kernel_pgdir, bi->hhdm_offset + base,
                               base, size,
                               PTE_READ | PTE_WRITE | PTE_GLOBAL) < 0) {
                panic("mmu: MMIO map failed (base=%p len=%zu)",
                      (void *)base, size);
            }
        }
    }

    arch_mmu_switch(kernel_pgdir);
    pr_info("MMU: x86_64 paging enabled (HHDM=%p)\n",
            (void *)bi->hhdm_offset);
}

paddr_t arch_mmu_create_table(void) {
    paddr_t dst = mmu_pt_alloc();
    if (!dst)
        return 0;
    uint64_t *src = (uint64_t *)phys_to_virt(kernel_pgdir);
    uint64_t *out = (uint64_t *)phys_to_virt(dst);
    memcpy(out, src, PAGE_SIZE);
    return dst;
}

static void destroy_pt(paddr_t table, int level) {
    if (!table || table == kernel_pgdir)
        return;

    uint64_t *pt = (uint64_t *)phys_to_virt(table);
    if (level > 0) {
        for (size_t i = 0; i < PTES_PER_PAGE; i++) {
            if (pt[i] & PTE_P)
                destroy_pt((paddr_t)(pt[i] & PTE_ADDR_MASK), level - 1);
        }
    }
    pmm_free_page(table);
}

void arch_mmu_destroy_table(paddr_t table) {
    if (!table || table == kernel_pgdir)
        return;

    /*
     * Only free user-half entries (lower 256 PML4 slots).
     * Upper 256 are shared kernel mappings — don't recurse into them.
     */
    uint64_t *pml4 = (uint64_t *)phys_to_virt(table);
    for (size_t i = 0; i < PTES_PER_PAGE / 2; i++) {
        if (pml4[i] & PTE_P)
            destroy_pt((paddr_t)(pml4[i] & PTE_ADDR_MASK), 2);
    }
    pmm_free_page(table);
}

int arch_mmu_map(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags) {
    uint64_t *pte = walk_pgtable(table, va, true);
    if (!pte)
        return -ENOMEM;
    *pte = (pa & ~0xfffULL) | flags_to_pte(flags);
    return 0;
}

int arch_mmu_map_merge(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags) {
    uint64_t *pte = walk_pgtable(table, va, true);
    if (!pte)
        return -ENOMEM;
    uint64_t nf = flags_to_pte(flags);
    if (*pte & PTE_P) {
        paddr_t existing = (paddr_t)(*pte & ~0xfffULL);
        if (existing != (pa & ~0xfffULL))
            return -EEXIST;
        *pte |= nf;
        return 0;
    }
    *pte = (pa & ~0xfffULL) | nf;
    return 0;
}

int arch_mmu_unmap(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & PTE_P))
        return -ENOENT;
    *pte = 0;
    arch_mmu_flush_tlb_page(va);
    return 0;
}

paddr_t arch_mmu_translate(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & PTE_P))
        return 0;
    return ((paddr_t)(*pte & PTE_ADDR_MASK)) | (va & 0xfffULL);
}

uint64_t arch_mmu_get_pte(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & PTE_P))
        return 0;
    paddr_t pa = (paddr_t)(*pte & PTE_ADDR_MASK);
    return ((pa >> PAGE_SHIFT) << 10) | pte_to_flags(*pte);
}

int arch_mmu_set_pte(paddr_t table, vaddr_t va, uint64_t pte) {
    uint64_t *entry = walk_pgtable(table, va, false);
    if (!entry)
        return -ENOENT;
    paddr_t pa = (paddr_t)(((pte >> 10) << PAGE_SHIFT) & PTE_ADDR_MASK);
    uint64_t flags = pte & ((1ULL << 10) - 1);
    if (!(flags & PTE_VALID)) {
        *entry = 0;
        return 0;
    }
    *entry = pa | flags_to_pte(flags);
    return 0;
}

void arch_mmu_switch(paddr_t table) {
    __asm__ __volatile__("mov %0, %%cr3" : : "r"(table) : "memory");
}

paddr_t arch_mmu_current(void) {
    paddr_t cr3;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

void arch_mmu_flush_tlb(void) {
    arch_mmu_switch(arch_mmu_current());
}

void arch_mmu_flush_tlb_page(vaddr_t va) {
    __asm__ __volatile__("invlpg (%0)" : : "r"(va) : "memory");
}

void arch_mmu_flush_tlb_all(void) {
    arch_mmu_flush_tlb();
}

paddr_t arch_mmu_get_kernel_pgdir(void) {
    return kernel_pgdir;
}

void *phys_to_virt(paddr_t addr) {
    const struct boot_info *bi = boot_info_get();
    if (bi && bi->hhdm_offset)
        return (void *)(addr + bi->hhdm_offset);
    return (void *)addr;
}

paddr_t virt_to_phys(void *addr) {
    const struct boot_info *bi = boot_info_get();
    uint64_t va = (uint64_t)addr;
    if (bi && bi->hhdm_offset &&
        va >= bi->hhdm_offset &&
        va < bi->hhdm_offset + bi->phys_mem_max) {
        return (paddr_t)(va - bi->hhdm_offset);
    }
    if (bi && bi->kernel_virt_base &&
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
