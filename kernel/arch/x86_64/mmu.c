/**
 * kernel/arch/x86_64/mmu.c - x86_64 MMU implementation
 */

#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define PTES_PER_PAGE 512

#define PTE_P (1ULL << 0)
#define PTE_W (1ULL << 1)
#define PTE_U (1ULL << 2)
#define PTE_G (1ULL << 8)
#define PTE_NX (1ULL << 63)

static paddr_t kernel_pgdir;
extern char _kernel_start[], _kernel_end[];

static inline size_t va_index(vaddr_t va, int level) {
    return (va >> (PAGE_SHIFT + level * 9)) & 0x1ff;
}

static paddr_t pt_alloc(void) {
    paddr_t pa = pmm_alloc_page();
    if (!pa)
        return 0;
    memset(phys_to_virt(pa), 0, PAGE_SIZE);
    return pa;
}

static uint64_t *walk_pgtable(paddr_t table, vaddr_t va, bool create) {
    uint64_t *pt = (uint64_t *)phys_to_virt(table);
    for (int level = 3; level > 0; level--) {
        size_t idx = va_index(va, level);
        if (!(pt[idx] & PTE_P)) {
            if (!create)
                return NULL;
            paddr_t next = pt_alloc();
            if (!next)
                return NULL;
            pt[idx] = next | PTE_P | PTE_W;
        }
        pt = (uint64_t *)phys_to_virt((paddr_t)(pt[idx] & ~0xfffULL));
    }
    return &pt[va_index(va, 0)];
}

static uint64_t flags_to_pte(uint64_t f) {
    uint64_t p = PTE_P;
    if (f & PTE_WRITE)
        p |= PTE_W;
    if (f & PTE_USER)
        p |= PTE_U;
    if (f & PTE_GLOBAL)
        p |= PTE_G;
    if (!(f & PTE_EXEC))
        p |= PTE_NX;
    return p;
}

static int map_region(paddr_t root, vaddr_t va, paddr_t pa, size_t sz,
                      uint64_t f) {
    for (size_t off = 0; off < sz; off += PAGE_SIZE) {
        if (arch_mmu_map(root, va + off, pa + off, f) < 0)
            return -1;
    }
    return 0;
}

void arch_mmu_init(const struct boot_info *bi) {
    if (!bi)
        panic("mmu: missing boot info");

    kernel_pgdir = pt_alloc();
    if (!kernel_pgdir)
        panic("mmu: init failed");

    for (uint32_t i = 0; i < bi->memmap_count; i++) {
        const struct boot_memmap_entry *e = &bi->memmap[i];
        if (!boot_mem_is_ram(e->type))
            continue;
        map_region(kernel_pgdir, bi->hhdm_offset + e->base, e->base,
                   e->length, PTE_READ | PTE_WRITE | PTE_GLOBAL);
    }

    size_t ksize = ALIGN_UP((paddr_t)_kernel_end - (paddr_t)_kernel_start,
                            PAGE_SIZE);
    map_region(kernel_pgdir, bi->kernel_virt_base, bi->kernel_phys_base, ksize,
               PTE_READ | PTE_WRITE | PTE_EXEC | PTE_GLOBAL);

    arch_mmu_switch(kernel_pgdir);
    pr_info("MMU: x86_64 paging enabled (HHDM=%p)\n",
            (void *)bi->hhdm_offset);
}

paddr_t arch_mmu_create_table(void) {
    paddr_t dst = pt_alloc();
    if (!dst)
        return 0;
    uint64_t *src = (uint64_t *)phys_to_virt(kernel_pgdir);
    uint64_t *out = (uint64_t *)phys_to_virt(dst);
    memcpy(out, src, PAGE_SIZE);
    return dst;
}

void arch_mmu_destroy_table(paddr_t table) {
    (void)table;
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
    return ((paddr_t)(*pte & ~0xfffULL)) | (va & 0xfffULL);
}

uint64_t arch_mmu_get_pte(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    return pte ? *pte : 0;
}

int arch_mmu_set_pte(paddr_t table, vaddr_t va, uint64_t pte) {
    uint64_t *entry = walk_pgtable(table, va, false);
    if (!entry)
        return -ENOENT;
    *entry = pte;
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
        va >= bi->kernel_virt_base &&
        va < bi->kernel_virt_base + ((uint64_t)_kernel_end - (uint64_t)_kernel_start)) {
        return (paddr_t)(va - bi->kernel_virt_base + bi->kernel_phys_base);
    }
    return (paddr_t)addr;
}

void *ioremap(paddr_t phys, size_t size __attribute__((unused))) {
    return phys_to_virt(phys);
}

void iounmap(void *virt __attribute__((unused))) {}
