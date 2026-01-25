/**
 * kernel/arch/riscv64/mmu.c - RISC-V 64 MMU (Sv39) Implementation
 */

#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>

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

static paddr_t pt_alloc(void) {
    paddr_t pa = pmm_alloc_page();
    if (pa) {
        memset((void *)pa, 0, PAGE_SIZE);
    }
    return pa;
}

static uint64_t *walk_pgtable(paddr_t table, vaddr_t va, bool create) {
    uint64_t *pt = (uint64_t *)table;
    for (int i = LEVELS - 1; i > 0; i--) {
        size_t idx = va_to_vpn(va, i);
        if (!(pt[idx] & PTE_V)) {
            if (!create) {
                return NULL;
            }
            paddr_t next = pt_alloc();
            if (!next) {
                return NULL;
            }
            pt[idx] = pa_to_pte(next) | PTE_V;
        }
        pt = pte_to_pa(pt[idx]);
    }
    return &pt[va_to_vpn(va, 0)];
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
    return p;
}

static void pt_free_recursive(paddr_t table, int level) {
    uint64_t *pt = (uint64_t *)table;
    for (int i = 0; i < (level > 0 ? PTES_PER_PAGE : 0); i++) {
        if ((pt[i] & PTE_V) && !(pt[i] & (PTE_R | PTE_W | PTE_X))) {
            pt_free_recursive((paddr_t)pte_to_pa(pt[i]), level - 1);
        }
    }
    pmm_free_page(table);
}

static int map_region(paddr_t root, vaddr_t va, paddr_t pa, size_t sz,
                      uint64_t f) {
    for (size_t off = 0; off < sz; off += PAGE_SIZE) {
        if (arch_mmu_map(root, va + off, pa + off, f) < 0) {
            return -1;
        }
    }
    return 0;
}

/* --- Public Interface --- */

void arch_mmu_init(paddr_t mem_base, size_t mem_size) {
    if (!(kernel_pgdir = pt_alloc())) {
        panic("mmu: init failed");
    }

    /* 1. Map whole RAM as RW first (Identity Mapping) */
    map_region(kernel_pgdir, mem_base, mem_base, mem_size,
               PTE_READ | PTE_WRITE);

    /* 2. Overwrite kernel text/data with RWX permissions */
    map_region(kernel_pgdir, (vaddr_t)_kernel_start, (paddr_t)_kernel_start,
               ALIGN_UP((paddr_t)_kernel_end, PAGE_SIZE) -
                   (paddr_t)_kernel_start,
               PTE_READ | PTE_WRITE | PTE_EXEC);

    /* 3. Map UART/Device MMIO (Common for QEMU virt) */
    map_region(kernel_pgdir, 0x10000000UL, 0x10000000UL, 64 << 10,
               PTE_READ | PTE_WRITE);

    arch_mmu_switch(kernel_pgdir);
    pr_info("MMU: Sv39 paging enabled (base=%p, size=%lu MB)\n",
            (void *)mem_base, mem_size >> 20);
}

paddr_t arch_mmu_create_table(void) {
    paddr_t table = pt_alloc();
    if (table) {
        memcpy((void *)table, (void *)kernel_pgdir, PAGE_SIZE);
    }
    return table;
}

void arch_mmu_destroy_table(paddr_t table) {
    if (table && table != kernel_pgdir) {
        pt_free_recursive(table, LEVELS - 1);
    }
}

int arch_mmu_map(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags) {
    uint64_t *pte = walk_pgtable(table, va, true);
    if (!pte) {
        return -ENOMEM;
    }
    *pte = pa_to_pte(pa) | flags_to_pte(flags);
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

/* --- KVM Helpers --- */

void *phys_to_virt(paddr_t addr) {
    return (void *)addr;
}

paddr_t virt_to_phys(void *addr) {
    return (paddr_t)addr;
}

void *ioremap(paddr_t phys, size_t size __attribute__((unused))) {
    return (void *)phys;
}

void iounmap(void *virt __attribute__((unused))) {}
