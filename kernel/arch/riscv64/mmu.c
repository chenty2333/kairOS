/**
 * mmu.c - RISC-V 64 MMU (Sv39) Implementation
 *
 * Sv39 uses a 3-level page table with 39-bit virtual addresses:
 * - VPN[2] (9 bits): Level 2 page table index
 * - VPN[1] (9 bits): Level 1 page table index
 * - VPN[0] (9 bits): Level 0 page table index
 * - Offset (12 bits): Page offset
 *
 * Page Table Entry format:
 * [63:54] Reserved
 * [53:10] PPN (Physical Page Number)
 * [9:8]   RSW (Reserved for Software)
 * [7]     D (Dirty)
 * [6]     A (Accessed)
 * [5]     G (Global)
 * [4]     U (User)
 * [3]     X (Execute)
 * [2]     W (Write)
 * [1]     R (Read)
 * [0]     V (Valid)
 */

#include <kairos/types.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/printk.h>

/* Page size and shifts */
#define PAGE_SIZE       4096
#define PAGE_SHIFT      12
#define PAGE_MASK       (~(PAGE_SIZE - 1))

/* Sv39 parameters */
#define PTES_PER_PAGE   512         /* 4KB / 8 bytes per PTE */
#define PTE_SHIFT       3           /* log2(8) - PTE size */
#define VPN_BITS        9
#define VPN_MASK        ((1UL << VPN_BITS) - 1)
#define LEVELS          3

/* Virtual address breakdown */
#define VA_OFFSET_MASK  ((1UL << PAGE_SHIFT) - 1)
#define VA_VPN0_SHIFT   12
#define VA_VPN1_SHIFT   21
#define VA_VPN2_SHIFT   30

/* PTE flags */
#define PTE_V           (1UL << 0)  /* Valid */
#define PTE_R           (1UL << 1)  /* Readable */
#define PTE_W           (1UL << 2)  /* Writable */
#define PTE_X           (1UL << 3)  /* Executable */
#define PTE_U           (1UL << 4)  /* User accessible */
#define PTE_G           (1UL << 5)  /* Global */
#define PTE_A           (1UL << 6)  /* Accessed */
#define PTE_D           (1UL << 7)  /* Dirty */

/* PPN extraction */
#define PTE_PPN_SHIFT   10
#define PTE_PPN_MASK    (0xFFFFFFFFFFFUL << PTE_PPN_SHIFT)

/* SATP register format */
#define SATP_MODE_SV39  (8UL << 60)
#define SATP_ASID_SHIFT 44
#define SATP_PPN_MASK   ((1UL << 44) - 1)

/* Kernel virtual address space */
#define KERNEL_BASE     0xFFFFFFFF80000000UL
#define PHYS_BASE       0x80000000UL

/* Forward declarations */
static uint64_t *pte_to_pa(uint64_t pte);
static uint64_t pa_to_pte(paddr_t pa);

/* Kernel page table (physical address) */
static paddr_t kernel_pgdir;

/* External symbols */
extern char _kernel_start[];
extern char _kernel_end[];

/**
 * Extract VPN[level] from virtual address
 */
static inline size_t va_to_vpn(vaddr_t va, int level)
{
    size_t shift = PAGE_SHIFT + (level * VPN_BITS);
    return (va >> shift) & VPN_MASK;
}

/**
 * Convert PTE to physical address of next level table or page
 */
static uint64_t *pte_to_pa(uint64_t pte)
{
    return (uint64_t *)((pte >> PTE_PPN_SHIFT) << PAGE_SHIFT);
}

/**
 * Convert physical address to PTE format
 */
static uint64_t pa_to_pte(paddr_t pa)
{
    return ((pa >> PAGE_SHIFT) << PTE_PPN_SHIFT);
}

/**
 * Check if PTE is a leaf (has R, W, or X permission)
 */
static inline bool pte_is_leaf(uint64_t pte)
{
    return (pte & (PTE_R | PTE_W | PTE_X)) != 0;
}

/**
 * Allocate a page table page
 */
static paddr_t alloc_pgtable(void)
{
    paddr_t pa = pmm_alloc_page();
    if (pa == 0) {
        return 0;
    }

    /* Zero the page table */
    uint64_t *table = (uint64_t *)pa;
    for (int i = 0; i < PTES_PER_PAGE; i++) {
        table[i] = 0;
    }

    return pa;
}

/**
 * Free a page table page
 */
static void free_pgtable(paddr_t pa)
{
    pmm_free_page(pa);
}

/**
 * Walk the page table, optionally creating entries
 *
 * @table: Physical address of root page table
 * @va: Virtual address to look up
 * @create: If true, create missing page table levels
 *
 * Returns pointer to PTE, or NULL if not found/cannot create
 */
static uint64_t *walk_pgtable(paddr_t table, vaddr_t va, bool create)
{
    uint64_t *pgtable = (uint64_t *)table;

    for (int level = LEVELS - 1; level > 0; level--) {
        size_t idx = va_to_vpn(va, level);
        uint64_t pte = pgtable[idx];

        if (!(pte & PTE_V)) {
            if (!create) {
                return NULL;
            }

            /* Allocate new page table level */
            paddr_t new_table = alloc_pgtable();
            if (new_table == 0) {
                return NULL;
            }

            pgtable[idx] = pa_to_pte(new_table) | PTE_V;
            pgtable = (uint64_t *)new_table;
        } else if (pte_is_leaf(pte)) {
            /* Huge page - not supported in this simple implementation */
            return NULL;
        } else {
            pgtable = pte_to_pa(pte);
        }
    }

    /* Return pointer to leaf PTE */
    size_t idx = va_to_vpn(va, 0);
    return &pgtable[idx];
}

/**
 * Convert generic flags to RISC-V PTE flags
 */
static uint64_t flags_to_pte(uint64_t flags)
{
    uint64_t pte_flags = PTE_V | PTE_A | PTE_D;

    if (flags & PTE_READ) {
        pte_flags |= PTE_R;
    }
    if (flags & PTE_WRITE) {
        pte_flags |= PTE_W;
    }
    if (flags & PTE_EXEC) {
        pte_flags |= PTE_X;
    }
    if (flags & PTE_USER) {
        pte_flags |= PTE_U;
    }
    if (flags & PTE_GLOBAL) {
        pte_flags |= PTE_G;
    }

    return pte_flags;
}

/*
 * ============================================================
 *                   Public MMU Interface
 * ============================================================
 */

/**
 * arch_mmu_init - Initialize the MMU
 *
 * Creates the kernel page table and enables paging.
 */
void arch_mmu_init(void)
{
    /* Allocate root page table */
    kernel_pgdir = alloc_pgtable();
    if (kernel_pgdir == 0) {
        panic("arch_mmu_init: failed to allocate kernel page table");
    }

    pr_info("MMU: Kernel page table at %p\n", (void *)kernel_pgdir);

    /* Identity map kernel memory */
    paddr_t kernel_start = ALIGN_DOWN((paddr_t)_kernel_start, PAGE_SIZE);
    paddr_t kernel_end_addr = ALIGN_UP((paddr_t)_kernel_end, PAGE_SIZE);

    pr_info("MMU: Mapping kernel %p - %p\n",
            (void *)kernel_start, (void *)kernel_end_addr);

    for (paddr_t pa = kernel_start; pa < kernel_end_addr; pa += PAGE_SIZE) {
        /* Identity map for now (VA == PA) */
        int ret = arch_mmu_map(kernel_pgdir, pa, pa,
                               PTE_READ | PTE_WRITE | PTE_EXEC);
        if (ret < 0) {
            panic("arch_mmu_init: failed to map kernel page %p", (void *)pa);
        }
    }

    /* Map physical memory for kernel use (first 128MB for now) */
    paddr_t phys_start = 0x80000000UL;
    paddr_t phys_end = phys_start + (128UL << 20);  /* 128 MB */

    pr_info("MMU: Mapping physical memory %p - %p\n",
            (void *)phys_start, (void *)phys_end);

    for (paddr_t pa = phys_start; pa < phys_end; pa += PAGE_SIZE) {
        /* Skip if already mapped as kernel */
        if (pa >= kernel_start && pa < kernel_end_addr) {
            continue;
        }

        int ret = arch_mmu_map(kernel_pgdir, pa, pa,
                               PTE_READ | PTE_WRITE);
        if (ret < 0) {
            panic("arch_mmu_init: failed to map physical memory at %p",
                  (void *)pa);
        }
    }

    /* Enable paging */
    arch_mmu_switch(kernel_pgdir);

    pr_info("MMU: Sv39 paging enabled\n");
}

/**
 * arch_mmu_create_table - Create a new page table
 *
 * Returns physical address of new page table.
 */
paddr_t arch_mmu_create_table(void)
{
    paddr_t table = alloc_pgtable();
    if (table == 0) {
        return 0;
    }

    /* Copy kernel mappings (upper half of address space) */
    uint64_t *new_table = (uint64_t *)table;
    uint64_t *kern_table = (uint64_t *)kernel_pgdir;

    /* Copy entries for kernel space (upper half) */
    for (int i = PTES_PER_PAGE / 2; i < PTES_PER_PAGE; i++) {
        new_table[i] = kern_table[i];
    }

    return table;
}

/**
 * arch_mmu_destroy_table - Destroy a page table
 * @table: Physical address of page table to destroy
 *
 * Frees all user-space page table pages. Does not free kernel mappings.
 */
void arch_mmu_destroy_table(paddr_t table)
{
    if (table == 0 || table == kernel_pgdir) {
        return;
    }

    uint64_t *l2 = (uint64_t *)table;

    /* Only free user space entries (lower half) */
    for (int i = 0; i < PTES_PER_PAGE / 2; i++) {
        if (!(l2[i] & PTE_V)) {
            continue;
        }

        if (pte_is_leaf(l2[i])) {
            continue;  /* Huge page, just skip */
        }

        uint64_t *l1 = pte_to_pa(l2[i]);
        for (int j = 0; j < PTES_PER_PAGE; j++) {
            if (!(l1[j] & PTE_V)) {
                continue;
            }

            if (pte_is_leaf(l1[j])) {
                continue;
            }

            uint64_t *l0 = pte_to_pa(l1[j]);
            free_pgtable((paddr_t)l0);
        }

        free_pgtable((paddr_t)l1);
    }

    free_pgtable(table);
}

/**
 * arch_mmu_map - Map a virtual address to a physical address
 * @table: Physical address of page table
 * @va: Virtual address to map
 * @pa: Physical address to map to
 * @flags: Mapping flags (PTE_READ, PTE_WRITE, etc.)
 *
 * Returns 0 on success, negative error on failure.
 */
int arch_mmu_map(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags)
{
    uint64_t *pte = walk_pgtable(table, va, true);
    if (!pte) {
        return -ENOMEM;
    }

    if (*pte & PTE_V) {
        /* Already mapped - check if same mapping */
        if (pte_to_pa(*pte) == (uint64_t *)pa) {
            /* Same page, just update flags */
            *pte = pa_to_pte(pa) | flags_to_pte(flags);
            return 0;
        }
        return -EEXIST;
    }

    *pte = pa_to_pte(pa) | flags_to_pte(flags);
    return 0;
}

/**
 * arch_mmu_unmap - Unmap a virtual address
 * @table: Physical address of page table
 * @va: Virtual address to unmap
 *
 * Returns 0 on success, negative error on failure.
 */
int arch_mmu_unmap(paddr_t table, vaddr_t va)
{
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & PTE_V)) {
        return -ENOENT;
    }

    *pte = 0;
    arch_mmu_flush_tlb_page(va);
    return 0;
}

/**
 * arch_mmu_translate - Translate virtual address to physical
 * @table: Physical address of page table
 * @va: Virtual address to translate
 *
 * Returns physical address, or 0 if not mapped.
 */
paddr_t arch_mmu_translate(paddr_t table, vaddr_t va)
{
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & PTE_V)) {
        return 0;
    }

    paddr_t pa = (paddr_t)pte_to_pa(*pte);
    return pa | (va & VA_OFFSET_MASK);
}

/**
 * arch_mmu_switch - Switch to a new address space
 * @table: Physical address of page table to switch to
 */
void arch_mmu_switch(paddr_t table)
{
    uint64_t satp = SATP_MODE_SV39 | (table >> PAGE_SHIFT);
    __asm__ __volatile__(
        "csrw satp, %0\n"
        "sfence.vma"
        :: "r"(satp)
        : "memory"
    );
}

/**
 * arch_mmu_current - Get current page table
 *
 * Returns physical address of current page table.
 */
paddr_t arch_mmu_current(void)
{
    uint64_t satp;
    __asm__ __volatile__("csrr %0, satp" : "=r"(satp));
    return (satp & SATP_PPN_MASK) << PAGE_SHIFT;
}

/**
 * arch_mmu_flush_tlb - Flush entire TLB
 */
void arch_mmu_flush_tlb(void)
{
    __asm__ __volatile__("sfence.vma" ::: "memory");
}

/**
 * arch_mmu_flush_tlb_page - Flush TLB for a single page
 * @va: Virtual address of page to flush
 */
void arch_mmu_flush_tlb_page(vaddr_t va)
{
    __asm__ __volatile__("sfence.vma %0" :: "r"(va) : "memory");
}

/*
 * ============================================================
 *               Kernel Virtual Memory Helpers
 * ============================================================
 */

/**
 * phys_to_virt - Convert physical address to kernel virtual address
 *
 * For now, we use identity mapping so VA == PA.
 */
void *phys_to_virt(paddr_t addr)
{
    return (void *)addr;
}

/**
 * virt_to_phys - Convert kernel virtual address to physical
 */
paddr_t virt_to_phys(void *addr)
{
    return (paddr_t)addr;
}

/**
 * ioremap - Map device memory into kernel virtual space
 * @phys: Physical address of device
 * @size: Size of region to map
 *
 * Returns virtual address of mapped region.
 */
void *ioremap(paddr_t phys, size_t size)
{
    /* For now, with identity mapping, just return the physical address */
    (void)size;
    return (void *)phys;
}

/**
 * iounmap - Unmap device memory
 * @virt: Virtual address to unmap
 */
void iounmap(void *virt)
{
    /* Nothing to do with identity mapping */
    (void)virt;
}
