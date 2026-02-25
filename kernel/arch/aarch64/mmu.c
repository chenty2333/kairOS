/**
 * kernel/arch/aarch64/mmu.c - AArch64 MMU implementation
 *
 * 4-level page table (48-bit VA), 4KB granule.
 * MAIR indices: 0=Device-nGnRnE, 1=Device-nGnRE, 2=Normal-NC,
 *               3=Normal-WT, 4=Normal-WB.
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
#define LEVELS 4

/* --- Hardware PTE bits --- */
#define AARCH64_PTE_VALID     (1ULL << 0)
#define AARCH64_PTE_TABLE     (1ULL << 1)
#define AARCH64_PTE_PAGE      (1ULL << 1)
#define AARCH64_PTE_AF        (1ULL << 10)
#define AARCH64_PTE_SH_INNER  (3ULL << 8)
#define AARCH64_PTE_SH_OUTER  (2ULL << 8)
#define AARCH64_PTE_ATTRIDX(n) ((uint64_t)(n) << 2)
#define AARCH64_PTE_AP_RW_EL1 (0ULL << 6)
#define AARCH64_PTE_AP_RW_EL0 (1ULL << 6)
#define AARCH64_PTE_AP_RO_EL1 (2ULL << 6)
#define AARCH64_PTE_AP_RO_EL0 (3ULL << 6)
#define AARCH64_PTE_UXN       (1ULL << 54)
#define AARCH64_PTE_PXN       (1ULL << 53)
#define AARCH64_PTE_SW_COW    (1ULL << 55) /* software-defined bit for COW */
#define AARCH64_PTE_ADDR_MASK 0x000FFFFFFFFFF000ULL
#define AARCH64_PTE_ATTRIDX_MASK (7ULL << 2)
#define AARCH64_PTE_AP_MASK   (3ULL << 6)

/* MAIR attribute indices */
#define MT_DEVICE_nGnRnE 0
#define MT_DEVICE_nGnRE  1
#define MT_NORMAL_NC     2
#define MT_NORMAL_WT     3
#define MT_NORMAL_WB     4

static paddr_t kernel_pgdir;
extern char _kernel_start[], _kernel_end[];

/* --- mmu_ops callbacks for common walker --- */

static bool aarch64_pte_valid(uint64_t pte) {
    return (pte & AARCH64_PTE_VALID) != 0;
}

static paddr_t aarch64_pte_addr(uint64_t pte) {
    return (paddr_t)(pte & AARCH64_PTE_ADDR_MASK);
}

static uint64_t aarch64_make_branch(paddr_t pa) {
    return pa | AARCH64_PTE_VALID | AARCH64_PTE_TABLE;
}

static size_t aarch64_va_index(vaddr_t va, int level) {
    return (va >> (PAGE_SHIFT + level * 9)) & 0x1ff;
}

static const struct mmu_ops aarch64_mmu_ops = {
    .levels      = LEVELS,
    .pte_valid   = aarch64_pte_valid,
    .pte_addr    = aarch64_pte_addr,
    .make_branch = aarch64_make_branch,
    .va_index    = aarch64_va_index,
};

/* Convenience wrapper */
static uint64_t *walk_pgtable(paddr_t table, vaddr_t va, bool create) {
    return mmu_walk_pgtable(&aarch64_mmu_ops, table, va, create);
}

static inline bool pte_is_table(uint64_t pte) {
    return (pte & (AARCH64_PTE_VALID | AARCH64_PTE_TABLE)) ==
           (AARCH64_PTE_VALID | AARCH64_PTE_TABLE);
}

static void destroy_pt(paddr_t table, int level) {
    if (!table || table == kernel_pgdir)
        return;

    uint64_t *pt = (uint64_t *)phys_to_virt(table);
    if (level > 0) {
        for (size_t i = 0; i < PTES_PER_PAGE; i++) {
            if (pte_is_table(pt[i])) {
                destroy_pt((paddr_t)(pt[i] & AARCH64_PTE_ADDR_MASK), level - 1);
            }
        }
    }
    pmm_free_page(table);
}

static paddr_t copy_pt(paddr_t src, int level) {
    paddr_t dst = mmu_pt_alloc();
    if (!dst)
        return 0;

    uint64_t *src_pt = (uint64_t *)phys_to_virt(src);
    uint64_t *dst_pt = (uint64_t *)phys_to_virt(dst);
    memcpy(dst_pt, src_pt, PAGE_SIZE);

    for (size_t i = 0; i < PTES_PER_PAGE; i++) {
        uint64_t pte = dst_pt[i];
        if (!(pte & AARCH64_PTE_VALID))
            continue;

        /* Strip user mappings from kernel table copies */
        if (pte & AARCH64_PTE_AP_RW_EL0) {
            dst_pt[i] = 0;
            continue;
        }

        if (level > 0 && pte_is_table(pte)) {
            paddr_t child_src = (paddr_t)(pte & AARCH64_PTE_ADDR_MASK);
            paddr_t child_dst = copy_pt(child_src, level - 1);
            if (!child_dst) {
                destroy_pt(dst, level);
                return 0;
            }
            dst_pt[i] = child_dst | (pte & 0xfffULL);
        }
    }
    return dst;
}

static uint64_t flags_to_pte(uint64_t f) {
    /*
     * For 4KB granule page descriptors (L3), bit[1] must be 1.
     * Reuse the same encoding constant as table descriptors.
     */
    uint64_t p = AARCH64_PTE_VALID | AARCH64_PTE_PAGE | AARCH64_PTE_AF;

    if (f & PTE_DEVICE) {
        /* Device memory: nGnRnE, Outer Shareable */
        p |= AARCH64_PTE_ATTRIDX(MT_DEVICE_nGnRnE);
        p |= AARCH64_PTE_SH_OUTER;
    } else {
        /* Normal memory: Write-Back, Inner Shareable */
        p |= AARCH64_PTE_ATTRIDX(MT_NORMAL_WB);
        p |= AARCH64_PTE_SH_INNER;
    }

    if (f & PTE_USER) {
        p |= (f & PTE_WRITE) ? AARCH64_PTE_AP_RW_EL0 : AARCH64_PTE_AP_RO_EL0;
    } else {
        p |= (f & PTE_WRITE) ? AARCH64_PTE_AP_RW_EL1 : AARCH64_PTE_AP_RO_EL1;
    }
    if (f & PTE_COW)
        p |= AARCH64_PTE_SW_COW;
    if (!(f & PTE_EXEC))
        p |= AARCH64_PTE_UXN | AARCH64_PTE_PXN;
    return p;
}

static uint64_t pte_to_flags(uint64_t pte) {
    if (!(pte & AARCH64_PTE_VALID))
        return 0;

    uint64_t f = PTE_VALID | PTE_READ;
    uint64_t ap = pte & AARCH64_PTE_AP_MASK;
    if (ap == AARCH64_PTE_AP_RW_EL0 || ap == AARCH64_PTE_AP_RW_EL1)
        f |= PTE_WRITE;
    if (ap == AARCH64_PTE_AP_RW_EL0 || ap == AARCH64_PTE_AP_RO_EL0)
        f |= PTE_USER;
    if (!(pte & (AARCH64_PTE_UXN | AARCH64_PTE_PXN)))
        f |= PTE_EXEC;
    if ((pte & AARCH64_PTE_ATTRIDX_MASK) == AARCH64_PTE_ATTRIDX(MT_DEVICE_nGnRnE))
        f |= PTE_DEVICE;
    if (pte & AARCH64_PTE_SW_COW)
        f |= PTE_COW;
    return f;
}

/* --- Build TCR_EL1 --- */
static uint64_t build_tcr(void) {
    /* Read physical address size from ID_AA64MMFR0_EL1 */
    uint64_t mmfr0;
    __asm__ __volatile__("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    uint64_t pa_range = mmfr0 & 0xf;

    uint64_t tcr = 0;
    tcr |= (64 - 48);           /* T0SZ = 16 (48-bit TTBR0 VA) */
    tcr |= (64 - 48) << 16;     /* T1SZ = 16 (48-bit TTBR1 VA) */
    tcr |= (0b00ULL) << 14;     /* TG0 = 4KB */
    tcr |= (0b10ULL) << 30;     /* TG1 = 4KB */
    tcr |= (0b11ULL) << 8;      /* IRGN0 = WB-WA */
    tcr |= (0b11ULL) << 24;     /* IRGN1 = WB-WA */
    tcr |= (0b01ULL) << 10;     /* ORGN0 = WB-WA */
    tcr |= (0b01ULL) << 26;     /* ORGN1 = WB-WA */
    tcr |= (0b11ULL) << 12;     /* SH0 = Inner Shareable */
    tcr |= (0b11ULL) << 28;     /* SH1 = Inner Shareable */
    tcr |= pa_range << 32;      /* IPS = detected PA range */
    return tcr;
}

/* --- Build MAIR_EL1 --- */
static uint64_t build_mair(void) {
    /* Attr0: Device-nGnRnE (0x00)
     * Attr1: Device-nGnRE  (0x04)
     * Attr2: Normal NC      (0x44)
     * Attr3: Normal WT      (0xBB)
     * Attr4: Normal WB      (0xFF)
     */
    return 0x00ULL | (0x04ULL << 8) | (0x44ULL << 16) |
           (0xBBULL << 24) | (0xFFULL << 32);
}

/* --- Public Interface --- */

void arch_mmu_init(const struct boot_info *bi) {
    if (!bi)
        panic("mmu: missing boot info");

    kernel_pgdir = mmu_pt_alloc();
    if (!kernel_pgdir)
        panic("mmu: init failed");

    /* 1. Map HHDM for all RAM-backed memory regions */
    for (uint32_t i = 0; i < bi->memmap_count; i++) {
        const struct boot_memmap_entry *e = &bi->memmap[i];
        if (!boot_mem_is_ram(e->type))
            continue;
        if (mmu_map_region(kernel_pgdir, bi->hhdm_offset + e->base, e->base,
                           e->length,
                           PTE_READ | PTE_WRITE | PTE_GLOBAL) < 0) {
            panic("mmu: HHDM map failed");
        }
    }

    /* 1b. Map framebuffer MMIO into HHDM */
    for (uint32_t i = 0; i < bi->framebuffer_count; i++) {
        paddr_t phys = (paddr_t)bi->framebuffers[i].phys;
        if (!phys || !bi->framebuffers[i].size)
            continue;
        if (bi->hhdm_offset && phys >= bi->hhdm_offset)
            phys -= bi->hhdm_offset;
        size_t size = ALIGN_UP((size_t)bi->framebuffers[i].size, PAGE_SIZE);
        if (mmu_map_region(kernel_pgdir, bi->hhdm_offset + phys, phys, size,
                           PTE_READ | PTE_WRITE | PTE_DEVICE) < 0) {
            panic("mmu: framebuffer map failed");
        }
    }

    /* 2. Map kernel high half */
    size_t ksize = ALIGN_UP((paddr_t)_kernel_end - (paddr_t)_kernel_start,
                            PAGE_SIZE);
    if (mmu_map_region(kernel_pgdir, bi->kernel_virt_base, bi->kernel_phys_base,
                       ksize,
                       PTE_READ | PTE_WRITE | PTE_EXEC | PTE_GLOBAL) < 0) {
        panic("mmu: kernel map failed");
    }

    /*
     * Keep a low VA identity alias for kernel image.
     * Secondary CPUs started via PSCI enable MMU while executing from PA.
     */
    if (mmu_map_region(kernel_pgdir, bi->kernel_phys_base, bi->kernel_phys_base,
                       ksize,
                       PTE_READ | PTE_WRITE | PTE_EXEC | PTE_GLOBAL) < 0) {
        panic("mmu: kernel identity map failed");
    }

    const struct platform_desc *plat = platform_get();
    if (plat) {
        for (int i = 0; i < plat->num_early_mmio; i++) {
            paddr_t base = plat->early_mmio[i].base;
            size_t  size = plat->early_mmio[i].size;
            if (mmu_map_region(kernel_pgdir, bi->hhdm_offset + base,
                               base, size,
                               PTE_READ | PTE_WRITE | PTE_DEVICE) < 0) {
                panic("mmu: platform MMIO map failed (%p)", (void *)base);
            }
        }
    } else {
        panic("mmu: no platform selected");
    }

    /* 4. Program MAIR, TCR, TTBR1 and enable MMU */
    uint64_t mair = build_mair();
    uint64_t tcr = build_tcr();

    __asm__ __volatile__(
        "dsb ishst\n"
        "msr mair_el1, %0\n"
        "msr tcr_el1, %1\n"
        "msr ttbr1_el1, %2\n"
        "tlbi vmalle1\n"
        "dsb ish\n"
        "isb\n"
        :: "r"(mair), "r"(tcr), "r"(kernel_pgdir)
        : "memory");

    aarch64_early_console_set_ready(true);
    pr_info("MMU: AArch64 paging enabled (HHDM=%p)\n",
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
    if (!pte)
        return -ENOMEM;
    *pte = (pa & AARCH64_PTE_ADDR_MASK) | flags_to_pte(flags);
    return 0;
}

int arch_mmu_map_merge(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags) {
    uint64_t *pte = walk_pgtable(table, va, true);
    if (!pte)
        return -ENOMEM;
    uint64_t nf = flags_to_pte(flags);
    if (*pte & AARCH64_PTE_VALID) {
        paddr_t existing = (paddr_t)(*pte & AARCH64_PTE_ADDR_MASK);
        if (existing != (pa & AARCH64_PTE_ADDR_MASK))
            return -EEXIST;
        *pte |= nf;
        return 0;
    }
    *pte = (pa & AARCH64_PTE_ADDR_MASK) | nf;
    return 0;
}

int arch_mmu_unmap(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & AARCH64_PTE_VALID))
        return -ENOENT;
    *pte = 0;
    arch_mmu_flush_tlb_page(va);
    return 0;
}

paddr_t arch_mmu_translate(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & AARCH64_PTE_VALID))
        return 0;
    return ((paddr_t)(*pte & AARCH64_PTE_ADDR_MASK)) | (va & 0xfffULL);
}

uint64_t arch_mmu_get_pte(paddr_t table, vaddr_t va) {
    uint64_t *pte = walk_pgtable(table, va, false);
    if (!pte || !(*pte & AARCH64_PTE_VALID))
        return 0;
    paddr_t pa = (paddr_t)(*pte & AARCH64_PTE_ADDR_MASK);
    return ((pa >> PAGE_SHIFT) << 10) | pte_to_flags(*pte);
}

int arch_mmu_set_pte(paddr_t table, vaddr_t va, uint64_t pte) {
    uint64_t *entry = walk_pgtable(table, va, false);
    if (!entry)
        return -ENOENT;
    paddr_t pa = (paddr_t)(((pte >> 10) << PAGE_SHIFT) & AARCH64_PTE_ADDR_MASK);
    uint64_t flags = pte & ((1ULL << 10) - 1);
    if (!(flags & PTE_VALID)) {
        *entry = 0;
        return 0;
    }
    *entry = pa | flags_to_pte(flags);
    return 0;
}

void arch_mmu_switch(paddr_t table) {
    __asm__ __volatile__("msr ttbr0_el1, %0\n" :: "r"(table) : "memory");
    if (kernel_pgdir)
        __asm__ __volatile__("msr ttbr1_el1, %0\n" :: "r"(kernel_pgdir)
                             : "memory");
    __asm__ __volatile__("tlbi vmalle1; dsb ish; isb");
}

paddr_t arch_mmu_current(void) {
    paddr_t ttbr;
    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(ttbr));
    return ttbr;
}

void arch_mmu_flush_tlb(void) {
    __asm__ __volatile__("tlbi vmalle1; dsb ish; isb");
}

void arch_mmu_flush_tlb_page(vaddr_t va) {
    __asm__ __volatile__("tlbi vae1, %0; dsb ish; isb" :: "r"(va >> 12));
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
