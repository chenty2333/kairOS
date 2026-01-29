/**
 * kernel/core/init/mm.c - Memory initialization
 */

#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/init.h>
#include <kairos/mm.h>
#include <kairos/printk.h>

void init_mm(const struct boot_info *bi) {
    if (!bi) {
        panic("boot: missing boot info");
    }
    pr_info("mm: init start\n");
    pmm_init_from_memmap(bi);
    pr_info("mm: pmm ready\n");
    kmalloc_init();
    pr_info("mm: kmalloc ready\n");
    arch_mmu_init(bi);
    pr_info("mm: mmu ready\n");
    vmm_init();
    pr_info("mm: vmm ready\n");
}
