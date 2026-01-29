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
    pmm_init_from_memmap(bi);
    kmalloc_init();
    arch_mmu_init(bi);
    vmm_init();
}
