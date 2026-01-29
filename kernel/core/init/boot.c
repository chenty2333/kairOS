/**
 * kernel/core/init/boot.c - Early boot initialization
 */

#include <kairos/boot.h>
#include <kairos/fdt.h>
#include <kairos/init.h>
#include <kairos/printk.h>

/* Kernel version */
#define KAIROS_VERSION_MAJOR 0
#define KAIROS_VERSION_MINOR 1
#define KAIROS_VERSION_PATCH 0

static const void *boot_dtb;

const void *init_boot_dtb(void) {
    return boot_dtb;
}

void init_boot(const struct boot_info *bi) {
    void *dtb = bi ? bi->dtb : NULL;
    boot_dtb = dtb;

    printk("\n===========================================\n");
    printk("  Kairos Kernel v%d.%d.%d\n", KAIROS_VERSION_MAJOR,
           KAIROS_VERSION_MINOR, KAIROS_VERSION_PATCH);
    printk("  Modern Device Model & FDT Support\n");
    printk("===========================================\n\n");

    if (dtb) {
        if (fdt_parse(dtb) < 0) {
            panic("Failed to parse DTB");
        }
    } else {
        pr_warn("boot: no DTB provided\n");
    }

    if (!bi) {
        panic("boot: missing boot info");
    }

    pr_info("boot: memmap=%u hhdm=%p kphys=%p kvirt=%p\n",
            bi->memmap_count,
            (void *)bi->hhdm_offset,
            (void *)bi->kernel_phys_base,
            (void *)bi->kernel_virt_base);
}
