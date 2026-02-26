/**
 * kernel/core/init/boot.c - Early boot initialization
 */

#include <kairos/boot.h>
#include <kairos/fdt.h>
#include <kairos/init.h>
#include <kairos/platform_core.h>
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
    pr_debug("boot: limine firmware type=%llu rev=%llu\n",
             (unsigned long long)bi->limine_firmware_type,
             (unsigned long long)bi->limine_firmware_type_revision);
    pr_debug("boot: limine paging mode=%llu rev=%llu\n",
             (unsigned long long)bi->limine_paging_mode,
             (unsigned long long)bi->limine_paging_mode_revision);
    pr_debug("boot: limine mp rev=%llu flags=0x%llx\n",
             (unsigned long long)bi->limine_mp_revision,
             (unsigned long long)bi->limine_mp_flags);
    if (bi->boot_timestamp_revision) {
        pr_debug("boot: limine date_at_boot=%lld rev=%llu\n",
                 (long long)bi->boot_timestamp,
                 (unsigned long long)bi->boot_timestamp_revision);
    }
    if (bi->bootloader_perf_revision) {
        pr_debug("boot: limine perf reset=%lluus init=%lluus exec=%lluus rev=%llu\n",
                 (unsigned long long)bi->bootloader_reset_usec,
                 (unsigned long long)bi->bootloader_init_usec,
                 (unsigned long long)bi->bootloader_exec_usec,
                 (unsigned long long)bi->bootloader_perf_revision);
    }

#if defined(ARCH_aarch64)
    platform_select("aarch64");
#elif defined(ARCH_riscv64)
    platform_select("riscv64");
#elif defined(ARCH_x86_64)
    platform_select("x86_64");
#endif
}
