/**
 * kernel/include/kairos/boot.h - Boot information structures
 */

#ifndef _KAIROS_BOOT_H
#define _KAIROS_BOOT_H

#include <kairos/config.h>
#include <kairos/types.h>

#define BOOT_MEMMAP_MAX 256

enum boot_mem_type {
    BOOT_MEM_USABLE = 0,
    BOOT_MEM_RESERVED,
    BOOT_MEM_ACPI_RECLAIM,
    BOOT_MEM_ACPI_NVS,
    BOOT_MEM_BOOTLOADER_RECLAIM,
    BOOT_MEM_KERNEL_AND_MODULES,
    BOOT_MEM_FRAMEBUFFER,
    BOOT_MEM_BAD
};

struct boot_memmap_entry {
    uint64_t base;
    uint64_t length;
    uint32_t type;
};

struct boot_cpu_info {
    uint32_t cpu_id;
    uint64_t hw_id;
    void *mp_info;
};

struct boot_info {
    const char *bootloader_name;
    const char *bootloader_version;
    const char *cmdline;
    void *dtb;
    void *rsdp;
    void *efi_system_table;

    uint64_t hhdm_offset;

    uint64_t kernel_phys_base;
    uint64_t kernel_virt_base;
    uint64_t kernel_entry;

    uint64_t phys_mem_min;
    uint64_t phys_mem_max;

    uint32_t memmap_count;
    struct boot_memmap_entry memmap[BOOT_MEMMAP_MAX];

    uint32_t cpu_count;
    uint32_t bsp_cpu_id;
    struct boot_cpu_info cpus[CONFIG_MAX_CPUS];
};

static inline bool boot_mem_is_ram(uint32_t type) {
    switch (type) {
        case BOOT_MEM_USABLE:
        case BOOT_MEM_BOOTLOADER_RECLAIM:
        case BOOT_MEM_KERNEL_AND_MODULES:
        case BOOT_MEM_ACPI_RECLAIM:
        case BOOT_MEM_ACPI_NVS:
            return true;
        default:
            return false;
    }
}

const struct boot_info *boot_info_get(void);
uint64_t boot_hhdm_offset(void);
void boot_info_set(const struct boot_info *info);

#endif /* _KAIROS_BOOT_H */
