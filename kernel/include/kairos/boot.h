/**
 * kernel/include/kairos/boot.h - Boot information structures
 */

#ifndef _KAIROS_BOOT_H
#define _KAIROS_BOOT_H

#include <kairos/config.h>
#include <kairos/types.h>

#define BOOT_MEMMAP_MAX 256
#define BOOT_MODULES_MAX 16
#define BOOT_FRAMEBUFFERS_MAX 4

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

struct boot_module {
    const char *path;
    const char *string;
    void *addr;
    uint64_t size;
};

struct boot_framebuffer {
    uint64_t phys;
    uint64_t size;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint8_t memory_model;
    uint8_t red_mask_size;
    uint8_t red_mask_shift;
    uint8_t green_mask_size;
    uint8_t green_mask_shift;
    uint8_t blue_mask_size;
    uint8_t blue_mask_shift;
};

struct boot_info {
    const char *bootloader_name;
    const char *bootloader_version;
    const char *cmdline;
    const char *limine_executable_path;
    const char *limine_executable_string;
    uint64_t limine_executable_media_type;
    uint64_t limine_executable_partition_index;
    uint64_t limine_executable_revision;
    void *dtb;
    void *rsdp;
    void *efi_system_table;

    uint64_t limine_firmware_type;
    uint64_t limine_firmware_type_revision;
    uint64_t limine_loaded_base_revision;
    uint64_t limine_loaded_base_revision_valid;
    uint64_t limine_paging_mode;
    uint64_t limine_paging_mode_revision;
    uint64_t limine_mp_revision;
    uint64_t limine_mp_flags;

    int64_t boot_timestamp;
    uint64_t boot_timestamp_revision;
    uint64_t bootloader_reset_usec;
    uint64_t bootloader_init_usec;
    uint64_t bootloader_exec_usec;
    uint64_t bootloader_perf_revision;

    uint64_t hhdm_offset;

    uint64_t kernel_phys_base;
    uint64_t kernel_virt_base;
    uint64_t kernel_entry;

    uint64_t phys_mem_min;
    uint64_t phys_mem_max;

    uint32_t memmap_count;
    struct boot_memmap_entry memmap[BOOT_MEMMAP_MAX];

    uint32_t module_count;
    struct boot_module modules[BOOT_MODULES_MAX];

    uint32_t framebuffer_count;
    struct boot_framebuffer framebuffers[BOOT_FRAMEBUFFERS_MAX];

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
const struct boot_module *boot_find_module(const char *name);

#endif /* _KAIROS_BOOT_H */
