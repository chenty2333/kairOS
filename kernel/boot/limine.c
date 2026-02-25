/**
 * kernel/boot/limine.c - Limine boot protocol integration
 */

#include <boot/limine.h>
#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/config.h>
#include <kairos/fdt.h>
#include <kairos/printk.h>
#include <kairos/string.h>

struct efi_guid {
    uint32_t a;
    uint16_t b;
    uint16_t c;
    uint8_t d[8];
};

struct efi_configuration_table {
    struct efi_guid guid;
    void *table;
};

struct efi_table_header {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
};

struct efi_system_table {
    struct efi_table_header hdr;
    uint16_t *firmware_vendor;
    uint32_t firmware_revision;
    void *con_in_handle;
    void *con_in;
    void *con_out_handle;
    void *con_out;
    void *std_err_handle;
    void *std_err;
    void *runtime_services;
    void *boot_services;
    size_t num_tables;
    struct efi_configuration_table *tables;
};

static struct boot_info boot_info;

#if defined(ARCH_aarch64)
extern volatile uintptr_t aarch64_mp_info_raw_ptrs[CONFIG_MAX_CPUS];
extern volatile uintptr_t aarch64_mp_info_virt_ptrs[CONFIG_MAX_CPUS];
extern volatile uint32_t aarch64_mp_info_ptr_count;
#endif

static uintptr_t limine_ptr_to_virt(const volatile void *ptr) {
    uintptr_t addr = (uintptr_t)ptr;
    if (!addr)
        return 0;
    if (boot_info.hhdm_offset && addr < boot_info.hhdm_offset)
        addr += (uintptr_t)boot_info.hhdm_offset;
    return addr;
}

#if defined(ARCH_aarch64)
static bool efi_guid_equal(const struct efi_guid *a,
                           const struct efi_guid *b) {
    return memcmp(a, b, sizeof(*a)) == 0;
}

static void *efi_find_dtb(void *system_table) {
    static const struct efi_guid dtb_guid = {
        0xb1b621d5, 0xf19c, 0x41a5,
        {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}
    };

    if (!system_table) {
        return NULL;
    }

    struct efi_system_table *st =
        (struct efi_system_table *)limine_ptr_to_virt(system_table);
    if (!st || st->num_tables == 0) {
        return NULL;
    }

    struct efi_configuration_table *tables =
        (struct efi_configuration_table *)limine_ptr_to_virt(st->tables);
    if (!tables) {
        return NULL;
    }

    for (size_t i = 0; i < st->num_tables; i++) {
        struct efi_configuration_table *tbl = &tables[i];
        if (efi_guid_equal(&tbl->guid, &dtb_guid)) {
            return (void *)limine_ptr_to_virt(tbl->table);
        }
    }

    return NULL;
}
#endif

/* Limine base revision */
__attribute__((used, section(".limine_requests")))
static volatile uint64_t limine_base_revision[] = LIMINE_BASE_REVISION(5);

/* Request markers */
__attribute__((used, section(".limine_requests_start_marker")))
static volatile uint64_t limine_requests_start[] = LIMINE_REQUESTS_START_MARKER;

/* Requests */
__attribute__((used, section(".limine_requests")))
static volatile struct limine_bootloader_info_request limine_bootloader_info = {
    .id = LIMINE_BOOTLOADER_INFO_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_executable_cmdline_request limine_cmdline = {
    .id = LIMINE_EXECUTABLE_CMDLINE_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_executable_file_request limine_exec_file = {
    .id = LIMINE_EXECUTABLE_FILE_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_firmware_type_request limine_firmware_type = {
    .id = LIMINE_FIRMWARE_TYPE_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_hhdm_request limine_hhdm = {
    .id = LIMINE_HHDM_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_memmap_request limine_memmap = {
    .id = LIMINE_MEMMAP_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_framebuffer_request limine_framebuffer = {
    .id = LIMINE_FRAMEBUFFER_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_dtb_request limine_dtb = {
    .id = LIMINE_DTB_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_module_request limine_modules = {
    .id = LIMINE_MODULE_REQUEST_ID,
    .revision = 0,
    .response = NULL,
    .internal_module_count = 0,
    .internal_modules = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_rsdp_request limine_rsdp = {
    .id = LIMINE_RSDP_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_smbios_request limine_smbios = {
    .id = LIMINE_SMBIOS_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_efi_system_table_request limine_efi = {
    .id = LIMINE_EFI_SYSTEM_TABLE_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_efi_memmap_request limine_efi_memmap = {
    .id = LIMINE_EFI_MEMMAP_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_executable_address_request limine_exec_addr = {
    .id = LIMINE_EXECUTABLE_ADDRESS_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_date_at_boot_request limine_date_at_boot = {
    .id = LIMINE_DATE_AT_BOOT_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_bootloader_performance_request limine_boot_perf = {
    .id = LIMINE_BOOTLOADER_PERFORMANCE_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_riscv_bsp_hartid_request limine_riscv_bsp_hartid = {
    .id = LIMINE_RISCV_BSP_HARTID_REQUEST_ID,
    .revision = 0,
    .response = NULL,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_mp_request limine_mp = {
    .id = LIMINE_MP_REQUEST_ID,
    .revision = 0,
    .response = NULL,
#if defined(ARCH_x86_64)
    .flags = LIMINE_MP_REQUEST_X86_64_X2APIC,
#else
    .flags = 0,
#endif
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_paging_mode_request limine_paging_mode = {
    .id = LIMINE_PAGING_MODE_REQUEST_ID,
    .revision = 0,
    .response = NULL,
#if defined(ARCH_x86_64)
    .mode = LIMINE_PAGING_MODE_X86_64_DEFAULT,
    .max_mode = LIMINE_PAGING_MODE_X86_64_4LVL,
    .min_mode = LIMINE_PAGING_MODE_X86_64_4LVL,
#elif defined(ARCH_aarch64)
    .mode = LIMINE_PAGING_MODE_AARCH64_DEFAULT,
    .max_mode = LIMINE_PAGING_MODE_AARCH64_4LVL,
    .min_mode = LIMINE_PAGING_MODE_AARCH64_4LVL,
#elif defined(ARCH_riscv64)
    .mode = LIMINE_PAGING_MODE_RISCV_SV39,
    .max_mode = LIMINE_PAGING_MODE_RISCV_SV39,
    .min_mode = LIMINE_PAGING_MODE_RISCV_SV39,
#else
    .mode = 0,
    .max_mode = 0,
    .min_mode = 0,
#endif
};

__attribute__((used, section(".limine_requests_end_marker")))
static volatile uint64_t limine_requests_end[] = LIMINE_REQUESTS_END_MARKER;

static bool limine_path_has_suffix(const char *path, const char *suffix) {
    if (!path || !suffix) {
        return false;
    }
    size_t plen = strlen(path);
    size_t slen = strlen(suffix);
    if (slen == 0 || plen < slen) {
        return false;
    }
    return memcmp(path + plen - slen, suffix, slen) == 0;
}

static void *limine_find_dtb_module(void) {
    struct limine_module_response *mod_resp =
        (struct limine_module_response *)limine_ptr_to_virt(limine_modules.response);
    if (!mod_resp || mod_resp->module_count == 0) {
        return NULL;
    }

    struct limine_file **modules =
        (struct limine_file **)limine_ptr_to_virt(mod_resp->modules);
    if (!modules) {
        return NULL;
    }

    for (uint64_t i = 0; i < mod_resp->module_count; i++) {
        struct limine_file *mod =
            (struct limine_file *)limine_ptr_to_virt(modules[i]);
        if (!mod) {
            continue;
        }

        const char *mod_string =
            (const char *)limine_ptr_to_virt(mod->string);
        const char *mod_path =
            (const char *)limine_ptr_to_virt(mod->path);

        if (mod_string && strcmp(mod_string, "dtb") == 0) {
            return (void *)limine_ptr_to_virt(mod->address);
        }
        if (limine_path_has_suffix(mod_path, ".dtb") ||
            limine_path_has_suffix(mod_string, ".dtb")) {
            return (void *)limine_ptr_to_virt(mod->address);
        }
    }
    return NULL;
}

static uint32_t limine_memmap_type_to_boot(uint32_t type) {
    switch (type) {
    case LIMINE_MEMMAP_USABLE:
        return BOOT_MEM_USABLE;
    case LIMINE_MEMMAP_RESERVED:
        return BOOT_MEM_RESERVED;
    case LIMINE_MEMMAP_ACPI_RECLAIMABLE:
        return BOOT_MEM_ACPI_RECLAIM;
    case LIMINE_MEMMAP_ACPI_NVS:
        return BOOT_MEM_ACPI_NVS;
    case LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE:
        return BOOT_MEM_BOOTLOADER_RECLAIM;
    case LIMINE_MEMMAP_EXECUTABLE_AND_MODULES:
        return BOOT_MEM_KERNEL_AND_MODULES;
    case LIMINE_MEMMAP_FRAMEBUFFER:
        return BOOT_MEM_FRAMEBUFFER;
    case LIMINE_MEMMAP_BAD_MEMORY:
        return BOOT_MEM_BAD;
#ifdef LIMINE_MEMMAP_RESERVED_MAPPED
    case LIMINE_MEMMAP_RESERVED_MAPPED:
        return BOOT_MEM_RESERVED;
#endif
#ifdef LIMINE_MEMMAP_ACPI_TABLES
    case LIMINE_MEMMAP_ACPI_TABLES:
        return BOOT_MEM_ACPI_RECLAIM;
#endif
    default:
        return BOOT_MEM_RESERVED;
    }
}

static const char *limine_fw_type_name(uint64_t fw) {
    switch (fw) {
    case LIMINE_FIRMWARE_TYPE_X86BIOS:
        return "x86bios";
    case LIMINE_FIRMWARE_TYPE_EFI32:
        return "efi32";
    case LIMINE_FIRMWARE_TYPE_EFI64:
        return "efi64";
    case LIMINE_FIRMWARE_TYPE_SBI:
        return "sbi";
    default:
        return "unknown";
    }
}

static bool limine_fw_type_allowed(uint64_t fw) {
#if defined(ARCH_x86_64) || defined(ARCH_aarch64)
    return fw == LIMINE_FIRMWARE_TYPE_EFI64;
#elif defined(ARCH_riscv64)
    return fw == LIMINE_FIRMWARE_TYPE_EFI64 || fw == LIMINE_FIRMWARE_TYPE_SBI;
#else
    return true;
#endif
}

static const char *limine_media_type_name(uint64_t media_type) {
    switch (media_type) {
    case LIMINE_MEDIA_TYPE_GENERIC:
        return "generic";
    case LIMINE_MEDIA_TYPE_OPTICAL:
        return "optical";
    case LIMINE_MEDIA_TYPE_TFTP:
        return "tftp";
    default:
        return "unknown";
    }
}

static void boot_init_limine(void) {
    memset(&boot_info, 0, sizeof(boot_info));
#if defined(ARCH_aarch64)
    memset((void *)aarch64_mp_info_raw_ptrs, 0, sizeof(aarch64_mp_info_raw_ptrs));
    memset((void *)aarch64_mp_info_virt_ptrs, 0, sizeof(aarch64_mp_info_virt_ptrs));
    aarch64_mp_info_ptr_count = 0;
#endif

    if (!LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision)) {
        panic("Limine base revision unsupported");
    }
    if (LIMINE_LOADED_BASE_REVISION_VALID(limine_base_revision)) {
        boot_info.limine_loaded_base_revision_valid = 1;
        boot_info.limine_loaded_base_revision =
            LIMINE_LOADED_BASE_REVISION(limine_base_revision);
    }

    struct limine_firmware_type_response *fw_type_resp =
        (struct limine_firmware_type_response *)
            limine_ptr_to_virt(limine_firmware_type.response);
    if (!fw_type_resp) {
        panic("boot: limine firmware type response missing");
    }
    boot_info.limine_firmware_type_revision = fw_type_resp->revision;
    boot_info.limine_firmware_type = fw_type_resp->firmware_type;
    if (!limine_fw_type_allowed(boot_info.limine_firmware_type)) {
        panic("boot: unsupported limine firmware type=%llu",
              (unsigned long long)boot_info.limine_firmware_type);
    }
    pr_info("boot: limine firmware type=%s(%llu) rev=%llu\n",
            limine_fw_type_name(boot_info.limine_firmware_type),
            (unsigned long long)boot_info.limine_firmware_type,
            (unsigned long long)boot_info.limine_firmware_type_revision);

    struct limine_paging_mode_response *paging_resp =
        (struct limine_paging_mode_response *)
            limine_ptr_to_virt(limine_paging_mode.response);
    if (!paging_resp) {
        panic("boot: limine paging mode response missing");
    }
    boot_info.limine_paging_mode_revision = paging_resp->revision;
    boot_info.limine_paging_mode = paging_resp->mode;
    if (boot_info.limine_paging_mode < limine_paging_mode.min_mode ||
        boot_info.limine_paging_mode > limine_paging_mode.max_mode) {
        panic("boot: limine paging mode out of range mode=%llu range=[%llu,%llu]",
              (unsigned long long)boot_info.limine_paging_mode,
              (unsigned long long)limine_paging_mode.min_mode,
              (unsigned long long)limine_paging_mode.max_mode);
    }
    if (limine_paging_mode.min_mode == limine_paging_mode.max_mode &&
        boot_info.limine_paging_mode != limine_paging_mode.min_mode) {
        panic("boot: limine paging mode mismatch mode=%llu expected=%llu",
              (unsigned long long)boot_info.limine_paging_mode,
              (unsigned long long)limine_paging_mode.min_mode);
    }
    pr_info("boot: limine paging mode=%llu rev=%llu req=[%llu,%llu]\n",
            (unsigned long long)boot_info.limine_paging_mode,
            (unsigned long long)boot_info.limine_paging_mode_revision,
            (unsigned long long)limine_paging_mode.min_mode,
            (unsigned long long)limine_paging_mode.max_mode);

    if (limine_hhdm.response) {
        boot_info.hhdm_offset = limine_hhdm.response->offset;
    }

    struct limine_bootloader_info_response *bootloader_resp =
        (struct limine_bootloader_info_response *)
            limine_ptr_to_virt(limine_bootloader_info.response);
    if (bootloader_resp) {
        boot_info.bootloader_name =
            (const char *)limine_ptr_to_virt(bootloader_resp->name);
        boot_info.bootloader_version =
            (const char *)limine_ptr_to_virt(bootloader_resp->version);
    }

    struct limine_executable_cmdline_response *cmdline_resp =
        (struct limine_executable_cmdline_response *)
            limine_ptr_to_virt(limine_cmdline.response);
    if (cmdline_resp) {
        boot_info.cmdline =
            (const char *)limine_ptr_to_virt(cmdline_resp->cmdline);
    }

    struct limine_executable_file_response *exec_file_resp =
        (struct limine_executable_file_response *)
            limine_ptr_to_virt(limine_exec_file.response);
    if (exec_file_resp) {
        boot_info.limine_executable_revision = exec_file_resp->revision;
        struct limine_file *exec_file =
            (struct limine_file *)
                limine_ptr_to_virt(exec_file_resp->executable_file);
        if (exec_file) {
            boot_info.limine_executable_path =
                (const char *)limine_ptr_to_virt(exec_file->path);
            boot_info.limine_executable_string =
                (const char *)limine_ptr_to_virt(exec_file->string);
            boot_info.limine_executable_media_type = exec_file->media_type;
            boot_info.limine_executable_partition_index =
                exec_file->partition_index;
            pr_info("boot: limine executable media=%s(%llu) part=%llu rev=%llu\n",
                    limine_media_type_name(boot_info.limine_executable_media_type),
                    (unsigned long long)boot_info.limine_executable_media_type,
                    (unsigned long long)boot_info.limine_executable_partition_index,
                    (unsigned long long)boot_info.limine_executable_revision);
        }
    }

    struct limine_dtb_response *dtb_resp =
        (struct limine_dtb_response *)limine_ptr_to_virt(limine_dtb.response);
    if (dtb_resp) {
        boot_info.dtb = (void *)limine_ptr_to_virt(dtb_resp->dtb_ptr);
    }

    struct limine_rsdp_response *rsdp_resp =
        (struct limine_rsdp_response *)limine_ptr_to_virt(limine_rsdp.response);
    if (rsdp_resp) {
        boot_info.rsdp = (void *)limine_ptr_to_virt(rsdp_resp->address);
    }

    struct limine_smbios_response *smbios_resp =
        (struct limine_smbios_response *)limine_ptr_to_virt(limine_smbios.response);
    if (smbios_resp) {
        boot_info.smbios_revision = smbios_resp->revision;
        boot_info.smbios_entry_32 = (void *)limine_ptr_to_virt(smbios_resp->entry_32);
        boot_info.smbios_entry_64 = (void *)limine_ptr_to_virt(smbios_resp->entry_64);
    }

    struct limine_efi_system_table_response *efi_resp =
        (struct limine_efi_system_table_response *)
            limine_ptr_to_virt(limine_efi.response);
    if (efi_resp) {
        boot_info.efi_system_table =
            (void *)limine_ptr_to_virt(efi_resp->address);
    }

    struct limine_efi_memmap_response *efi_memmap_resp =
        (struct limine_efi_memmap_response *)
            limine_ptr_to_virt(limine_efi_memmap.response);
    if (efi_memmap_resp) {
        boot_info.efi_memmap_revision = efi_memmap_resp->revision;
        boot_info.efi_memmap = (void *)limine_ptr_to_virt(efi_memmap_resp->memmap);
        boot_info.efi_memmap_size = efi_memmap_resp->memmap_size;
        boot_info.efi_memmap_desc_size = efi_memmap_resp->desc_size;
        boot_info.efi_memmap_desc_version = efi_memmap_resp->desc_version;
        if (boot_info.efi_memmap_size && !boot_info.efi_memmap) {
            panic("boot: limine efi memmap pointer missing");
        }
        if (boot_info.efi_memmap_size && boot_info.efi_memmap_desc_size == 0) {
            panic("boot: limine efi memmap desc_size is zero");
        }
    }

    struct limine_executable_address_response *exec_addr_resp =
        (struct limine_executable_address_response *)
            limine_ptr_to_virt(limine_exec_addr.response);
    if (exec_addr_resp) {
        boot_info.kernel_phys_base = exec_addr_resp->physical_base;
        boot_info.kernel_virt_base = exec_addr_resp->virtual_base;
    }

    struct limine_date_at_boot_response *date_resp =
        (struct limine_date_at_boot_response *)
            limine_ptr_to_virt(limine_date_at_boot.response);
    if (date_resp) {
        boot_info.boot_timestamp = date_resp->timestamp;
        boot_info.boot_timestamp_revision = date_resp->revision;
        pr_info("boot: limine date_at_boot=%lld rev=%llu\n",
                (long long)boot_info.boot_timestamp,
                (unsigned long long)boot_info.boot_timestamp_revision);
    }

    struct limine_bootloader_performance_response *perf_resp =
        (struct limine_bootloader_performance_response *)
            limine_ptr_to_virt(limine_boot_perf.response);
    if (perf_resp) {
        boot_info.bootloader_perf_revision = perf_resp->revision;
        boot_info.bootloader_reset_usec = perf_resp->reset_usec;
        boot_info.bootloader_init_usec = perf_resp->init_usec;
        boot_info.bootloader_exec_usec = perf_resp->exec_usec;
        pr_info("boot: limine perf reset=%lluus init=%lluus exec=%lluus rev=%llu\n",
                (unsigned long long)boot_info.bootloader_reset_usec,
                (unsigned long long)boot_info.bootloader_init_usec,
                (unsigned long long)boot_info.bootloader_exec_usec,
                (unsigned long long)boot_info.bootloader_perf_revision);
    }

    struct limine_riscv_bsp_hartid_response *riscv_bsp_hartid_resp =
        (struct limine_riscv_bsp_hartid_response *)
            limine_ptr_to_virt(limine_riscv_bsp_hartid.response);
    if (riscv_bsp_hartid_resp) {
        boot_info.limine_riscv_bsp_hartid_valid = 1;
        boot_info.limine_riscv_bsp_hartid_revision = riscv_bsp_hartid_resp->revision;
        boot_info.limine_riscv_bsp_hartid = riscv_bsp_hartid_resp->bsp_hartid;
    }

    if (!boot_info.dtb) {
        boot_info.dtb = limine_find_dtb_module();
    }
#if defined(ARCH_aarch64)
    if (!boot_info.dtb && boot_info.efi_system_table) {
        boot_info.dtb = efi_find_dtb(boot_info.efi_system_table);
    }
#endif

    struct limine_module_response *modules_resp =
        (struct limine_module_response *)limine_ptr_to_virt(limine_modules.response);
    if (modules_resp && modules_resp->module_count) {
        uint64_t count = modules_resp->module_count;
        if (count > BOOT_MODULES_MAX)
            count = BOOT_MODULES_MAX;

        struct limine_file **modules =
            (struct limine_file **)limine_ptr_to_virt(modules_resp->modules);
        if (!modules) {
            count = 0;
        }

        boot_info.module_count = (uint32_t)count;
        for (uint64_t i = 0; i < count; i++) {
            struct limine_file *mod =
                (struct limine_file *)limine_ptr_to_virt(modules[i]);
            if (!mod)
                continue;
            boot_info.modules[i].path =
                (const char *)limine_ptr_to_virt(mod->path);
            boot_info.modules[i].string =
                (const char *)limine_ptr_to_virt(mod->string);
            boot_info.modules[i].addr =
                (void *)limine_ptr_to_virt(mod->address);
            boot_info.modules[i].size = mod->size;
        }
    }

    struct limine_memmap_response *memmap_resp =
        (struct limine_memmap_response *)limine_ptr_to_virt(limine_memmap.response);
    if (!memmap_resp) {
        panic("boot: limine memmap response missing");
    }
    if (memmap_resp->entry_count == 0) {
        panic("boot: limine memmap empty");
    }

    uint64_t min = UINT64_MAX;
    uint64_t max = 0;
    uint64_t count = memmap_resp->entry_count;
    if (count > BOOT_MEMMAP_MAX) {
        count = BOOT_MEMMAP_MAX;
    }

    struct limine_memmap_entry **entries =
        (struct limine_memmap_entry **)limine_ptr_to_virt(memmap_resp->entries);
    if (!entries) {
        panic("boot: limine memmap entries missing");
    }

    for (uint64_t i = 0; i < count; i++) {
        struct limine_memmap_entry *entry =
            (struct limine_memmap_entry *)limine_ptr_to_virt(entries[i]);
        if (!entry) {
            panic("boot: limine memmap entry[%llu] missing",
                  (unsigned long long)i);
        }
        if (entry->length && entry->base > UINT64_MAX - entry->length) {
            panic("boot: limine memmap entry[%llu] overflow base=0x%llx len=0x%llx",
                  (unsigned long long)i,
                  (unsigned long long)entry->base,
                  (unsigned long long)entry->length);
        }

        boot_info.memmap[i].base = entry->base;
        boot_info.memmap[i].length = entry->length;
        boot_info.memmap[i].type = limine_memmap_type_to_boot(entry->type);
        if (boot_mem_is_ram(boot_info.memmap[i].type)) {
            if (entry->base < min)
                min = entry->base;
            if (entry->base + entry->length > max)
                max = entry->base + entry->length;
        }
    }
    boot_info.memmap_count = (uint32_t)count;
    if (min != UINT64_MAX) {
        boot_info.phys_mem_min = min;
        boot_info.phys_mem_max = max;
    } else {
        panic("boot: limine memmap has no RAM ranges");
    }

    struct limine_framebuffer_response *fb_resp =
        (struct limine_framebuffer_response *)
            limine_ptr_to_virt(limine_framebuffer.response);
    if (fb_resp && fb_resp->framebuffer_count) {
        uint64_t count = fb_resp->framebuffer_count;
        if (count > BOOT_FRAMEBUFFERS_MAX)
            count = BOOT_FRAMEBUFFERS_MAX;

        struct limine_framebuffer **fbs =
            (struct limine_framebuffer **)limine_ptr_to_virt(fb_resp->framebuffers);
        if (!fbs) {
            count = 0;
        }

        boot_info.framebuffer_count = (uint32_t)count;
        for (uint64_t i = 0; i < count; i++) {
            struct limine_framebuffer *fb =
                (struct limine_framebuffer *)limine_ptr_to_virt(fbs[i]);
            if (!fb)
                continue;
            uint64_t fb_addr = (uint64_t)(uintptr_t)fb->address;
            if (boot_info.hhdm_offset &&
                fb_addr >= boot_info.hhdm_offset) {
                fb_addr -= boot_info.hhdm_offset;
            }
            boot_info.framebuffers[i].phys = fb_addr;
            boot_info.framebuffers[i].width = (uint32_t)fb->width;
            boot_info.framebuffers[i].height = (uint32_t)fb->height;
            boot_info.framebuffers[i].pitch = (uint32_t)fb->pitch;
            boot_info.framebuffers[i].bpp = (uint32_t)fb->bpp;
            boot_info.framebuffers[i].memory_model = fb->memory_model;
            boot_info.framebuffers[i].red_mask_size = fb->red_mask_size;
            boot_info.framebuffers[i].red_mask_shift = fb->red_mask_shift;
            boot_info.framebuffers[i].green_mask_size = fb->green_mask_size;
            boot_info.framebuffers[i].green_mask_shift = fb->green_mask_shift;
            boot_info.framebuffers[i].blue_mask_size = fb->blue_mask_size;
            boot_info.framebuffers[i].blue_mask_shift = fb->blue_mask_shift;
            boot_info.framebuffers[i].size =
                fb->pitch * fb->height;
        }
    }

#if defined(ARCH_aarch64)
    uint32_t limine_cpu_count = 0;
#endif
    struct limine_mp_response *mp_resp =
        (struct limine_mp_response *)limine_ptr_to_virt(limine_mp.response);
    if (!mp_resp) {
        panic("boot: limine mp response missing");
    }
    boot_info.limine_mp_revision = mp_resp->revision;
    boot_info.limine_mp_flags = (uint64_t)mp_resp->flags;
    uint64_t requested_mp_flags = limine_mp.flags;
    uint64_t missing_mp_flags = requested_mp_flags & ~boot_info.limine_mp_flags;
    uint64_t unknown_mp_flags = boot_info.limine_mp_flags & ~requested_mp_flags;
#if defined(ARCH_x86_64)
    if (missing_mp_flags) {
        pr_warn("boot: limine mp missing requested flags req=0x%llx got=0x%llx\n",
                (unsigned long long)requested_mp_flags,
                (unsigned long long)boot_info.limine_mp_flags);
    }
#else
    if (missing_mp_flags) {
        panic("boot: limine mp missing requested flags req=0x%llx got=0x%llx",
              (unsigned long long)requested_mp_flags,
              (unsigned long long)boot_info.limine_mp_flags);
    }
#endif
    if (unknown_mp_flags) {
        pr_warn("boot: limine mp has unknown flags req=0x%llx got=0x%llx\n",
                (unsigned long long)requested_mp_flags,
                (unsigned long long)boot_info.limine_mp_flags);
    }
    pr_info("boot: limine mp rev=%llu flags=0x%llx cpus=%llu\n",
            (unsigned long long)boot_info.limine_mp_revision,
            (unsigned long long)boot_info.limine_mp_flags,
            (unsigned long long)mp_resp->cpu_count);
#if defined(ARCH_riscv64)
    if (boot_info.limine_riscv_bsp_hartid_valid &&
        boot_info.limine_riscv_bsp_hartid != mp_resp->bsp_hartid) {
        panic("boot: limine riscv bsp hartid mismatch req=%llu mp=%llu",
              (unsigned long long)boot_info.limine_riscv_bsp_hartid,
              (unsigned long long)mp_resp->bsp_hartid);
    }
#endif
    if (mp_resp->cpu_count) {
        uint64_t count = mp_resp->cpu_count;
        if (count > CONFIG_MAX_CPUS)
            count = CONFIG_MAX_CPUS;

        struct limine_mp_info **cpus =
            (struct limine_mp_info **)limine_ptr_to_virt(mp_resp->cpus);
        if (!cpus) {
            panic("boot: limine mp cpu array missing");
        }

        boot_info.cpu_count = (uint32_t)count;
#if defined(ARCH_aarch64)
        limine_cpu_count = (uint32_t)count;
        aarch64_mp_info_ptr_count = (uint32_t)count;
#endif
        boot_info.bsp_cpu_id = 0;
        for (uint64_t i = 0; i < count; i++) {
            struct limine_mp_info *info =
                (struct limine_mp_info *)limine_ptr_to_virt(cpus[i]);
            if (!info) {
                panic("boot: limine mp cpu[%llu] missing",
                      (unsigned long long)i);
            }
            boot_info.cpus[i].cpu_id = (uint32_t)i;
            boot_info.cpus[i].mp_info = info;
#if defined(ARCH_x86_64)
            boot_info.cpus[i].hw_id = info->lapic_id;
            if (info->lapic_id == mp_resp->bsp_lapic_id)
                boot_info.bsp_cpu_id = (uint32_t)i;
#elif defined(ARCH_aarch64)
            boot_info.cpus[i].hw_id = info->mpidr;
            aarch64_mp_info_raw_ptrs[i] = (uintptr_t)cpus[i];
            aarch64_mp_info_virt_ptrs[i] = (uintptr_t)info;
            if (info->mpidr == mp_resp->bsp_mpidr)
                boot_info.bsp_cpu_id = (uint32_t)i;
#elif defined(ARCH_riscv64)
            boot_info.cpus[i].hw_id = info->hartid;
            if (info->hartid == mp_resp->bsp_hartid)
                boot_info.bsp_cpu_id = (uint32_t)i;
#else
            boot_info.cpus[i].hw_id = 0;
#endif
        }
    } else {
        boot_info.cpu_count = 1;
        boot_info.bsp_cpu_id = 0;
#if defined(ARCH_riscv64)
        if (boot_info.limine_riscv_bsp_hartid_valid) {
            boot_info.cpus[0].cpu_id = 0;
            boot_info.cpus[0].hw_id = boot_info.limine_riscv_bsp_hartid;
        }
#endif
    }

#if defined(ARCH_aarch64)
    if (boot_info.cpu_count <= 1 && boot_info.dtb) {
        uint64_t cpu_ids[CONFIG_MAX_CPUS] = {0};
        uint32_t dtb_cpu_count = 0;
        if (fdt_get_cpus(boot_info.dtb, cpu_ids, CONFIG_MAX_CPUS,
                         &dtb_cpu_count) == 0 &&
            dtb_cpu_count > 1) {
            boot_info.cpu_count = dtb_cpu_count;
            boot_info.bsp_cpu_id = 0;
            for (uint32_t i = 0; i < dtb_cpu_count; i++) {
                void *mp_info = (i < limine_cpu_count) ? boot_info.cpus[i].mp_info : NULL;
                boot_info.cpus[i].cpu_id = i;
                boot_info.cpus[i].hw_id = cpu_ids[i];
                boot_info.cpus[i].mp_info = mp_info;
                if (mp_resp &&
                    cpu_ids[i] == mp_resp->bsp_mpidr)
                    boot_info.bsp_cpu_id = i;
            }
            pr_info("boot: DTB CPU topology %u CPUs\n", dtb_cpu_count);
        }
    }
#endif

    boot_info_set(&boot_info);
}

extern void kernel_main(const struct boot_info *bi);

void limine_bootstrap(void) {
    boot_init_limine();
    arch_cpu_init((int)boot_info.bsp_cpu_id);
    kernel_main(boot_info_get());
    for (;;) {
        arch_cpu_halt();
    }
}
