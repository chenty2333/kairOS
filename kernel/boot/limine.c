/**
 * kernel/boot/limine.c - Limine boot protocol integration
 */

#include <boot/limine.h>
#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/config.h>
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

    struct efi_system_table *st = (struct efi_system_table *)system_table;
    if (!st->tables || st->num_tables == 0) {
        return NULL;
    }

    for (size_t i = 0; i < st->num_tables; i++) {
        struct efi_configuration_table *tbl = &st->tables[i];
        if (efi_guid_equal(&tbl->guid, &dtb_guid)) {
            return tbl->table;
        }
    }

    return NULL;
}

/* Limine base revision */
__attribute__((used, section(".limine_requests")))
static volatile uint64_t limine_base_revision[] = LIMINE_BASE_REVISION(0);

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
static volatile struct limine_efi_system_table_request limine_efi = {
    .id = LIMINE_EFI_SYSTEM_TABLE_REQUEST_ID,
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
static volatile struct limine_mp_request limine_mp = {
    .id = LIMINE_MP_REQUEST_ID,
    .revision = 0,
    .response = NULL,
    .flags = 0,
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_paging_mode_request limine_paging_mode = {
    .id = LIMINE_PAGING_MODE_REQUEST_ID,
    .revision = 0,
    .response = NULL,
#if defined(ARCH_x86_64)
    .mode = LIMINE_PAGING_MODE_X86_64_DEFAULT,
    .max_mode = LIMINE_PAGING_MODE_X86_64_5LVL,
    .min_mode = LIMINE_PAGING_MODE_X86_64_4LVL,
#elif defined(ARCH_aarch64)
    .mode = LIMINE_PAGING_MODE_AARCH64_DEFAULT,
    .max_mode = LIMINE_PAGING_MODE_AARCH64_5LVL,
    .min_mode = LIMINE_PAGING_MODE_AARCH64_4LVL,
#elif defined(ARCH_riscv64)
    .mode = LIMINE_PAGING_MODE_RISCV_SV39,
    .max_mode = LIMINE_PAGING_MODE_RISCV_SV48,
    .min_mode = LIMINE_PAGING_MODE_RISCV_SV39,
#else
    .mode = 0,
    .max_mode = 0,
    .min_mode = 0,
#endif
};

__attribute__((used, section(".limine_requests_end_marker")))
static volatile uint64_t limine_requests_end[] = LIMINE_REQUESTS_END_MARKER;

static struct boot_info boot_info;

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
    if (!limine_modules.response || limine_modules.response->module_count == 0) {
        return NULL;
    }
    for (uint64_t i = 0; i < limine_modules.response->module_count; i++) {
        struct limine_file *mod = limine_modules.response->modules[i];
        if (!mod) {
            continue;
        }
        if (mod->string && strcmp(mod->string, "dtb") == 0) {
            return mod->address;
        }
        if (limine_path_has_suffix(mod->path, ".dtb") ||
            limine_path_has_suffix(mod->string, ".dtb")) {
            return mod->address;
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
    case LIMINE_MEMMAP_ACPI_TABLES:
        return BOOT_MEM_ACPI_RECLAIM;
    default:
        return BOOT_MEM_RESERVED;
    }
}

static void boot_init_limine(void) {
    memset(&boot_info, 0, sizeof(boot_info));

    if (!LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision)) {
        panic("Limine base revision unsupported");
    }

    if (limine_bootloader_info.response) {
        boot_info.bootloader_name =
            (const char *)(uintptr_t)limine_bootloader_info.response->name;
        boot_info.bootloader_version =
            (const char *)(uintptr_t)limine_bootloader_info.response->version;
    }

    if (limine_cmdline.response) {
        boot_info.cmdline =
            (const char *)(uintptr_t)limine_cmdline.response->cmdline;
    }

    if (limine_hhdm.response) {
        boot_info.hhdm_offset = limine_hhdm.response->offset;
    }

    if (limine_dtb.response) {
        boot_info.dtb = (void *)(uintptr_t)limine_dtb.response->dtb_ptr;
    }

    if (limine_rsdp.response) {
        boot_info.rsdp = (void *)(uintptr_t)limine_rsdp.response->address;
    }

    if (limine_efi.response) {
        boot_info.efi_system_table =
            (void *)(uintptr_t)limine_efi.response->address;
    }

    if (limine_exec_addr.response) {
        boot_info.kernel_phys_base = limine_exec_addr.response->physical_base;
        boot_info.kernel_virt_base = limine_exec_addr.response->virtual_base;
    }

    if (!boot_info.dtb && boot_info.efi_system_table) {
        boot_info.dtb = efi_find_dtb(boot_info.efi_system_table);
    }
    if (!boot_info.dtb) {
        boot_info.dtb = limine_find_dtb_module();
    }

    if (limine_modules.response && limine_modules.response->module_count) {
        uint64_t count = limine_modules.response->module_count;
        if (count > BOOT_MODULES_MAX)
            count = BOOT_MODULES_MAX;
        boot_info.module_count = (uint32_t)count;
        for (uint64_t i = 0; i < count; i++) {
            struct limine_file *mod = limine_modules.response->modules[i];
            if (!mod)
                continue;
            boot_info.modules[i].path = (const char *)(uintptr_t)mod->path;
            boot_info.modules[i].string =
                (const char *)(uintptr_t)mod->string;
            boot_info.modules[i].addr = (void *)(uintptr_t)mod->address;
            boot_info.modules[i].size = mod->size;
        }
    }

    if (limine_memmap.response) {
        uint64_t min = UINT64_MAX;
        uint64_t max = 0;
        uint64_t count = limine_memmap.response->entry_count;
        if (count > BOOT_MEMMAP_MAX) {
            count = BOOT_MEMMAP_MAX;
        }
        for (uint64_t i = 0; i < count; i++) {
            struct limine_memmap_entry *entry =
                (struct limine_memmap_entry *)(uintptr_t)
                    limine_memmap.response->entries[i];
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
        }
    }

    if (limine_mp.response && limine_mp.response->cpu_count) {
        uint64_t count = limine_mp.response->cpu_count;
        if (count > CONFIG_MAX_CPUS)
            count = CONFIG_MAX_CPUS;
        boot_info.cpu_count = (uint32_t)count;
        boot_info.bsp_cpu_id = 0;
        for (uint64_t i = 0; i < count; i++) {
            struct limine_mp_info *info =
                (struct limine_mp_info *)(uintptr_t)limine_mp.response->cpus[i];
            boot_info.cpus[i].cpu_id = (uint32_t)i;
            boot_info.cpus[i].mp_info = info;
#if defined(ARCH_x86_64)
            boot_info.cpus[i].hw_id = info->lapic_id;
            if (info->lapic_id == limine_mp.response->bsp_lapic_id)
                boot_info.bsp_cpu_id = (uint32_t)i;
#elif defined(ARCH_aarch64)
            boot_info.cpus[i].hw_id = info->mpidr;
            if (info->mpidr == limine_mp.response->bsp_mpidr)
                boot_info.bsp_cpu_id = (uint32_t)i;
#elif defined(ARCH_riscv64)
            boot_info.cpus[i].hw_id = info->hartid;
            if (info->hartid == limine_mp.response->bsp_hartid)
                boot_info.bsp_cpu_id = (uint32_t)i;
#else
            boot_info.cpus[i].hw_id = 0;
#endif
        }
    } else {
        boot_info.cpu_count = 1;
        boot_info.bsp_cpu_id = 0;
    }

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
