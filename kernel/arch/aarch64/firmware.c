/**
 * kernel/arch/aarch64/firmware.c - Firmware helpers
 */

#include <kairos/boot.h>

void *arch_acpi_get_rsdp(void) {
    const struct boot_info *bi = boot_info_get();
    return bi ? bi->rsdp : NULL;
}
