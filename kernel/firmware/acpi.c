/**
 * kernel/firmware/acpi.c - ACPI core scaffolding
 */

#include <kairos/acpi.h>
#include <kairos/printk.h>

static void *acpi_rsdp_ptr;
static bool acpi_available;

__attribute__((weak)) void *arch_acpi_get_rsdp(void) {
    return NULL;
}

static int acpi_probe_rsdp(void) {
    acpi_rsdp_ptr = arch_acpi_get_rsdp();
    if (!acpi_rsdp_ptr)
        return -ENODEV;
    return 0;
}

int acpi_init(void) {
    int ret = acpi_probe_rsdp();
    if (ret)
        return ret;

    acpi_available = true;
    pr_info("ACPI: RSDP at %p\n", acpi_rsdp_ptr);
    return 0;
}

void *acpi_rsdp(void) {
    return acpi_rsdp_ptr;
}
