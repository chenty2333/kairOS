/**
 * kernel/include/kairos/acpi.h - ACPI core scaffolding
 */

#ifndef _KAIROS_ACPI_H
#define _KAIROS_ACPI_H

#include <kairos/types.h>

/* Arch hook: return RSDP pointer when ACPI is available. */
void *arch_acpi_get_rsdp(void);

int acpi_init(void);
void *acpi_rsdp(void);

#endif
