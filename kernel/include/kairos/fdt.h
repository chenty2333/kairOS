/**
 * kernel/include/kairos/fdt.h - Flattened Device Tree
 */

#ifndef _KAIROS_FDT_H
#define _KAIROS_FDT_H

#include <kairos/types.h>

int fdt_parse(void *fdt);
int fdt_scan_devices(void *fdt);

int fdt_get_memory(int index, paddr_t *base, size_t *size);
int fdt_memory_count(void);
int fdt_get_reserved(int index, paddr_t *base, size_t *size);
int fdt_reserved_count(void);

#endif
