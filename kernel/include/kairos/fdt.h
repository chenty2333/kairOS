/**
 * kernel/include/kairos/fdt.h - Flattened Device Tree
 */

#ifndef _KAIROS_FDT_H
#define _KAIROS_FDT_H

#include <kairos/types.h>

int fdt_parse(const void *fdt);
int fdt_scan_devices(const void *fdt);

const char *fdt_root_compatible(void);

int fdt_get_memory(int index, paddr_t *base, size_t *size);
int fdt_memory_count(void);
int fdt_get_reserved(int index, paddr_t *base, size_t *size);
int fdt_reserved_count(void);
int fdt_get_cpus(const void *fdt, uint64_t *cpu_ids, uint32_t max_ids,
                 uint32_t *out_count);
int fdt_get_psci_method(const void *fdt, char *method, size_t method_len);

#endif
