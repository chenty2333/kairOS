/**
 * kernel/include/kairos/platform.h - Platform Bus
 *
 * The platform bus is for memory-mapped devices found via FDT or ACPI.
 */

#ifndef _KAIROS_PLATFORM_H
#define _KAIROS_PLATFORM_H

#include <kairos/device.h>
#include <kairos/types.h>

extern struct bus_type platform_bus_type;

/**
 * struct platform_device_info - Platform device specific data
 * @base: MMIO base address
 * @size: MMIO size
 * @irq: Interrupt number
 * @compatible: Compatible string (e.g., "virtio,mmio")
 */
struct platform_device_info {
    paddr_t base;
    size_t size;
    int irq;
    char compatible[64];
};

int platform_bus_init(void);

/* Helpers to verify if a device is on the platform bus */
static inline int is_platform_device(struct device *dev) {
    return dev->bus == &platform_bus_type;
}

#endif