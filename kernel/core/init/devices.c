/**
 * kernel/core/init/devices.c - Device model initialization
 */

#include <kairos/acpi.h>
#include <kairos/device.h>
#include <kairos/fdt.h>
#include <kairos/firmware.h>
#include <kairos/init.h>
#include <kairos/pci.h>
#include <kairos/platform.h>
#include <kairos/printk.h>
#include <kairos/virtio.h>

/* Drivers */
extern struct driver virtio_mmio_driver;
extern struct virtio_driver virtio_blk_driver;
extern struct virtio_driver virtio_net_driver;

void init_devices(void) {
    const void *dtb = init_boot_dtb();

    printk("\n=== Phase 5: Device Discovery ===\n");
    platform_bus_init();
    pci_bus_init();
    bus_register(&virtio_bus_type);

    driver_register(&virtio_mmio_driver);
    virtio_register_driver(&virtio_blk_driver);
    virtio_register_driver(&virtio_net_driver);

    fw_init();
    acpi_init();
    if (dtb) {
        fdt_scan_devices(dtb);
    }
    platform_bus_enumerate();
    pci_enumerate();
}
