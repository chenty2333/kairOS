/**
 * kernel/core/init/devices.c - Device model initialization
 */

#include <kairos/acpi.h>
#include <kairos/boot.h>
#include <kairos/config.h>
#include <kairos/device.h>
#include <kairos/fdt.h>
#include <kairos/firmware.h>
#include <kairos/init.h>
#include <kairos/iommu.h>
#include <kairos/mm.h>
#include <kairos/pci.h>
#include <kairos/platform.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/virtio.h>

/* Drivers */
extern struct driver virtio_mmio_driver;
extern struct pci_driver virtio_pci_driver;
extern struct virtio_driver virtio_blk_driver;
extern struct virtio_driver virtio_net_driver;
#if CONFIG_VIRTIO_IOMMU
extern struct virtio_driver virtio_iommu_driver;
#endif
#if CONFIG_DRM_LITE
extern struct driver drm_lite_driver;
#endif

static void register_limine_framebuffers(void) {
    const struct boot_info *bi = boot_info_get();
    if (!bi || bi->framebuffer_count == 0) {
        pr_warn("fw: no limine framebuffer reported\n");
        return;
    }

    uint32_t count = bi->framebuffer_count;
    for (uint32_t i = 0; i < count; i++) {
        const struct boot_framebuffer *fb = &bi->framebuffers[i];
        if (!fb->phys || !fb->size)
            continue;

        struct fw_device_desc *desc = kzalloc(sizeof(*desc));
        if (!desc) {
            pr_warn("fw: failed to allocate limine framebuffer desc\n");
            return;
        }

        snprintf(desc->name, sizeof(desc->name), "limine-fb%u", i);
        snprintf(desc->compatible, sizeof(desc->compatible),
                 "limine,framebuffer");
        desc->fw_data = (void *)fb;
        fw_register_desc(desc);
        pr_info("fw: limine fb%u %ux%u pitch=%u bpp=%u phys=%p\n",
                i, fb->width, fb->height, fb->pitch, fb->bpp,
                (void *)(uintptr_t)fb->phys);
    }
}

void init_devices(void) {
    const void *dtb = init_boot_dtb();

    printk("\n=== Phase 5: Device Discovery ===\n");
    platform_bus_init();
    iommu_init();
    pci_bus_init();
    bus_register(&virtio_bus_type);

    driver_register(&virtio_mmio_driver);
    pci_register_driver(&virtio_pci_driver);
    virtio_register_driver(&virtio_blk_driver);
    virtio_register_driver(&virtio_net_driver);
#if CONFIG_VIRTIO_IOMMU
    virtio_register_driver(&virtio_iommu_driver);
#endif
#if CONFIG_DRM_LITE
    driver_register(&drm_lite_driver);
#endif

    fw_init();
    register_limine_framebuffers();
    acpi_init();
    if (dtb) {
        fdt_scan_devices(dtb);
    }
    platform_bus_enumerate();
    int ret = pci_enumerate();
    if (ret < 0)
        pr_warn("pci: enumerate skipped (ret=%d)\n", ret);
}
