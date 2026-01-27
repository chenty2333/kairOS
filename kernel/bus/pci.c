/**
 * kernel/bus/pci.c - PCI core scaffolding
 */

#include <kairos/pci.h>
#include <kairos/printk.h>

__attribute__((weak)) int arch_pci_host_init(struct pci_host *host) {
    (void)host;
    return -ENODEV;
}

__attribute__((weak)) int arch_pci_enumerate(struct pci_host *host) {
    (void)host;
    return -ENOSYS;
}

static int pci_bus_match(struct device *dev, struct driver *drv) {
    struct pci_device *pdev = to_pci_device(dev);
    struct pci_driver *pdrv = to_pci_driver(drv);

    bool vendor_ok =
        (pdrv->vendor_id == PCI_ANY_ID || pdrv->vendor_id == pdev->vendor_id);
    bool device_ok =
        (pdrv->device_id == PCI_ANY_ID || pdrv->device_id == pdev->device_id);
    return vendor_ok && device_ok;
}

static int pci_drv_probe(struct device *dev) {
    struct pci_device *pdev = to_pci_device(dev);
    struct pci_driver *pdrv = to_pci_driver(dev->driver);
    if (!pdrv->probe)
        return -EINVAL;
    return pdrv->probe(pdev);
}

struct bus_type pci_bus_type = {
    .name = "pci",
    .match = pci_bus_match,
};

int pci_bus_init(void) {
    int ret = bus_register(&pci_bus_type);
    if (ret == 0)
        pr_info("pci: core initialized\n");
    return ret;
}

int pci_register_driver(struct pci_driver *pdrv) {
    if (!pdrv)
        return -EINVAL;
    pdrv->drv.bus = &pci_bus_type;
    pdrv->drv.probe = pci_drv_probe;
    return driver_register(&pdrv->drv);
}

int pci_enumerate(void) {
    struct pci_host host = {0};
    int ret = arch_pci_host_init(&host);
    if (ret < 0)
        return ret;
    return arch_pci_enumerate(&host);
}

