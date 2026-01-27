/**
 * kernel/include/kairos/pci.h - PCI core scaffolding
 */

#ifndef _KAIROS_PCI_H
#define _KAIROS_PCI_H

#include <kairos/device.h>
#include <kairos/types.h>

#define PCI_ANY_ID 0xffff

struct pci_host_ops {
    uint32_t (*read_config)(uint8_t bus, uint8_t slot, uint8_t func,
                            uint16_t offset, uint8_t size);
    void (*write_config)(uint8_t bus, uint8_t slot, uint8_t func,
                         uint16_t offset, uint32_t value, uint8_t size);
};

struct pci_host {
    struct pci_host_ops *ops;
    void *priv;
};

struct pci_device {
    struct device dev;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint32_t class_code;
};

#define to_pci_device(d) container_of(d, struct pci_device, dev)

struct pci_driver {
    struct driver drv;
    uint16_t vendor_id;
    uint16_t device_id;
    int (*probe)(struct pci_device *pdev);
    void (*remove)(struct pci_device *pdev);
};

#define to_pci_driver(d) container_of(d, struct pci_driver, drv)

extern struct bus_type pci_bus_type;

int pci_bus_init(void);
int pci_enumerate(void);
int pci_register_driver(struct pci_driver *pdrv);

/* Arch hooks */
int arch_pci_host_init(struct pci_host *host);
int arch_pci_enumerate(struct pci_host *host);

#endif
