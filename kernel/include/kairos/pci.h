/**
 * kernel/include/kairos/pci.h - PCI core with ECAM support
 */

#ifndef _KAIROS_PCI_H
#define _KAIROS_PCI_H

#include <kairos/device.h>
#include <kairos/types.h>

#define PCI_ANY_ID 0xffff

/* PCI configuration register offsets */
#define PCI_VENDOR_ID       0x00
#define PCI_DEVICE_ID       0x02
#define PCI_COMMAND         0x04
#define PCI_STATUS          0x06
#define PCI_CLASS_REVISION  0x08
#define PCI_CACHE_LINE_SIZE 0x0c
#define PCI_HEADER_TYPE     0x0e
#define PCI_BAR0            0x10
#define PCI_BAR1            0x14
#define PCI_BAR2            0x18
#define PCI_BAR3            0x1c
#define PCI_BAR4            0x20
#define PCI_BAR5            0x24
#define PCI_IRQ_LINE        0x3c
#define PCI_IRQ_PIN         0x3d

/* PCI command register bits */
#define PCI_COMMAND_IO          0x0001
#define PCI_COMMAND_MEMORY      0x0002
#define PCI_COMMAND_MASTER      0x0004
#define PCI_COMMAND_INTX_DISABLE 0x0400

/* Header type */
#define PCI_HEADER_TYPE_MASK    0x7f
#define PCI_HEADER_MULTI_FUNC   0x80

/* BAR decoding */
#define PCI_BAR_IO              0x01
#define PCI_BAR_MEM_TYPE_MASK   0x06
#define PCI_BAR_MEM_TYPE_32     0x00
#define PCI_BAR_MEM_TYPE_64     0x04
#define PCI_BAR_MEM_PREFETCH    0x08

#define PCI_MAX_BAR 6

struct pci_host_ops {
    uint32_t (*read_config)(uint8_t bus, uint8_t slot, uint8_t func,
                            uint16_t offset, uint8_t size);
    void (*write_config)(uint8_t bus, uint8_t slot, uint8_t func,
                         uint16_t offset, uint32_t value, uint8_t size);
};

struct pci_host {
    struct pci_host_ops *ops;
    void *priv;
    void *ecam_base;
    uint8_t bus_start;
    uint8_t bus_end;
    uint32_t irq_base;
};

struct pci_device {
    struct device dev;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint32_t class_code;
    uint8_t irq_pin;
    uint8_t irq_line;
    uint64_t bar[PCI_MAX_BAR];
    uint64_t bar_size[PCI_MAX_BAR];
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

/* ECAM address calculation: bus << 20 | slot << 15 | func << 12 | offset */
static inline volatile void *pci_ecam_addr(void *ecam_base,
                                            uint8_t bus, uint8_t slot,
                                            uint8_t func, uint16_t offset)
{
    return (volatile void *)((char *)ecam_base +
           (((uint32_t)bus << 20) |
            ((uint32_t)slot << 15) |
            ((uint32_t)func << 12) |
            offset));
}

extern struct bus_type pci_bus_type;

/* Core APIs */
int pci_bus_init(void);
int pci_enumerate(void);
int pci_register_driver(struct pci_driver *pdrv);

/* Config space access */
uint8_t  pci_read_config_8(struct pci_host *host, uint8_t bus,
                            uint8_t slot, uint8_t func, uint16_t off);
uint16_t pci_read_config_16(struct pci_host *host, uint8_t bus,
                             uint8_t slot, uint8_t func, uint16_t off);
uint32_t pci_read_config_32(struct pci_host *host, uint8_t bus,
                             uint8_t slot, uint8_t func, uint16_t off);
void pci_write_config_8(struct pci_host *host, uint8_t bus,
                         uint8_t slot, uint8_t func, uint16_t off, uint8_t val);
void pci_write_config_16(struct pci_host *host, uint8_t bus,
                          uint8_t slot, uint8_t func, uint16_t off, uint16_t val);
void pci_write_config_32(struct pci_host *host, uint8_t bus,
                          uint8_t slot, uint8_t func, uint16_t off, uint32_t val);

/* Bus scanning and device control */
int pci_scan_bus(struct pci_host *host);
void pci_set_master(struct pci_host *host, struct pci_device *pdev);

/* Arch hook */
int arch_pci_host_init(struct pci_host *host);

#endif
