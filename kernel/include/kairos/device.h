/**
 * kernel/include/kairos/device.h - The Device Model
 *
 * Core abstractions for device drivers and buses.
 */

#ifndef _KAIROS_DEVICE_H
#define _KAIROS_DEVICE_H

#include <kairos/list.h>
#include <kairos/types.h>

struct device;
struct driver;
struct sysfs_node;
struct dma_ops;
struct iommu_domain;

/* 
 * Bus Type: Describes how to match devices on this bus.
 * e.g., "platform", "pci", "usb"
 */
struct bus_type {
    const char *name;
    int (*match)(struct device *dev, struct driver *drv);
    struct list_head list;      /* Global bus list node */
};

/*
 * Device: A physical or virtual device instance.
 */
struct device {
    char name[32];              /* Unique name, e.g., "virtio-mmio.0" */
    char compatible[64];        /* Firmware compatible string */
    struct bus_type *bus;       /* Bus this device sits on */
    struct driver *driver;      /* Bound driver (NULL if unbound) */
    void *platform_data;        /* Bus-specific data (e.g., MMIO addr, IRQ) */
    struct resource *resources; /* Resource array */
    size_t num_resources;
    const struct dma_ops *dma_ops; /* DMA backend (NULL => direct mapping) */
    struct iommu_domain *iommu_domain; /* Attached IOMMU domain */
    bool iommu_domain_owned;      /* Destroy domain on device detach */
    void *driver_data;          /* Driver private data */
    struct sysfs_node *sysfs_node; /* sysfs directory for this device */
    struct list_head list;      /* Global device list node */
    struct list_head bus_list;  /* Bus-specific device list node */
};

/*
 * Driver: Code that controls a device.
 */
struct driver {
    const char *name;           /* Driver name, e.g., "virtio-blk" */
    const char *compatible;     /* FDT compatible string, e.g., "virtio,mmio" */
    struct bus_type *bus;       /* Bus this driver handles */
    int (*probe)(struct device *dev);
    void (*remove)(struct device *dev);
    struct list_head list;      /* Global driver list node */
};

/* Core APIs */
int bus_register(struct bus_type *bus);
void bus_unregister(struct bus_type *bus);

int device_register(struct device *dev);
void device_unregister(struct device *dev);

int driver_register(struct driver *drv);
void driver_unregister(struct driver *drv);

struct resource {
    uint64_t start;
    uint64_t end;
    uint64_t flags;
};
#define IORESOURCE_MEM 0x1
#define IORESOURCE_IRQ 0x2

const struct resource *device_get_resource(struct device *dev, uint64_t type,
                                           size_t index);
void dev_set_drvdata(struct device *dev, void *data);
void *dev_get_drvdata(struct device *dev);
void *dev_ioremap_resource(struct device *dev, size_t index);

#endif
