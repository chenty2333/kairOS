/**
 * kernel/core/dev/device.c - Device Model Core
 */

#include <kairos/device.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>

static LIST_HEAD(bus_list);
static LIST_HEAD(device_list);
static LIST_HEAD(driver_list);

/* Simple linear match and probe */
static int bus_match_probe(struct device *dev, struct driver *drv) {
    if (dev->bus != drv->bus) return 0;
    
    /* If bus provides match method, use it; otherwise match by name */
    if (dev->bus && dev->bus->match) {
        if (!dev->bus->match(dev, drv)) return 0;
    } else {
        /* Default match: exact name equality */
        if (strcmp(dev->name, drv->name) != 0) return 0;
    }

    /* Match found, try probe */
    // pr_info("device: probing %s with %s\n", dev->name, drv->name);
    dev->driver = drv;
    int ret = drv->probe(dev);
    if (ret == 0) {
        return 1;
    }
    dev->driver = NULL;
    return 0;
}

int bus_register(struct bus_type *bus) {
    if (!bus || !bus->name) return -EINVAL;
    list_add_tail(&bus->list, &bus_list);
    return 0;
}

void bus_unregister(struct bus_type *bus) {
    if (bus) list_del(&bus->list);
}

int device_register(struct device *dev) {
    if (!dev) return -EINVAL;
    
    list_add_tail(&dev->list, &device_list);
    
    /* Try to attach to an existing driver */
    struct driver *drv;
    list_for_each_entry(drv, &driver_list, list) {
        if (!dev->driver && bus_match_probe(dev, drv)) break;
    }
    
    return 0;
}

void device_unregister(struct device *dev) {
    if (!dev) return;
    if (dev->driver && dev->driver->remove) {
        dev->driver->remove(dev);
    }
    list_del(&dev->list);
}

int driver_register(struct driver *drv) {
    if (!drv || !drv->probe) return -EINVAL;
    
    list_add_tail(&drv->list, &driver_list);
    
    /* Try to attach to existing devices */
    struct device *dev;
    list_for_each_entry(dev, &device_list, list) {
        if (!dev->driver) bus_match_probe(dev, drv);
    }
    
    return 0;
}

void driver_unregister(struct driver *drv) {
    if (drv) list_del(&drv->list);
    /* TODO: Detach from devices */
}

const struct resource *device_get_resource(struct device *dev, uint64_t type,
                                           size_t index) {
    if (!dev || !dev->resources || dev->num_resources == 0)
        return NULL;

    size_t seen = 0;
    for (size_t i = 0; i < dev->num_resources; i++) {
        const struct resource *res = &dev->resources[i];
        if (!(res->flags & type))
            continue;
        if (seen == index)
            return res;
        seen++;
    }
    return NULL;
}

void dev_set_drvdata(struct device *dev, void *data) {
    if (dev)
        dev->driver_data = data;
}

void *dev_get_drvdata(struct device *dev) {
    return dev ? dev->driver_data : NULL;
}

void *dev_ioremap_resource(struct device *dev, size_t index) {
    const struct resource *res = device_get_resource(dev, IORESOURCE_MEM, index);
    if (!res || res->end < res->start)
        return NULL;
    size_t size = (size_t)(res->end - res->start + 1);
    return ioremap((paddr_t)res->start, size);
}
