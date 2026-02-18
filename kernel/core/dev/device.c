/**
 * kernel/core/dev/device.c - Device Model Core
 */

#include <kairos/device.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sysfs.h>

static LIST_HEAD(bus_list);
static LIST_HEAD(device_list);
static LIST_HEAD(driver_list);
static spinlock_t device_model_lock = SPINLOCK_INIT;

static int bus_match_probe_locked(struct device *dev, struct driver *drv);

static void device_try_bind(struct device *dev) {
    struct driver *drv;
    list_for_each_entry(drv, &driver_list, list) {
        if (!dev->driver && bus_match_probe_locked(dev, drv))
            break;
    }
}

/* Simple linear match and probe */
static int bus_match_probe_locked(struct device *dev, struct driver *drv) {
    if (dev->bus != drv->bus) return 0;
    
    /* If bus provides match method, use it; otherwise match by name */
    if (dev->bus && dev->bus->match) {
        if (!dev->bus->match(dev, drv)) return 0;
    } else {
        /* Default match: exact name equality */
        if (strcmp(dev->name, drv->name) != 0) return 0;
    }

    /* Match found; drop the model lock to avoid probe re-entrancy deadlocks. */
    // pr_info("device: probing %s with %s\n", dev->name, drv->name);
    dev->driver = drv;
    spin_unlock(&device_model_lock);
    int ret = drv->probe(dev);
    spin_lock(&device_model_lock);
    if (ret == 0)
        return 1;
    dev->driver = NULL;
    return 0;
}

int bus_register(struct bus_type *bus) {
    if (!bus || !bus->name) return -EINVAL;
    spin_lock(&device_model_lock);
    list_add_tail(&bus->list, &bus_list);
    spin_unlock(&device_model_lock);
    return 0;
}

void bus_unregister(struct bus_type *bus) {
    if (!bus)
        return;
    spin_lock(&device_model_lock);
    list_del(&bus->list);
    spin_unlock(&device_model_lock);
}

int device_register(struct device *dev) {
    if (!dev) return -EINVAL;

    spin_lock(&device_model_lock);
    list_add_tail(&dev->list, &device_list);

    /* Try to attach to an existing driver */
    device_try_bind(dev);
    spin_unlock(&device_model_lock);

    /* Create sysfs node under /sys/devices/ */
    struct sysfs_node *devs = sysfs_devices_dir();
    if (devs) {
        dev->sysfs_node = sysfs_mkdir(devs, dev->name);
        if (!dev->sysfs_node)
            pr_warn("device: sysfs mkdir failed for %s\n", dev->name);
    }

    return 0;
}

void device_unregister(struct device *dev) {
    if (!dev) return;
    spin_lock(&device_model_lock);
    if (dev->driver && dev->driver->remove) {
        dev->driver->remove(dev);
    }
    list_del(&dev->list);
    dev->driver = NULL;
    spin_unlock(&device_model_lock);

    /* Remove sysfs node */
    if (dev->sysfs_node) {
        sysfs_rmdir(dev->sysfs_node);
        dev->sysfs_node = NULL;
    }
}

int driver_register(struct driver *drv) {
    if (!drv || !drv->probe) return -EINVAL;
    
    spin_lock(&device_model_lock);
    list_add_tail(&drv->list, &driver_list);
    
    /* Try to attach to existing devices */
    struct device *dev;
    list_for_each_entry(dev, &device_list, list) {
        if (!dev->driver)
            bus_match_probe_locked(dev, drv);
    }
    spin_unlock(&device_model_lock);
    
    return 0;
}

void driver_unregister(struct driver *drv) {
    if (!drv)
        return;
    spin_lock(&device_model_lock);
    struct device *dev;
    list_for_each_entry(dev, &device_list, list) {
        if (dev->driver == drv) {
            if (drv->remove) {
                spin_unlock(&device_model_lock);
                drv->remove(dev);
                spin_lock(&device_model_lock);
            }
            dev->driver = NULL;
        }
    }
    list_del(&drv->list);
    spin_unlock(&device_model_lock);
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
