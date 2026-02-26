/**
 * kernel/bus/platform.c - Platform Bus Implementation
 */

#include <kairos/platform.h>
#include <kairos/platform_irq.h>
#include <kairos/arch.h>
#include <kairos/firmware.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>

/*
 * platform_match - Match platform device to driver
 * @dev: Device to match
 * @drv: Driver to match
 *
 * For now, we just match by name. 
 * Future: Match 'compatible' string from FDT.
 */
static int platform_match(struct device *dev, struct driver *drv) {
    /* Simple name match */
    if (strcmp(dev->name, drv->name) == 0) return 1;
    
    /* Compatible string match */
    if (drv->compatible && dev->compatible[0]) {
        if (strcmp(dev->compatible, drv->compatible) == 0)
            return 1;
    }
    if (drv->compatible && dev->platform_data) {
        struct platform_device_info *info = dev->platform_data;
        if (strcmp(info->compatible, drv->compatible) == 0) {
            return 1;
        }
    }

    return 0;
}

struct bus_type platform_bus_type = {
    .name = "platform",
    .match = platform_match,
};

int platform_bus_init(void) {
    pr_info("platform: initialized\n");
    return bus_register(&platform_bus_type);
}

static int platform_register_desc(struct fw_device_desc *desc, void *arg) {
    (void)arg;
    if (!desc || desc->enumerated)
        return 0;

    struct device *dev = kzalloc(sizeof(*dev));
    if (!dev)
        return -ENOMEM;

    strncpy(dev->name, desc->name, sizeof(dev->name) - 1);
    strncpy(dev->compatible, desc->compatible, sizeof(dev->compatible) - 1);
    dev->bus = &platform_bus_type;
    dev->platform_data = desc->fw_data;
    dev->resources = desc->resources;
    dev->num_resources = desc->num_resources;

    int ret = device_register(dev);
    if (ret < 0) {
        kfree(dev);
        return ret;
    }

    desc->enumerated = true;
    return 0;
}

int platform_bus_enumerate(void) {
    return fw_for_each_desc(platform_register_desc, NULL);
}

int platform_device_get_irq(const struct device *dev, size_t index) {
    if (!dev || !is_platform_device((struct device *)dev))
        return -EINVAL;

    const struct resource *res =
        device_get_resource((struct device *)dev, IORESOURCE_IRQ, index);
    if (!res)
        return -ENOENT;
    if (res->start > 0x7fffffffULL)
        return -ERANGE;

    int irq = (int)res->start;
    if (irq <= 0)
        return -EINVAL;
    return irq;
}

int platform_device_request_irq(struct device *dev, size_t index,
                                void (*handler)(void *), void *arg,
                                uint32_t flags)
{
    int irq = platform_device_get_irq(dev, index);
    if (irq < 0)
        return irq;
    return arch_request_irq(irq, handler, arg, flags);
}

int platform_device_free_irq(struct device *dev, size_t index,
                             void (*handler)(void *), void *arg)
{
    int irq = platform_device_get_irq(dev, index);
    if (irq < 0)
        return irq;
    return arch_free_irq(irq, handler, arg);
}

int platform_device_free_irq_sync(struct device *dev, size_t index,
                                  void (*handler)(void *), void *arg)
{
    int irq = platform_device_get_irq(dev, index);
    if (irq < 0)
        return irq;
    return arch_free_irq_sync(irq, handler, arg);
}
