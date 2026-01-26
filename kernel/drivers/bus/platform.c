/**
 * kernel/drivers/bus/platform.c - Platform Bus Implementation
 */

#include <kairos/platform.h>
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

