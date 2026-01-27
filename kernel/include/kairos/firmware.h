/**
 * kernel/include/kairos/firmware.h - Firmware device descriptions
 */

#ifndef _KAIROS_FIRMWARE_H
#define _KAIROS_FIRMWARE_H

#include <kairos/device.h>
#include <kairos/list.h>
#include <kairos/types.h>

struct fw_device_desc {
    char name[32];
    char compatible[64];
    struct resource *resources;
    size_t num_resources;
    void *fw_data;
    bool enumerated;
    struct list_head list;
};

void fw_init(void);
int fw_register_desc(struct fw_device_desc *desc);
int fw_for_each_desc(int (*fn)(struct fw_device_desc *desc, void *arg),
                     void *arg);

#endif
