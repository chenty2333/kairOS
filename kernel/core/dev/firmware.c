/**
 * kernel/core/dev/firmware.c - Firmware device description registry
 */

#include <kairos/firmware.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>

static LIST_HEAD(fw_desc_list);
static spinlock_t fw_lock = SPINLOCK_INIT;

void fw_init(void) {
    spin_lock(&fw_lock);
    INIT_LIST_HEAD(&fw_desc_list);
    spin_unlock(&fw_lock);
}

int fw_register_desc(struct fw_device_desc *desc) {
    if (!desc)
        return -EINVAL;
    spin_lock(&fw_lock);
    list_add_tail(&desc->list, &fw_desc_list);
    spin_unlock(&fw_lock);
    pr_info("fw: registered %s (%s)\n", desc->name, desc->compatible);
    return 0;
}

int fw_for_each_desc(int (*fn)(struct fw_device_desc *desc, void *arg),
                     void *arg) {
    if (!fn)
        return -EINVAL;
    spin_lock(&fw_lock);
    struct fw_device_desc *desc, *tmp;
    list_for_each_entry_safe(desc, tmp, &fw_desc_list, list) {
        spin_unlock(&fw_lock);
        int ret = fn(desc, arg);
        if (ret)
            return ret;
        spin_lock(&fw_lock);
    }
    spin_unlock(&fw_lock);
    return 0;
}
