/**
 * kernel/drivers/input/input_core.c - Input Device Core
 *
 * Generic input device framework implementation.
 */

#include <kairos/input.h>
#include <kairos/arch.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/types.h>

/* Global input device list */
static LIST_HEAD(input_dev_list);
static spinlock_t input_dev_lock = SPINLOCK_INIT;
static int input_dev_count = 0;

/* Forward declaration for evdev integration */
extern void evdev_notify_event(struct input_dev *dev, struct input_event *event);
extern int evdev_register_device(struct input_dev *dev);
extern void evdev_unregister_device(struct input_dev *dev);

struct input_dev *input_dev_alloc(void) {
    struct input_dev *dev = kzalloc(sizeof(*dev));
    if (!dev)
        return NULL;

    spin_init(&dev->lock);
    INIT_LIST_HEAD(&dev->client_list);
    INIT_LIST_HEAD(&dev->node);

    return dev;
}

void input_dev_free(struct input_dev *dev) {
    if (!dev)
        return;
    kfree(dev);
}

int input_dev_register(struct input_dev *dev) {
    if (!dev)
        return -EINVAL;

    bool irq_state = arch_irq_save();
    spin_lock(&input_dev_lock);

    list_add_tail(&dev->node, &input_dev_list);
    input_dev_count++;

    spin_unlock(&input_dev_lock);
    arch_irq_restore(irq_state);

    pr_info("input: registered device '%s' (bus=0x%x vendor=0x%x product=0x%x)\n",
            dev->name, dev->id_bus, dev->id_vendor, dev->id_product);

    int ret = evdev_register_device(dev);
    if (ret < 0) {
        pr_warn("input: evdev registration failed for '%s' (err=%d)\n",
                dev->name, ret);
        irq_state = arch_irq_save();
        spin_lock(&input_dev_lock);
        list_del(&dev->node);
        input_dev_count--;
        spin_unlock(&input_dev_lock);
        arch_irq_restore(irq_state);
        return ret;
    }

    return 0;
}

void input_dev_unregister(struct input_dev *dev) {
    if (!dev)
        return;

    evdev_unregister_device(dev);

    bool irq_state = arch_irq_save();
    spin_lock(&input_dev_lock);

    list_del(&dev->node);
    input_dev_count--;

    spin_unlock(&input_dev_lock);
    arch_irq_restore(irq_state);

    pr_info("input: unregistered device '%s'\n", dev->name);
}

struct input_dev *input_dev_get_by_index(int index) {
    if (index < 0)
        return NULL;

    bool irq_state = arch_irq_save();
    spin_lock(&input_dev_lock);

    int i = 0;
    struct input_dev *dev;
    list_for_each_entry(dev, &input_dev_list, node) {
        if (i == index) {
            spin_unlock(&input_dev_lock);
            arch_irq_restore(irq_state);
            return dev;
        }
        i++;
    }

    spin_unlock(&input_dev_lock);
    arch_irq_restore(irq_state);
    return NULL;
}

int input_dev_get_count(void) {
    bool irq_state = arch_irq_save();
    spin_lock(&input_dev_lock);
    int count = input_dev_count;
    spin_unlock(&input_dev_lock);
    arch_irq_restore(irq_state);
    return count;
}

static void input_report_event(struct input_dev *dev, uint16_t type,
                                uint16_t code, int32_t value) {
    if (!dev)
        return;

    struct input_event event;
    uint64_t ticks = arch_timer_ticks();
    uint64_t freq = arch_timer_freq();

    event.time_sec = ticks / freq;
    event.time_usec = ((ticks % freq) * 1000000ULL) / freq;
    event.type = type;
    event.code = code;
    event.value = value;

    evdev_notify_event(dev, &event);
}

void input_report_key(struct input_dev *dev, uint16_t code, int32_t value) {
    input_report_event(dev, EV_KEY, code, value);
}

void input_report_rel(struct input_dev *dev, uint16_t code, int32_t value) {
    input_report_event(dev, EV_REL, code, value);
}

void input_report_abs(struct input_dev *dev, uint16_t code, int32_t value) {
    input_report_event(dev, EV_ABS, code, value);
}

void input_sync(struct input_dev *dev) {
    input_report_event(dev, EV_SYN, SYN_REPORT, 0);
}
