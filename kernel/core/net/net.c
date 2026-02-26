/**
 * kernel/core/net/net.c - Minimal network device registry
 */

#include <kairos/net.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>

static LIST_HEAD(netdev_list);
static spinlock_t netdev_lock = SPINLOCK_INIT;
static bool net_ready;

void net_init(void) {
    if (net_ready)
        return;
    INIT_LIST_HEAD(&netdev_list);
    spin_init(&netdev_lock);
    net_ready = true;
    pr_info("net: initialized\n");
}

int netdev_register(struct netdev *dev) {
    if (!dev || !dev->ops || !dev->ops->xmit)
        return -EINVAL;
    if (!net_ready)
        net_init();

    spin_lock(&netdev_lock);
    struct netdev *existing;
    list_for_each_entry(existing, &netdev_list, list) {
        if (strcmp(existing->name, dev->name) == 0) {
            spin_unlock(&netdev_lock);
            pr_warn("net: %s already registered\n", dev->name);
            return -EEXIST;
        }
    }
    INIT_LIST_HEAD(&dev->list);
    list_add_tail(&dev->list, &netdev_list);
    spin_unlock(&netdev_lock);

    pr_debug("net: registered %s\n", dev->name);
    return 0;
}

int netdev_unregister(struct netdev *dev) {
    if (!dev || !net_ready)
        return -EINVAL;
    spin_lock(&netdev_lock);
    list_del(&dev->list);
    spin_unlock(&netdev_lock);
    pr_debug("net: unregistered %s\n", dev->name);
    return 0;
}

struct netdev *netdev_first(void) {
    struct netdev *dev = NULL;
    if (!net_ready)
        return NULL;
    spin_lock(&netdev_lock);
    if (!list_empty(&netdev_list))
        dev = list_first_entry(&netdev_list, struct netdev, list);
    spin_unlock(&netdev_lock);
    return dev;
}
