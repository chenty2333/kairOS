/**
 * kernel/core/dev/device.c - Device Model Core
 */

#include <kairos/device.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/iommu.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sysfs.h>

static LIST_HEAD(bus_list);
static LIST_HEAD(device_list);
static LIST_HEAD(driver_list);
static spinlock_t device_model_lock = SPINLOCK_INIT;

enum device_sysfs_control_attr {
    DEVICE_SYSFS_ATTR_DRIVER = 0,
    DEVICE_SYSFS_ATTR_BIND,
    DEVICE_SYSFS_ATTR_UNBIND,
    DEVICE_SYSFS_ATTR_RESCAN,
    DEVICE_SYSFS_ATTR_CONTROL_POLICY,
    DEVICE_SYSFS_ATTR_CONTROL_STATS,
    DEVICE_SYSFS_ATTR_COUNT,
};

enum device_sysfs_control_op {
    DEVICE_SYSFS_OP_NONE = 0,
    DEVICE_SYSFS_OP_BIND,
    DEVICE_SYSFS_OP_UNBIND,
    DEVICE_SYSFS_OP_RESCAN,
};

struct device_sysfs_controls {
    struct sysfs_attribute attrs[DEVICE_SYSFS_ATTR_COUNT];
    struct sysfs_node *nodes[DEVICE_SYSFS_ATTR_COUNT];
    uint64_t ops_total;
    uint64_t ops_fail;
    uint64_t bind_ok;
    uint64_t bind_fail;
    uint64_t unbind_ok;
    uint64_t unbind_fail;
    uint64_t rescan_ok;
    uint64_t rescan_fail;
    uint32_t last_op;
    int32_t last_ret;
};

static int bus_match_probe_locked(struct device *dev, struct driver *drv);
static int device_sysfs_init_controls(struct device *dev);
static void device_sysfs_destroy_controls(struct device *dev);

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

static bool device_sysfs_store_has_token(const char *buf, size_t len) {
    if (!buf || len == 0)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = buf[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            return true;
    }
    return false;
}

static const char *device_sysfs_op_name(uint32_t op) {
    switch (op) {
    case DEVICE_SYSFS_OP_BIND:
        return "bind";
    case DEVICE_SYSFS_OP_UNBIND:
        return "unbind";
    case DEVICE_SYSFS_OP_RESCAN:
        return "rescan";
    default:
        return "none";
    }
}

static void device_sysfs_audit_record(struct device *dev,
                                      enum device_sysfs_control_op op,
                                      int ret) {
    if (!dev || !dev->sysfs_controls)
        return;
    struct device_sysfs_controls *controls = dev->sysfs_controls;

    __atomic_add_fetch(&controls->ops_total, 1, __ATOMIC_RELAXED);
    if (ret < 0)
        __atomic_add_fetch(&controls->ops_fail, 1, __ATOMIC_RELAXED);

    switch (op) {
    case DEVICE_SYSFS_OP_BIND:
        if (ret < 0)
            __atomic_add_fetch(&controls->bind_fail, 1, __ATOMIC_RELAXED);
        else
            __atomic_add_fetch(&controls->bind_ok, 1, __ATOMIC_RELAXED);
        break;
    case DEVICE_SYSFS_OP_UNBIND:
        if (ret < 0)
            __atomic_add_fetch(&controls->unbind_fail, 1, __ATOMIC_RELAXED);
        else
            __atomic_add_fetch(&controls->unbind_ok, 1, __ATOMIC_RELAXED);
        break;
    case DEVICE_SYSFS_OP_RESCAN:
        if (ret < 0)
            __atomic_add_fetch(&controls->rescan_fail, 1, __ATOMIC_RELAXED);
        else
            __atomic_add_fetch(&controls->rescan_ok, 1, __ATOMIC_RELAXED);
        break;
    default:
        break;
    }

    __atomic_store_n(&controls->last_op, (uint32_t)op, __ATOMIC_RELAXED);
    __atomic_store_n(&controls->last_ret, (int32_t)ret, __ATOMIC_RELAXED);
}

static ssize_t device_sysfs_control_policy_show(void *priv, char *buf,
                                                size_t bufsz) {
    if (!priv || !buf || bufsz == 0)
        return -EINVAL;
    int n = snprintf(buf, bufsz,
                     "driver=0444 bind=0200 unbind=0200 rescan=0200 "
                     "write_token=required\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return n;
}

static ssize_t device_sysfs_control_stats_show(void *priv, char *buf,
                                               size_t bufsz) {
    struct device *dev = priv;
    if (!dev || !buf || bufsz == 0)
        return -EINVAL;
    if (!dev->sysfs_controls)
        return -ENODEV;

    struct device_sysfs_controls *controls = dev->sysfs_controls;
    uint64_t ops_total = __atomic_load_n(&controls->ops_total, __ATOMIC_RELAXED);
    uint64_t ops_fail = __atomic_load_n(&controls->ops_fail, __ATOMIC_RELAXED);
    uint64_t bind_ok = __atomic_load_n(&controls->bind_ok, __ATOMIC_RELAXED);
    uint64_t bind_fail = __atomic_load_n(&controls->bind_fail, __ATOMIC_RELAXED);
    uint64_t unbind_ok =
        __atomic_load_n(&controls->unbind_ok, __ATOMIC_RELAXED);
    uint64_t unbind_fail =
        __atomic_load_n(&controls->unbind_fail, __ATOMIC_RELAXED);
    uint64_t rescan_ok =
        __atomic_load_n(&controls->rescan_ok, __ATOMIC_RELAXED);
    uint64_t rescan_fail =
        __atomic_load_n(&controls->rescan_fail, __ATOMIC_RELAXED);
    uint32_t last_op = __atomic_load_n(&controls->last_op, __ATOMIC_RELAXED);
    int32_t last_ret = __atomic_load_n(&controls->last_ret, __ATOMIC_RELAXED);

    int n = snprintf(buf, bufsz,
                     "ops_total %llu\nops_fail %llu\nbind_ok %llu\n"
                     "bind_fail %llu\nunbind_ok %llu\nunbind_fail %llu\n"
                     "rescan_ok %llu\nrescan_fail %llu\nlast_op %s\n"
                     "last_ret %d\n",
                     (unsigned long long)ops_total,
                     (unsigned long long)ops_fail, (unsigned long long)bind_ok,
                     (unsigned long long)bind_fail,
                     (unsigned long long)unbind_ok,
                     (unsigned long long)unbind_fail,
                     (unsigned long long)rescan_ok,
                     (unsigned long long)rescan_fail,
                     device_sysfs_op_name(last_op), (int)last_ret);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return n;
}

static ssize_t device_sysfs_driver_show(void *priv, char *buf, size_t bufsz) {
    struct device *dev = priv;
    if (!dev || !buf || bufsz == 0)
        return -EINVAL;

    const char *drv_name = "(none)";
    const char *bus_name = "(none)";
    int bound = 0;

    spin_lock(&device_model_lock);
    if (dev->driver && dev->driver->name) {
        drv_name = dev->driver->name;
        bound = 1;
    }
    if (dev->bus && dev->bus->name)
        bus_name = dev->bus->name;
    int n = snprintf(buf, bufsz, "bus=%s driver=%s bound=%d\n", bus_name,
                     drv_name, bound);
    spin_unlock(&device_model_lock);

    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return n;
}

int device_bind(struct device *dev) {
    if (!dev)
        return -EINVAL;

    spin_lock(&device_model_lock);
    if (dev->driver) {
        spin_unlock(&device_model_lock);
        return -EALREADY;
    }

    device_try_bind(dev);
    int ret = dev->driver ? 0 : -ENODEV;
    spin_unlock(&device_model_lock);
    return ret;
}

int device_unbind(struct device *dev) {
    if (!dev)
        return -EINVAL;

    spin_lock(&device_model_lock);
    struct driver *drv = dev->driver;
    if (!drv) {
        spin_unlock(&device_model_lock);
        return -ENODEV;
    }
    dev->driver = NULL;
    spin_unlock(&device_model_lock);

    if (drv->remove)
        drv->remove(dev);
    return 0;
}

int device_rescan(struct device *dev) {
    if (!dev)
        return -EINVAL;

    spin_lock(&device_model_lock);
    if (dev->driver) {
        spin_unlock(&device_model_lock);
        return -EALREADY;
    }
    device_try_bind(dev);
    int ret = dev->driver ? 0 : -ENODEV;
    spin_unlock(&device_model_lock);
    return ret;
}

static ssize_t device_sysfs_bind_store(void *priv, const char *buf, size_t len) {
    struct device *dev = priv;
    if (!dev)
        return -EINVAL;
    if (!device_sysfs_store_has_token(buf, len)) {
        device_sysfs_audit_record(dev, DEVICE_SYSFS_OP_BIND, -EINVAL);
        return -EINVAL;
    }
    int ret = device_bind(dev);
    device_sysfs_audit_record(dev, DEVICE_SYSFS_OP_BIND, ret);
    if (ret < 0)
        return ret;
    return (ssize_t)len;
}

static ssize_t device_sysfs_unbind_store(void *priv, const char *buf,
                                         size_t len) {
    struct device *dev = priv;
    if (!dev)
        return -EINVAL;
    if (!device_sysfs_store_has_token(buf, len)) {
        device_sysfs_audit_record(dev, DEVICE_SYSFS_OP_UNBIND, -EINVAL);
        return -EINVAL;
    }
    int ret = device_unbind(dev);
    device_sysfs_audit_record(dev, DEVICE_SYSFS_OP_UNBIND, ret);
    if (ret < 0)
        return ret;
    return (ssize_t)len;
}

static ssize_t device_sysfs_rescan_store(void *priv, const char *buf,
                                         size_t len) {
    struct device *dev = priv;
    if (!dev)
        return -EINVAL;
    if (!device_sysfs_store_has_token(buf, len)) {
        device_sysfs_audit_record(dev, DEVICE_SYSFS_OP_RESCAN, -EINVAL);
        return -EINVAL;
    }
    int ret = device_rescan(dev);
    device_sysfs_audit_record(dev, DEVICE_SYSFS_OP_RESCAN, ret);
    if (ret < 0)
        return ret;
    return (ssize_t)len;
}

static int device_sysfs_init_controls(struct device *dev) {
    if (!dev || !dev->sysfs_node)
        return -EINVAL;
    if (dev->sysfs_controls)
        return 0;

    struct device_sysfs_controls *controls = kzalloc(sizeof(*controls));
    if (!controls)
        return -ENOMEM;

    controls->attrs[DEVICE_SYSFS_ATTR_DRIVER] = (struct sysfs_attribute){
        .name = "driver",
        .mode = 0444,
        .show = device_sysfs_driver_show,
        .store = NULL,
        .priv = dev,
    };
    controls->attrs[DEVICE_SYSFS_ATTR_BIND] = (struct sysfs_attribute){
        .name = "bind",
        .mode = 0200,
        .show = NULL,
        .store = device_sysfs_bind_store,
        .priv = dev,
    };
    controls->attrs[DEVICE_SYSFS_ATTR_UNBIND] = (struct sysfs_attribute){
        .name = "unbind",
        .mode = 0200,
        .show = NULL,
        .store = device_sysfs_unbind_store,
        .priv = dev,
    };
    controls->attrs[DEVICE_SYSFS_ATTR_RESCAN] = (struct sysfs_attribute){
        .name = "rescan",
        .mode = 0200,
        .show = NULL,
        .store = device_sysfs_rescan_store,
        .priv = dev,
    };
    controls->attrs[DEVICE_SYSFS_ATTR_CONTROL_POLICY] =
        (struct sysfs_attribute){
            .name = "control_policy",
            .mode = 0444,
            .show = device_sysfs_control_policy_show,
            .store = NULL,
            .priv = dev,
        };
    controls->attrs[DEVICE_SYSFS_ATTR_CONTROL_STATS] = (struct sysfs_attribute){
        .name = "control_stats",
        .mode = 0444,
        .show = device_sysfs_control_stats_show,
        .store = NULL,
        .priv = dev,
    };

    for (size_t i = 0; i < DEVICE_SYSFS_ATTR_COUNT; i++) {
        controls->nodes[i] =
            sysfs_create_file(dev->sysfs_node, &controls->attrs[i]);
        if (!controls->nodes[i]) {
            for (size_t j = 0; j < i; j++) {
                if (controls->nodes[j])
                    sysfs_remove_file(controls->nodes[j]);
            }
            kfree(controls);
            return -ENOMEM;
        }
    }

    dev->sysfs_controls = controls;
    return 0;
}

static void device_sysfs_destroy_controls(struct device *dev) {
    if (!dev || !dev->sysfs_controls)
        return;

    for (size_t i = 0; i < DEVICE_SYSFS_ATTR_COUNT; i++) {
        if (dev->sysfs_controls->nodes[i]) {
            sysfs_remove_file(dev->sysfs_controls->nodes[i]);
            dev->sysfs_controls->nodes[i] = NULL;
        }
    }
    kfree(dev->sysfs_controls);
    dev->sysfs_controls = NULL;
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

    dev->sysfs_controls = NULL;

    /* Create sysfs node under /sys/devices/ before probe callbacks run. */
    dev->sysfs_node = NULL;
    struct sysfs_node *devs = sysfs_devices_dir();
    if (devs) {
        dev->sysfs_node = sysfs_mkdir(devs, dev->name);
        if (!dev->sysfs_node)
            pr_warn("device: sysfs mkdir failed for %s\n", dev->name);
        else {
            int ret = device_sysfs_init_controls(dev);
            if (ret < 0)
                pr_warn("device: sysfs controls init failed for %s (ret=%d)\n",
                        dev->name, ret);
        }
    }

    spin_lock(&device_model_lock);
    list_add_tail(&dev->list, &device_list);

    /* Try to attach to an existing driver */
    device_try_bind(dev);
    spin_unlock(&device_model_lock);

    return 0;
}

void device_unregister(struct device *dev) {
    if (!dev) return;

    int ret = device_unbind(dev);
    if (ret < 0 && ret != -ENODEV)
        pr_warn("device: failed to unbind %s (ret=%d)\n", dev->name, ret);

    spin_lock(&device_model_lock);
    iommu_detach_device(dev);
    list_del(&dev->list);
    dev->driver = NULL;
    spin_unlock(&device_model_lock);

    /* Remove sysfs node */
    if (dev->sysfs_node) {
        device_sysfs_destroy_controls(dev);
        sysfs_rmdir(dev->sysfs_node);
        dev->sysfs_node = NULL;
    }
}

int device_for_each(int (*fn)(struct device *dev, void *arg), void *arg) {
    if (!fn)
        return -EINVAL;

    size_t count = 0;
    bool irq_flags;
    spin_lock_irqsave(&device_model_lock, &irq_flags);
    struct device *iter;
    list_for_each_entry(iter, &device_list, list) { count++; }
    spin_unlock_irqrestore(&device_model_lock, irq_flags);

    if (!count)
        return 0;

    struct device **snapshot = kzalloc(sizeof(*snapshot) * count);
    if (!snapshot)
        return -ENOMEM;

    size_t n = 0;
    spin_lock_irqsave(&device_model_lock, &irq_flags);
    list_for_each_entry(iter, &device_list, list) {
        if (n >= count)
            break;
        snapshot[n++] = iter;
    }
    spin_unlock_irqrestore(&device_model_lock, irq_flags);

    int ret = 0;
    for (size_t i = 0; i < n; i++) {
        ret = fn(snapshot[i], arg);
        if (ret)
            break;
    }

    kfree(snapshot);
    return ret;
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

int device_sysfs_create_file(struct device *dev,
                             const struct sysfs_attribute *attr,
                             struct sysfs_node **out_node) {
    if (!dev || !attr || !attr->name)
        return -EINVAL;
    if (!dev->sysfs_node)
        return -ENODEV;

    struct sysfs_node *node = sysfs_create_file(dev->sysfs_node, attr);
    if (!node)
        return -ENOMEM;
    if (out_node)
        *out_node = node;
    return 0;
}

int device_sysfs_create_files(struct device *dev,
                              const struct sysfs_attribute *attrs,
                              size_t count) {
    if (!dev || !attrs || count == 0)
        return -EINVAL;
    if (!dev->sysfs_node)
        return -ENODEV;
    return sysfs_create_files(dev->sysfs_node, attrs, count);
}

void device_sysfs_remove_file(struct sysfs_node *node) {
    sysfs_remove_file(node);
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
