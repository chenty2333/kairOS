/**
 * blkdev.c - Block Device Registration and Management
 *
 * This implements the block device abstraction layer.
 * Individual drivers (virtio-blk, NVMe, etc.) register with this layer.
 */

#include <kairos/blkdev.h>
#include <kairos/printk.h>
#include <kairos/mm.h>
#include <kairos/spinlock.h>
#include <kairos/list.h>
#include <kairos/types.h>

/*
 * Global block device state
 */
static LIST_HEAD(blkdev_list);
static spinlock_t blkdev_lock = SPINLOCK_INIT;

/**
 * Helper: string comparison
 */
static int strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

/**
 * blkdev_register - Register a block device
 *
 * @dev: Block device to register
 *
 * Returns 0 on success, negative error on failure.
 */
int blkdev_register(struct blkdev *dev)
{
    if (!dev || !dev->name[0] || !dev->ops) {
        return -EINVAL;
    }

    if (!dev->ops->read || !dev->ops->write) {
        pr_err("blkdev: %s missing required operations\n", dev->name);
        return -EINVAL;
    }

    spin_lock(&blkdev_lock);

    /* Check for duplicate names */
    struct blkdev *existing;
    list_for_each_entry(existing, &blkdev_list, list) {
        if (strcmp(existing->name, dev->name) == 0) {
            spin_unlock(&blkdev_lock);
            pr_err("blkdev: %s already registered\n", dev->name);
            return -EEXIST;
        }
    }

    /* Add to list */
    dev->refcount = 0;
    list_add_tail(&dev->list, &blkdev_list);

    spin_unlock(&blkdev_lock);

    pr_info("blkdev: registered %s (%lu MB, %u byte sectors)\n",
            dev->name,
            (dev->sector_count * dev->sector_size) / (1024 * 1024),
            dev->sector_size);

    return 0;
}

/**
 * blkdev_unregister - Unregister a block device
 *
 * @dev: Block device to unregister
 */
void blkdev_unregister(struct blkdev *dev)
{
    if (!dev) {
        return;
    }

    spin_lock(&blkdev_lock);

    /* Check if still in use */
    if (dev->refcount > 0) {
        spin_unlock(&blkdev_lock);
        pr_warn("blkdev: %s still in use (refcount=%u)\n",
                dev->name, dev->refcount);
        return;
    }

    /* Remove from list */
    list_del(&dev->list);

    spin_unlock(&blkdev_lock);

    pr_info("blkdev: unregistered %s\n", dev->name);
}

/**
 * blkdev_get - Find and get reference to block device
 *
 * @name: Device name (e.g., "vda", "nvme0n1")
 *
 * Returns block device with incremented reference count, or NULL if not found.
 */
struct blkdev *blkdev_get(const char *name)
{
    struct blkdev *dev;

    if (!name) {
        return NULL;
    }

    spin_lock(&blkdev_lock);

    list_for_each_entry(dev, &blkdev_list, list) {
        if (strcmp(dev->name, name) == 0) {
            dev->refcount++;
            spin_unlock(&blkdev_lock);
            return dev;
        }
    }

    spin_unlock(&blkdev_lock);
    return NULL;
}

/**
 * blkdev_put - Release reference to block device
 *
 * @dev: Block device to release
 */
void blkdev_put(struct blkdev *dev)
{
    if (!dev) {
        return;
    }

    spin_lock(&blkdev_lock);
    if (dev->refcount > 0) {
        dev->refcount--;
    }
    spin_unlock(&blkdev_lock);
}

/**
 * blkdev_probe_partitions - Probe for partitions on a block device
 *
 * @dev: Block device to probe
 *
 * This is a placeholder for now. In a real implementation, this would
 * read the partition table (GPT, MBR) and create partition devices.
 *
 * Returns 0 on success, negative error on failure.
 */
int blkdev_probe_partitions(struct blkdev *dev)
{
    (void)dev;
    /* TODO: Implement partition probing */
    return 0;
}
