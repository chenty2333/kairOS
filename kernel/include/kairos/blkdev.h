/**
 * kairos/blkdev.h - Block Device Interface
 */

#ifndef _KAIROS_BLKDEV_H
#define _KAIROS_BLKDEV_H

#include <kairos/types.h>
#include <kairos/list.h>

/*
 * Block Device
 */
struct blkdev {
    char name[16];                      /* e.g., "nvme0n1", "vda" */
    uint64_t sector_count;              /* Total sectors */
    uint32_t sector_size;               /* Bytes per sector (usually 512) */

    struct blkdev_ops *ops;             /* Operations */
    void *private;                      /* Driver private data */

    struct list_head list;              /* Global blkdev list */
    uint32_t refcount;
};

/*
 * Block Device Operations
 */
struct blkdev_ops {
    /* Read sectors */
    int (*read)(struct blkdev *dev, uint64_t lba, void *buf, size_t count);

    /* Write sectors */
    int (*write)(struct blkdev *dev, uint64_t lba, const void *buf, size_t count);

    /* Flush write cache */
    int (*flush)(struct blkdev *dev);
};

/*
 * Block Device API
 */

/* Register a block device */
int blkdev_register(struct blkdev *dev);

/* Unregister a block device */
void blkdev_unregister(struct blkdev *dev);

/* Find block device by name */
struct blkdev *blkdev_get(const char *name);

/* Release block device reference */
void blkdev_put(struct blkdev *dev);

/* Read from block device */
static inline int blkdev_read(struct blkdev *dev, uint64_t lba,
                               void *buf, size_t count)
{
    return dev->ops->read(dev, lba, buf, count);
}

/* Write to block device */
static inline int blkdev_write(struct blkdev *dev, uint64_t lba,
                                const void *buf, size_t count)
{
    return dev->ops->write(dev, lba, buf, count);
}

/* Get device size in bytes */
static inline uint64_t blkdev_size(struct blkdev *dev)
{
    return dev->sector_count * dev->sector_size;
}

/*
 * Partition Support (optional)
 */
struct partition {
    struct blkdev *parent;              /* Parent device */
    uint64_t start_lba;                 /* Start sector */
    uint64_t sector_count;              /* Partition size */
    uint8_t type;                       /* Partition type */
    char name[16];                      /* e.g., "nvme0n1p1" */
};

/* Probe partitions on device */
int blkdev_probe_partitions(struct blkdev *dev);

#endif /* _KAIROS_BLKDEV_H */
