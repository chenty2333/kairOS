/**
 * kernel/include/kairos/blkdev.h - Block Device Interface
 */

#ifndef _KAIROS_BLKDEV_H
#define _KAIROS_BLKDEV_H

#include <kairos/list.h>
#include <kairos/types.h>

struct blkdev {
    char name[16];
    uint64_t sector_count;
    uint32_t sector_size;
    struct blkdev_ops *ops;
    void *private;
    struct list_head list;
    uint32_t refcount;
};

struct blkdev_ops {
    int (*read)(struct blkdev *dev, uint64_t lba, void *buf, size_t count);
    int (*write)(struct blkdev *dev, uint64_t lba, const void *buf,
                 size_t count);
    int (*flush)(struct blkdev *dev);
};

typedef void (*blkdev_iter_fn_t)(struct blkdev *dev, void *arg);

int blkdev_register(struct blkdev *dev);
void blkdev_unregister(struct blkdev *dev);
struct blkdev *blkdev_get(const char *name);
void blkdev_put(struct blkdev *dev);
int blkdev_for_each(blkdev_iter_fn_t fn, void *arg);

static inline int blkdev_read(struct blkdev *dev, uint64_t lba, void *buf,
                              size_t cnt) {
    return dev->ops->read(dev, lba, buf, cnt);
}

static inline int blkdev_write(struct blkdev *dev, uint64_t lba,
                               const void *buf, size_t cnt) {
    return dev->ops->write(dev, lba, buf, cnt);
}

#endif
