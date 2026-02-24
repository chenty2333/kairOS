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
#include <kairos/string.h>
#include <kairos/types.h>

/*
 * Global block device state
 */
static LIST_HEAD(blkdev_list);
static spinlock_t blkdev_lock = SPINLOCK_INIT;

#define MBR_SIGNATURE_OFFSET 510U
#define MBR_SIGNATURE 0xAA55U
#define MBR_PART_TABLE_OFFSET 446U
#define MBR_PART_COUNT 4U
#define MBR_PART_ENTRY_SIZE 16U
#define MBR_PROTECTIVE_TYPE 0xEEU
#define GPT_HEADER_LBA 1ULL
#define GPT_SIGNATURE "EFI PART"
#define GPT_PART_ENTRY_MAX_SIZE 4096U
#define GPT_PART_ENTRIES_HARD_LIMIT 4096U

struct partition_span {
    uint32_t index;
    uint64_t first_lba;
    uint64_t last_lba;
};

static int blkpart_read(struct blkdev *dev, uint64_t lba, void *buf, size_t count);
static int blkpart_write(struct blkdev *dev, uint64_t lba, const void *buf,
                         size_t count);
static int blkpart_flush(struct blkdev *dev);
static int blkdev_register_partition(struct blkdev *parent, uint32_t part_index,
                                     uint64_t first_lba, uint64_t last_lba);
static int blkdev_drop_partition_children(struct blkdev *parent);

static struct blkdev_ops blkpart_ops = {
    .read = blkpart_read,
    .write = blkpart_write,
    .flush = blkpart_flush,
};

static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p) {
    return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

static bool guid_is_zero(const uint8_t *guid, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (guid[i] != 0)
            return false;
    }
    return true;
}

static bool name_ends_with_digit(const char *name) {
    if (!name)
        return false;

    size_t len = 0;
    while (len < 15 && name[len] != '\0')
        len++;
    if (len == 0)
        return false;

    char ch = name[len - 1];
    return ch >= '0' && ch <= '9';
}

static bool blkdev_is_partition(const struct blkdev *dev) {
    return dev && dev->parent && dev->ops == &blkpart_ops;
}

static int make_partition_name(const struct blkdev *parent, uint32_t part_index,
                               char *out, size_t out_size) {
    if (!parent || !out || out_size == 0 || part_index == 0)
        return -EINVAL;

    bool suffix_p = name_ends_with_digit(parent->name);
    int n = snprintf(out, out_size, suffix_p ? "%sp%u" : "%s%u",
                     parent->name, part_index);
    if (n < 0 || (size_t)n >= out_size)
        return -ENAMETOOLONG;
    return 0;
}

static void log_partition_bounds(const char *dev_name, uint32_t idx,
                                 uint64_t first_lba, uint64_t last_lba) {
    if (last_lba < first_lba) {
        pr_warn("blkdev: %s partition %u has invalid bounds [%llu,%llu]\n",
                dev_name, idx, (unsigned long long)first_lba,
                (unsigned long long)last_lba);
        return;
    }
    pr_info("blkdev: %s partition %u lba=%llu..%llu (%llu sectors)\n",
            dev_name, idx, (unsigned long long)first_lba,
            (unsigned long long)last_lba,
            (unsigned long long)(last_lba - first_lba + 1ULL));
}

static int blkpart_read(struct blkdev *dev, uint64_t lba, void *buf, size_t count) {
    struct blkdev *parent = dev ? dev->parent : NULL;
    if (!dev || !parent || !buf || count == 0)
        return -EINVAL;
    if (lba >= dev->sector_count || count > dev->sector_count - lba)
        return -EINVAL;

    uint64_t parent_lba = dev->start_lba + lba;
    if (parent_lba > UINT64_MAX - count)
        return -EINVAL;
    if (parent_lba + count > parent->sector_count)
        return -EINVAL;
    return blkdev_read(parent, parent_lba, buf, count);
}

static int blkpart_write(struct blkdev *dev, uint64_t lba, const void *buf,
                         size_t count) {
    struct blkdev *parent = dev ? dev->parent : NULL;
    if (!dev || !parent || !buf || count == 0)
        return -EINVAL;
    if (lba >= dev->sector_count || count > dev->sector_count - lba)
        return -EINVAL;

    uint64_t parent_lba = dev->start_lba + lba;
    if (parent_lba > UINT64_MAX - count)
        return -EINVAL;
    if (parent_lba + count > parent->sector_count)
        return -EINVAL;
    return blkdev_write(parent, parent_lba, buf, count);
}

static int blkpart_flush(struct blkdev *dev) {
    struct blkdev *parent = dev ? dev->parent : NULL;
    if (!dev || !parent)
        return -EINVAL;
    if (!parent->ops || !parent->ops->flush)
        return 0;
    return parent->ops->flush(parent);
}

static int blkdev_register_partition(struct blkdev *parent, uint32_t part_index,
                                     uint64_t first_lba, uint64_t last_lba) {
    if (!parent || part_index == 0 || last_lba < first_lba)
        return -EINVAL;

    uint64_t sector_count = last_lba - first_lba + 1ULL;
    if (sector_count == 0)
        return -EINVAL;
    if (first_lba >= parent->sector_count ||
        sector_count > parent->sector_count - first_lba) {
        return -EINVAL;
    }

    struct blkdev *part = kzalloc(sizeof(*part));
    if (!part)
        return -ENOMEM;

    int rc = make_partition_name(parent, part_index, part->name, sizeof(part->name));
    if (rc < 0) {
        kfree(part);
        return rc;
    }

    part->sector_count = sector_count;
    part->sector_size = parent->sector_size;
    part->ops = &blkpart_ops;
    part->parent = parent;
    part->start_lba = first_lba;

    rc = blkdev_register(part);
    if (rc < 0) {
        kfree(part);
        return rc;
    }
    return 0;
}

static int blkdev_drop_partition_children(struct blkdev *parent) {
    if (!parent || blkdev_is_partition(parent))
        return -EINVAL;

    while (1) {
        struct blkdev *child = NULL;

        spin_lock(&blkdev_lock);
        struct blkdev *dev;
        list_for_each_entry(dev, &blkdev_list, list) {
            if (blkdev_is_partition(dev) && dev->parent == parent) {
                child = dev;
                break;
            }
        }
        if (!child) {
            spin_unlock(&blkdev_lock);
            return 0;
        }
        if (child->refcount > 0) {
            spin_unlock(&blkdev_lock);
            pr_warn("blkdev: %s partition %s still in use (refcount=%u)\n",
                    parent->name, child->name, child->refcount);
            return -EBUSY;
        }
        list_del(&child->list);
        spin_unlock(&blkdev_lock);

        pr_info("blkdev: unregistered %s\n", child->name);
        kfree(child);
    }
}

static int probe_mbr_partitions(struct blkdev *dev, const uint8_t *sector0,
                                bool *has_protective,
                                struct partition_span *parts,
                                size_t parts_cap, uint32_t *out_count) {
    if (!dev || !sector0 || !has_protective || !parts || !out_count)
        return -EINVAL;
    if (dev->sector_size < MBR_SIGNATURE_OFFSET + 2U)
        return -EINVAL;

    *has_protective = false;
    *out_count = 0;

    if (read_le16(sector0 + MBR_SIGNATURE_OFFSET) != MBR_SIGNATURE)
        return 0;

    for (uint32_t i = 0; i < MBR_PART_COUNT; i++) {
        const uint8_t *entry =
            sector0 + MBR_PART_TABLE_OFFSET + i * MBR_PART_ENTRY_SIZE;
        uint8_t type = entry[4];
        uint32_t first_lba = read_le32(entry + 8);
        uint32_t sectors = read_le32(entry + 12);

        if (type == 0 || sectors == 0)
            continue;

        if (type == MBR_PROTECTIVE_TYPE) {
            *has_protective = true;
            continue;
        }

        uint64_t first = (uint64_t)first_lba;
        uint64_t count = (uint64_t)sectors;
        uint64_t last = first + count - 1ULL;

        if (first >= dev->sector_count || last >= dev->sector_count) {
            pr_warn("blkdev: %s partition %u out of bounds [%llu,%llu]\n",
                    dev->name, i + 1, (unsigned long long)first,
                    (unsigned long long)last);
            continue;
        }

        if (*out_count >= parts_cap)
            continue;
        parts[*out_count].index = i + 1;
        parts[*out_count].first_lba = first;
        parts[*out_count].last_lba = last;
        (*out_count)++;
    }

    return 0;
}

static int probe_gpt_partitions(struct blkdev *dev, uint32_t *out_count,
                                bool register_children) {
    if (!dev || !out_count)
        return -EINVAL;
    if (dev->sector_count <= GPT_HEADER_LBA)
        return 0;

    uint8_t *header = kmalloc(dev->sector_size);
    if (!header)
        return -ENOMEM;

    memset(header, 0, dev->sector_size);
    int rc = blkdev_read(dev, GPT_HEADER_LBA, header, 1);
    if (rc < 0) {
        kfree(header);
        return rc;
    }

    if (memcmp(header, GPT_SIGNATURE, 8) != 0) {
        kfree(header);
        return 0;
    }

    uint64_t entries_lba = read_le64(header + 72);
    uint32_t entries_count = read_le32(header + 80);
    uint32_t entry_size = read_le32(header + 84);
    kfree(header);

    if (entries_count == 0 || entry_size < 56 ||
        entry_size > GPT_PART_ENTRY_MAX_SIZE) {
        pr_warn("blkdev: %s GPT header has invalid entry geometry\n", dev->name);
        return -EINVAL;
    }

    if (entries_count > GPT_PART_ENTRIES_HARD_LIMIT)
        entries_count = GPT_PART_ENTRIES_HARD_LIMIT;

    uint8_t *sector = kmalloc(dev->sector_size);
    if (!sector)
        return -ENOMEM;

    uint64_t cached_lba = UINT64_MAX;
    *out_count = 0;
    int first_err = 0;

    for (uint32_t i = 0; i < entries_count; i++) {
        uint64_t byte_off = (uint64_t)i * (uint64_t)entry_size;
        uint64_t lba = entries_lba + (byte_off / dev->sector_size);
        uint64_t off = byte_off % dev->sector_size;
        if (off + entry_size > dev->sector_size) {
            pr_warn("blkdev: %s GPT entry size crossing sectors is unsupported\n",
                    dev->name);
            break;
        }
        if (lba >= dev->sector_count)
            break;

        if (lba != cached_lba) {
            memset(sector, 0, dev->sector_size);
            rc = blkdev_read(dev, lba, sector, 1);
            if (rc < 0) {
                kfree(sector);
                return rc;
            }
            cached_lba = lba;
        }

        const uint8_t *entry = sector + off;
        if (guid_is_zero(entry, 16))
            continue;

        uint64_t first = read_le64(entry + 32);
        uint64_t last = read_le64(entry + 40);
        if (first >= dev->sector_count || last >= dev->sector_count || last < first) {
            pr_warn("blkdev: %s GPT partition %u out of bounds [%llu,%llu]\n",
                    dev->name, i + 1, (unsigned long long)first,
                    (unsigned long long)last);
            continue;
        }

        log_partition_bounds(dev->name, i + 1, first, last);
        if (register_children) {
            int reg_rc = blkdev_register_partition(dev, i + 1, first, last);
            if (reg_rc < 0) {
                if (first_err == 0)
                    first_err = reg_rc;
                pr_warn("blkdev: %s failed to register GPT partition %u (%d)\n",
                        dev->name, i + 1, reg_rc);
            }
        }
        (*out_count)++;
    }

    kfree(sector);
    return first_err;
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

    if (dev->sector_size == 0 || dev->sector_count == 0) {
        pr_err("blkdev: %s invalid geometry\n", dev->name);
        return -EINVAL;
    }

    if (!dev->ops->read || !dev->ops->write) {
        pr_err("blkdev: %s missing required operations\n", dev->name);
        return -EINVAL;
    }

    if (dev->parent) {
        if (dev->parent == dev || dev->sector_size != dev->parent->sector_size) {
            pr_err("blkdev: %s has invalid partition geometry\n", dev->name);
            return -EINVAL;
        }
        if (dev->start_lba >= dev->parent->sector_count ||
            dev->sector_count > dev->parent->sector_count - dev->start_lba) {
            pr_err("blkdev: %s partition outside parent bounds\n", dev->name);
            return -EINVAL;
        }
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
    INIT_LIST_HEAD(&dev->list);
    dev->refcount = 0;
    list_add_tail(&dev->list, &blkdev_list);

    spin_unlock(&blkdev_lock);

    pr_info("blkdev: registered %s (%lu MB, %u byte sectors)\n",
            dev->name,
            (dev->sector_count * dev->sector_size) / (1024 * 1024),
            dev->sector_size);

    if (dev->parent)
        return 0;

    int probe_rc = blkdev_probe_partitions(dev);
    if (probe_rc < 0) {
        pr_warn("blkdev: %s partition probe failed (%d)\n",
                dev->name, probe_rc);
    }

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

    if (blkdev_is_partition(dev)) {
        spin_lock(&blkdev_lock);
        if (dev->refcount > 0) {
            spin_unlock(&blkdev_lock);
            pr_warn("blkdev: %s still in use (refcount=%u)\n",
                    dev->name, dev->refcount);
            return;
        }
        list_del(&dev->list);
        spin_unlock(&blkdev_lock);
        pr_info("blkdev: unregistered %s\n", dev->name);
        kfree(dev);
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

    spin_unlock(&blkdev_lock);

    int child_rc = blkdev_drop_partition_children(dev);
    if (child_rc < 0)
        return;

    spin_lock(&blkdev_lock);
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

int blkdev_for_each(blkdev_iter_fn_t fn, void *arg)
{
    if (!fn)
        return -EINVAL;

    size_t count = 0;
    spin_lock(&blkdev_lock);
    struct blkdev *dev;
    list_for_each_entry(dev, &blkdev_list, list) {
        count++;
    }
    spin_unlock(&blkdev_lock);

    if (!count)
        return 0;

    struct blkdev **list = kmalloc(count * sizeof(*list));
    if (!list)
        return -ENOMEM;

    size_t idx = 0;
    spin_lock(&blkdev_lock);
    list_for_each_entry(dev, &blkdev_list, list) {
        if (idx < count)
            list[idx++] = dev;
    }
    spin_unlock(&blkdev_lock);

    for (size_t i = 0; i < idx; i++)
        fn(list[i], arg);

    kfree(list);
    return (int)idx;
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
    if (!dev)
        return -EINVAL;
    if (dev->parent)
        return -EINVAL;
    if (dev->sector_size < 512)
        return -EINVAL;

    int rc = blkdev_drop_partition_children(dev);
    if (rc < 0)
        return rc;

    uint8_t *sector0 = kmalloc(dev->sector_size);
    if (!sector0)
        return -ENOMEM;

    memset(sector0, 0, dev->sector_size);
    rc = blkdev_read(dev, 0, sector0, 1);
    if (rc < 0) {
        kfree(sector0);
        return rc;
    }

    bool has_protective = false;
    struct partition_span mbr_parts[MBR_PART_COUNT] = { 0 };
    uint32_t mbr_count = 0;
    rc = probe_mbr_partitions(dev, sector0, &has_protective, mbr_parts,
                              ARRAY_SIZE(mbr_parts), &mbr_count);
    kfree(sector0);
    if (rc < 0)
        return rc;

    uint32_t gpt_count = 0;
    int first_err = 0;
    if (has_protective) {
        rc = probe_gpt_partitions(dev, &gpt_count, true);
        if (rc < 0)
            first_err = rc;
    }

    if (gpt_count == 0 && mbr_count > 0) {
        for (uint32_t i = 0; i < mbr_count; i++) {
            log_partition_bounds(dev->name, mbr_parts[i].index,
                                 mbr_parts[i].first_lba,
                                 mbr_parts[i].last_lba);
            int reg_rc = blkdev_register_partition(dev, mbr_parts[i].index,
                                                   mbr_parts[i].first_lba,
                                                   mbr_parts[i].last_lba);
            if (reg_rc < 0) {
                if (first_err == 0)
                    first_err = reg_rc;
                pr_warn("blkdev: %s failed to register MBR partition %u (%d)\n",
                        dev->name, mbr_parts[i].index, reg_rc);
            }
        }
    }

    if (gpt_count > 0) {
        pr_info("blkdev: %s GPT partitions discovered: %u\n",
                dev->name, gpt_count);
    } else if (mbr_count > 0) {
        pr_info("blkdev: %s MBR partitions discovered: %u\n",
                dev->name, mbr_count);
    } else {
        pr_info("blkdev: %s no partition table entries found\n", dev->name);
    }

    return first_err;
}
