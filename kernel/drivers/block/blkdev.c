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

static int probe_mbr_partitions(struct blkdev *dev, const uint8_t *sector0,
                                bool *has_protective, uint32_t *out_count) {
    if (!dev || !sector0 || !has_protective || !out_count)
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

        if (type == MBR_PROTECTIVE_TYPE)
            *has_protective = true;

        uint64_t first = (uint64_t)first_lba;
        uint64_t count = (uint64_t)sectors;
        uint64_t last = first + count - 1ULL;

        if (first >= dev->sector_count || last >= dev->sector_count) {
            pr_warn("blkdev: %s partition %u out of bounds [%llu,%llu]\n",
                    dev->name, i + 1, (unsigned long long)first,
                    (unsigned long long)last);
            continue;
        }

        log_partition_bounds(dev->name, i + 1, first, last);
        (*out_count)++;
    }

    return 0;
}

static int probe_gpt_partitions(struct blkdev *dev, uint32_t *out_count) {
    if (!dev || !out_count)
        return -EINVAL;
    if (dev->sector_count <= GPT_HEADER_LBA)
        return 0;

    uint8_t *header = kmalloc(dev->sector_size);
    if (!header)
        return -ENOMEM;

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
        (*out_count)++;
    }

    kfree(sector);
    return 0;
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
    if (dev->sector_size < 512)
        return -EINVAL;

    uint8_t *sector0 = kmalloc(dev->sector_size);
    if (!sector0)
        return -ENOMEM;

    int rc = blkdev_read(dev, 0, sector0, 1);
    if (rc < 0) {
        kfree(sector0);
        return rc;
    }

    bool has_protective = false;
    uint32_t mbr_count = 0;
    rc = probe_mbr_partitions(dev, sector0, &has_protective, &mbr_count);
    kfree(sector0);
    if (rc < 0)
        return rc;

    uint32_t gpt_count = 0;
    if (has_protective) {
        rc = probe_gpt_partitions(dev, &gpt_count);
        if (rc < 0)
            return rc;
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

    /*
     * FIXME: Probe currently logs discovered partitions but does not register
     * partition child block devices yet.
     */
    return 0;
}
