/**
 * kernel/fs/bio/bio.c - Block I/O (Buffer Cache)
 */

#include <kairos/blkdev.h>
#include <kairos/buf.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sync.h>

#define NBUF 128
#define HASH_SIZE 32
#define BIO_MAX_BLOCK_BYTES CONFIG_PAGE_SIZE
#define BUF_HASH(dev, b, sz)                                                   \
    (((uintptr_t)(dev) ^ (uintptr_t)(b) ^ (uintptr_t)(sz)) % HASH_SIZE)

static struct buf bufs[NBUF];
static struct list_head hashtable[HASH_SIZE];
static struct list_head lru_list;
static struct list_head dirty_list;
static spinlock_t bcache_lock = SPINLOCK_INIT;

static inline int bio_validate_block_bytes(uint32_t block_bytes)
{
    if (block_bytes == 0 || block_bytes > BIO_MAX_BLOCK_BYTES)
        return -EINVAL;
    if ((block_bytes % 512U) != 0)
        return -EINVAL;
    return 0;
}

static inline uint32_t bio_sectors_per_block(struct blkdev *dev,
                                             uint32_t block_bytes)
{
    if (!dev || !dev->sector_size || (block_bytes % dev->sector_size) != 0)
        return 0;
    return block_bytes / dev->sector_size;
}

static int bflush_locked(struct buf *b)
{
    if (!b || !b->dev)
        return -EINVAL;
    if (!(b->flags & B_DIRTY))
        return 0;

    uint32_t sectors = bio_sectors_per_block(b->dev, b->block_bytes);
    if (sectors == 0)
        return -EINVAL;
    int ret = blkdev_write(b->dev, b->blockno * sectors, b->data, sectors);
    if (ret < 0)
        return ret;

    spin_lock(&bcache_lock);
    b->flags &= ~B_DIRTY;
    if (!list_empty(&b->dirty))
        list_del(&b->dirty);
    INIT_LIST_HEAD(&b->dirty);
    spin_unlock(&bcache_lock);
    return 0;
}

void binit(void) {
    INIT_LIST_HEAD(&lru_list);
    INIT_LIST_HEAD(&dirty_list);
    for (int i = 0; i < HASH_SIZE; i++)
        INIT_LIST_HEAD(&hashtable[i]);

    for (int i = 0; i < NBUF; i++) {
        struct buf *b = &bufs[i];
        b->data = kmalloc(BIO_MAX_BLOCK_BYTES);
        b->dev = NULL;
        b->flags = 0;
        b->refcount = 0;
        b->blockno = 0;
        b->block_bytes = 0;
        mutex_init(&b->lock, "buffer");
        INIT_LIST_HEAD(&b->dirty);
        list_add(&b->lru, &lru_list);
    }
    pr_info("bio: initialized %d buffers\n", NBUF);
}

/**
 * bget - Look for a buffer for the given device and block size.
 * Returns the buffer, locked.
 */
static struct buf *bget(struct blkdev *dev, uint64_t blockno,
                        uint32_t block_bytes) {
    struct buf *b;
    struct buf *dirty_victim = NULL;
    uint32_t h = BUF_HASH(dev, blockno, block_bytes);

retry:
    spin_lock(&bcache_lock);

    /* 1. Check if in hash table */
    list_for_each_entry(b, &hashtable[h], hash) {
        if (b->dev == dev && b->blockno == blockno &&
            b->block_bytes == block_bytes) {
            b->refcount++;
            spin_unlock(&bcache_lock);
            mutex_lock(&b->lock);
            return b;
        }
    }

    /* 2. Not in cache, find an unused buffer from LRU (backwards) */
    list_for_each_entry_reverse(b, &lru_list, lru) {
        if (b->refcount == 0 && !(b->flags & B_DIRTY)) {
            if (b->dev)
                list_del(&b->hash); /* Remove from old hash */
            b->dev = dev;
            b->blockno = blockno;
            b->block_bytes = block_bytes;
            b->flags = 0;
            b->refcount = 1;
            list_add(&b->hash, &hashtable[h]);
            spin_unlock(&bcache_lock);
            mutex_lock(&b->lock);
            return b;
        }
        if (b->refcount == 0 && !dirty_victim && (b->flags & B_DIRTY)) {
            dirty_victim = b;
        }
    }

    spin_unlock(&bcache_lock);

    if (dirty_victim) {
        mutex_lock(&dirty_victim->lock);
        int ret = bflush_locked(dirty_victim);
        mutex_unlock(&dirty_victim->lock);
        if (ret < 0)
            panic("bio: failed to flush dirty victim (ret=%d)", ret);
        dirty_victim = NULL;
        goto retry;
    }
    panic("bio: out of buffers");
}

/**
 * breadn - Read a block from disk. Returns a locked buffer.
 */
struct buf *breadn(struct blkdev *dev, uint64_t blockno, uint32_t block_bytes) {
    if (!dev || bio_validate_block_bytes(block_bytes) < 0)
        return NULL;

    struct buf *b = bget(dev, blockno, block_bytes);
    if (!(b->flags & B_VALID)) {
        uint32_t sectors = bio_sectors_per_block(dev, block_bytes);
        if (sectors == 0) {
            brelse(b);
            return NULL;
        }
        int ret = blkdev_read(dev, blockno * sectors, b->data, sectors);
        if (ret < 0) {
            brelse(b);
            return NULL;
        }
        b->flags |= B_VALID;
    }
    return b;
}

struct buf *bread(struct blkdev *dev, uint32_t blockno) {
    return breadn(dev, blockno, BIO_MAX_BLOCK_BYTES);
}

/**
 * bwrite - Write a buffer's content to disk.
 * Buffer must be locked.
 */
void bwrite(struct buf *b) {
    if (b->lock.holder != proc_current()) {
        panic("bwrite: buffer not held by current process");
    }
    b->flags |= (B_VALID | B_DIRTY);

    spin_lock(&bcache_lock);
    if (list_empty(&b->dirty))
        list_add_tail(&b->dirty, &dirty_list);
    spin_unlock(&bcache_lock);
}

/**
 * brelse - Release a locked buffer.
 */
void brelse(struct buf *b) {
    mutex_unlock(&b->lock);

    spin_lock(&bcache_lock);
    b->refcount--;
    if (b->refcount == 0) {
        /* Move to the head of LRU list (most recently released) */
        list_del(&b->lru);
        list_add(&b->lru, &lru_list);
    }
    spin_unlock(&bcache_lock);
}

int bsync_dev(struct blkdev *dev) {
    int first_err = 0;

    for (;;) {
        struct buf *target = NULL;

        spin_lock(&bcache_lock);
        struct list_head *pos;
        list_for_each(pos, &dirty_list) {
            struct buf *b = list_entry(pos, struct buf, dirty);
            if (!dev || b->dev == dev) {
                b->refcount++;
                target = b;
                break;
            }
        }
        spin_unlock(&bcache_lock);

        if (!target)
            break;

        mutex_lock(&target->lock);
        int ret = bflush_locked(target);
        mutex_unlock(&target->lock);
        if (ret < 0 && first_err == 0)
            first_err = ret;

        spin_lock(&bcache_lock);
        if (target->refcount > 0)
            target->refcount--;
        if (target->refcount == 0) {
            list_del(&target->lru);
            list_add(&target->lru, &lru_list);
        }
        spin_unlock(&bcache_lock);
    }

    return first_err;
}

int bsync_all(void) {
    return bsync_dev(NULL);
}
