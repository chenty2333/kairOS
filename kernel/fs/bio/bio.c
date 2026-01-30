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
#define BUF_HASH(dev, b) (((uintptr_t)(dev) ^ (b)) % HASH_SIZE)

static struct buf bufs[NBUF];
static struct list_head hashtable[HASH_SIZE];
static struct list_head lru_list;
static spinlock_t bcache_lock = SPINLOCK_INIT;

void binit(void) {
    INIT_LIST_HEAD(&lru_list);
    for (int i = 0; i < HASH_SIZE; i++)
        INIT_LIST_HEAD(&hashtable[i]);

    for (int i = 0; i < NBUF; i++) {
        struct buf *b = &bufs[i];
        b->data = kmalloc(4096); /* Assume 4K block size for now */
        b->dev = NULL;
        b->flags = 0;
        b->refcount = 0;
        mutex_init(&b->lock, "buffer");
        list_add(&b->lru, &lru_list);
    }
    pr_info("bio: initialized %d buffers\n", NBUF);
}

/**
 * bget - Look for a buffer for the given device and block.
 * Returns the buffer, locked.
 */
static struct buf *bget(struct blkdev *dev, uint32_t blockno) {
    struct buf *b;
    uint32_t h = BUF_HASH(dev, blockno);

    spin_lock(&bcache_lock);

    /* 1. Check if in hash table */
    list_for_each_entry(b, &hashtable[h], hash) {
        if (b->dev == dev && b->blockno == blockno) {
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
            b->flags = 0;
            b->refcount = 1;
            list_add(&b->hash, &hashtable[h]);
            spin_unlock(&bcache_lock);
            mutex_lock(&b->lock);
            return b;
        }
    }

    spin_unlock(&bcache_lock);
    panic("bio: out of buffers");
}

/**
 * bread - Read a block from disk. Returns a locked buffer.
 */
struct buf *bread(struct blkdev *dev, uint32_t blockno) {
    struct buf *b = bget(dev, blockno);
    if (!(b->flags & B_VALID)) {
        int ret = blkdev_read(dev,
                              (uint64_t)blockno * (4096 / dev->sector_size),
                              b->data, 4096 / dev->sector_size);
        if (ret < 0) {
            brelse(b);
            return NULL;
        }
        b->flags |= B_VALID;
    }
    return b;
}

/**
 * bwrite - Write a buffer's content to disk.
 * Buffer must be locked.
 */
void bwrite(struct buf *b) {
    if (b->lock.holder != proc_current()) {
        panic("bwrite: buffer not held by current process");
    }
    b->flags &= ~B_DIRTY;
    blkdev_write(b->dev, (uint64_t)b->blockno * (4096 / b->dev->sector_size),
                 b->data, 4096 / b->dev->sector_size);
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
