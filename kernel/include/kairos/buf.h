/**
 * kernel/include/kairos/buf.h - Block Buffer Cache
 */

#ifndef _KAIROS_BUF_H
#define _KAIROS_BUF_H

#include <kairos/types.h>
#include <kairos/list.h>
#include <kairos/spinlock.h>
#include <kairos/process.h>

#define B_VALID 0x1  /* Data has been read from disk */
#define B_DIRTY 0x2  /* Data needs to be written to disk */

struct buf {
    uint32_t flags;
    struct blkdev *dev;
    uint32_t blockno;
    uint32_t refcount;
    spinlock_t lock;
    struct wait_queue wq;
    struct list_head lru;  /* LRU list linkage */
    struct list_head hash; /* Hash table linkage */
    uint8_t *data;
};

/* Core Buffer API */
void binit(void);
struct buf *bread(struct blkdev *dev, uint32_t blockno);
void bwrite(struct buf *b);
void brelse(struct buf *b);

#endif
