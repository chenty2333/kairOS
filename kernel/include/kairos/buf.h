/**
 * kernel/include/kairos/buf.h - Block Buffer Cache
 */

#ifndef _KAIROS_BUF_H
#define _KAIROS_BUF_H

#include <kairos/list.h>
#include <kairos/process.h>
#include <kairos/sync.h>
#include <kairos/types.h>

#define B_VALID 0x1 /* Data has been read from disk */
#define B_DIRTY 0x2 /* Data needs to be written to disk */

struct buf {
    uint32_t flags;
    struct blkdev *dev;
    uint64_t blockno;
    uint32_t block_bytes;
    uint32_t refcount;
    struct mutex lock;
    struct list_head lru;  /* LRU list linkage */
    struct list_head hash; /* Hash table linkage */
    struct list_head dirty;
    uint8_t *data;
};

/* Core Buffer API */
void binit(void);
struct buf *bread(struct blkdev *dev, uint32_t blockno);
struct buf *breadn(struct blkdev *dev, uint64_t blockno, uint32_t block_bytes);
void bwrite(struct buf *b);
void brelse(struct buf *b);
int bsync_dev(struct blkdev *dev);
int bsync_all(void);

#endif
