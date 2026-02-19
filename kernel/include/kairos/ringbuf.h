/**
 * kernel/include/kairos/ringbuf.h - Simple ring buffer helpers
 */

#ifndef _KAIROS_RINGBUF_H
#define _KAIROS_RINGBUF_H

#include <kairos/types.h>

struct ringbuf {
    char *buf;
    uint32_t size;
    uint32_t head;
    uint32_t tail;
};

void ringbuf_init(struct ringbuf *rb, char *storage, uint32_t size);
bool ringbuf_empty(const struct ringbuf *rb);
bool ringbuf_full(const struct ringbuf *rb);
size_t ringbuf_len(const struct ringbuf *rb);
size_t ringbuf_avail(const struct ringbuf *rb);
bool ringbuf_push(struct ringbuf *rb, char c, bool overwrite);
bool ringbuf_pop(struct ringbuf *rb, char *out);

#endif
