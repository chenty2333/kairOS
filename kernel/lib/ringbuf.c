/**
 * kernel/lib/ringbuf.c - Simple ring buffer helpers
 */

#include <kairos/ringbuf.h>

void ringbuf_init(struct ringbuf *rb, char *storage, uint32_t size) {
    if (!rb)
        return;
    rb->buf = storage;
    rb->size = size;
    rb->head = 0;
    rb->tail = 0;
}

bool ringbuf_empty(const struct ringbuf *rb) {
    return !rb || rb->head == rb->tail;
}

bool ringbuf_full(const struct ringbuf *rb) {
    if (!rb || rb->size == 0)
        return true;
    return ((rb->head + 1) % rb->size) == rb->tail;
}

size_t ringbuf_len(const struct ringbuf *rb) {
    if (!rb || rb->size == 0)
        return 0;
    if (rb->head >= rb->tail)
        return rb->head - rb->tail;
    return rb->size - rb->tail + rb->head;
}

bool ringbuf_push(struct ringbuf *rb, char c, bool overwrite) {
    if (!rb || !rb->buf || rb->size == 0)
        return false;
    if (ringbuf_full(rb)) {
        if (!overwrite)
            return false;
        rb->tail = (rb->tail + 1) % rb->size;
    }
    rb->buf[rb->head] = c;
    rb->head = (rb->head + 1) % rb->size;
    return true;
}

bool ringbuf_pop(struct ringbuf *rb, char *out) {
    if (!rb || !rb->buf || !out)
        return false;
    if (ringbuf_empty(rb))
        return false;
    *out = rb->buf[rb->tail];
    rb->tail = (rb->tail + 1) % rb->size;
    return true;
}
