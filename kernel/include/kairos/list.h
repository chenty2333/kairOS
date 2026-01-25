/**
 * kernel/include/kairos/list.h - Doubly linked list
 */

#ifndef _KAIROS_LIST_H
#define _KAIROS_LIST_H

#include <kairos/types.h>

struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) {&(name), &(name)}
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list) {
    list->next = list->prev = list;
}

static inline void __list_add(struct list_head *n, struct list_head *prev,
                              struct list_head *next) {
    next->prev = n;
    n->next = next;
    n->prev = prev;
    prev->next = n;
}

static inline void list_add(struct list_head *n, struct list_head *h) {
    __list_add(n, h, h->next);
}

static inline void list_add_tail(struct list_head *n, struct list_head *h) {
    __list_add(n, h->prev, h);
}

static inline void list_del(struct list_head *e) {
    e->next->prev = e->prev;
    e->prev->next = e->next;
    e->next = e->prev = NULL;
}

static inline bool list_empty(const struct list_head *h) {
    return h->next == h;
}

#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(ptr, type, member)                                    \
    list_entry((ptr)->next, type, member)

#define list_for_each(pos, head)                                               \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head)                                       \
    for (pos = (head)->next, n = pos->next; pos != (head);                     \
         pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)                                 \
    for (pos = list_entry((head)->next, typeof(*pos), member);                 \
         &pos->member != (head);                                               \
         pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_reverse(pos, head, member)                         \
    for (pos = list_entry((head)->prev, typeof(*pos), member);                 \
         &pos->member != (head);                                               \
         pos = list_entry(pos->member.prev, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)                         \
    for (pos = list_entry((head)->next, typeof(*pos), member),                 \
        n = list_entry(pos->member.next, typeof(*pos), member);                \
         &pos->member != (head);                                               \
         pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif