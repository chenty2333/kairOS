/**
 * kairos/list.h - Doubly linked list (Linux-style)
 */

#ifndef _KAIROS_LIST_H
#define _KAIROS_LIST_H

#include <kairos/types.h>

struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __list_add(struct list_head *new,
                              struct list_head *prev,
                              struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

/* Add new entry after head */
static inline void list_add(struct list_head *new, struct list_head *head)
{
    __list_add(new, head, head->next);
}

/* Add new entry before head (at tail) */
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    __list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

/* Delete entry from list */
static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = NULL;
    entry->prev = NULL;
}

/* Check if list is empty */
static inline bool list_empty(const struct list_head *head)
{
    return head->next == head;
}

/* Get the struct containing this list entry */
#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

/* Get first entry */
#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

/* Iterate over list */
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/* Iterate over list (safe for deletion) */
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
         pos = n, n = pos->next)

/* Iterate over list entries */
#define list_for_each_entry(pos, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member))

/* Iterate over list entries (safe for deletion) */
#define list_for_each_entry_safe(pos, n, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member), \
         n = list_entry(pos->member.next, typeof(*pos), member); \
         &pos->member != (head); \
         pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif /* _KAIROS_LIST_H */
