/**
 * kairos/rbtree.h - Red-Black Tree
 *
 * Based on Linux kernel implementation.
 * Used by CFS scheduler for O(log n) process management.
 */

#ifndef _KAIROS_RBTREE_H
#define _KAIROS_RBTREE_H

#include <kairos/types.h>

struct rb_node {
    unsigned long __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));

struct rb_root {
    struct rb_node *rb_node;
};

#define RB_ROOT     (struct rb_root) { NULL }

#define rb_parent(r)    ((struct rb_node *)((r)->__rb_parent_color & ~3))

#define rb_entry(ptr, type, member) container_of(ptr, type, member)

/* Returns true if tree is empty */
static inline bool rb_empty(const struct rb_root *root)
{
    return root->rb_node == NULL;
}

/*
 * Core operations - implemented in lib/rbtree.c
 */

/* Insert node (caller must set up the key comparison) */
void rb_insert_color(struct rb_node *node, struct rb_root *root);

/* Remove node */
void rb_erase(struct rb_node *node, struct rb_root *root);

/* Find leftmost (minimum) node */
struct rb_node *rb_first(const struct rb_root *root);

/* Find rightmost (maximum) node */
struct rb_node *rb_last(const struct rb_root *root);

/* Find next node */
struct rb_node *rb_next(const struct rb_node *node);

/* Find previous node */
struct rb_node *rb_prev(const struct rb_node *node);

/* Replace a node (for rebalancing) */
void rb_replace_node(struct rb_node *victim, struct rb_node *new,
                     struct rb_root *root);

/*
 * Helper for linking a new node
 * Call this to set up parent/child pointers before rb_insert_color
 */
static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,
                                struct rb_node **link)
{
    node->__rb_parent_color = (unsigned long)parent;
    node->rb_left = node->rb_right = NULL;
    *link = node;
}

/*
 * Iteration macros
 */

#define rb_for_each(pos, root) \
    for (pos = rb_first(root); pos; pos = rb_next(pos))

#define rb_for_each_entry(pos, root, member) \
    for (pos = rb_first(root) ? rb_entry(rb_first(root), typeof(*pos), member) : NULL; \
         pos; \
         pos = rb_next(&pos->member) ? rb_entry(rb_next(&pos->member), typeof(*pos), member) : NULL)

#endif /* _KAIROS_RBTREE_H */
