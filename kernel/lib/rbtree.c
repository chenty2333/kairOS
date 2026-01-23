/**
 * rbtree.c - Red-Black Tree Implementation
 *
 * Based on Linux kernel implementation.
 * Used by CFS scheduler for O(log n) process management.
 *
 * Red-Black Tree Properties:
 * 1. Every node is either red or black
 * 2. Root is black
 * 3. Every leaf (NULL) is black
 * 4. Red nodes have only black children
 * 5. All paths from node to leaves have same black count
 */

#include <kairos/rbtree.h>

#define RB_RED      0
#define RB_BLACK    1

#define __rb_color(pc)      ((pc) & 1)
#define __rb_is_black(pc)   __rb_color(pc)
#define __rb_is_red(pc)     (!__rb_color(pc))
#define rb_color(rb)        __rb_color((rb)->__rb_parent_color)
#define rb_is_red(rb)       __rb_is_red((rb)->__rb_parent_color)
#define rb_is_black(rb)     __rb_is_black((rb)->__rb_parent_color)

static inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
    rb->__rb_parent_color = rb_color(rb) | (unsigned long)p;
}

static inline void rb_set_parent_color(struct rb_node *rb,
                                       struct rb_node *p, int color)
{
    rb->__rb_parent_color = (unsigned long)p | color;
}

static inline void __rb_change_child(struct rb_node *old, struct rb_node *new,
                                     struct rb_node *parent,
                                     struct rb_root *root)
{
    if (parent) {
        if (parent->rb_left == old) {
            parent->rb_left = new;
        } else {
            parent->rb_right = new;
        }
    } else {
        root->rb_node = new;
    }
}

static inline void __rb_rotate_set_parents(struct rb_node *old,
                                           struct rb_node *new,
                                           struct rb_root *root, int color)
{
    struct rb_node *parent = rb_parent(old);
    new->__rb_parent_color = old->__rb_parent_color;
    rb_set_parent_color(old, new, color);
    __rb_change_child(old, new, parent, root);
}

/**
 * rb_insert_color - Rebalance tree after insertion
 * @node: the newly inserted node
 * @root: the tree root
 *
 * The caller must set up the node's parent and color (red) before calling.
 */
void rb_insert_color(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *parent = rb_parent(node);
    struct rb_node *gparent, *tmp;

    while (true) {
        /*
         * Loop invariant: node is red.
         */
        if (!parent) {
            /*
             * Case 1: node is root
             * Make it black.
             */
            rb_set_parent_color(node, NULL, RB_BLACK);
            break;
        }

        /*
         * If parent is black, we're done.
         * Red parent means grandparent exists (since root is black).
         */
        if (rb_is_black(parent)) {
            break;
        }

        gparent = rb_parent(parent);

        tmp = gparent->rb_right;
        if (parent != tmp) {
            /* parent == gparent->rb_left */
            if (tmp && rb_is_red(tmp)) {
                /*
                 * Case 2: Uncle is red
                 * Recolor and move up.
                 */
                rb_set_parent_color(tmp, gparent, RB_BLACK);
                rb_set_parent_color(parent, gparent, RB_BLACK);
                node = gparent;
                parent = rb_parent(node);
                rb_set_parent_color(node, parent, RB_RED);
                continue;
            }

            tmp = parent->rb_right;
            if (node == tmp) {
                /*
                 * Case 3: Node is right child
                 * Left rotate at parent.
                 */
                tmp = node->rb_left;
                parent->rb_right = tmp;
                node->rb_left = parent;
                if (tmp) {
                    rb_set_parent_color(tmp, parent, RB_BLACK);
                }
                rb_set_parent_color(parent, node, RB_RED);
                parent = node;
                tmp = node->rb_right;
            }

            /*
             * Case 4: Node is left child
             * Right rotate at grandparent.
             */
            gparent->rb_left = tmp;
            parent->rb_right = gparent;
            if (tmp) {
                rb_set_parent_color(tmp, gparent, RB_BLACK);
            }
            __rb_rotate_set_parents(gparent, parent, root, RB_RED);
            break;
        } else {
            /* parent == gparent->rb_right */
            tmp = gparent->rb_left;
            if (tmp && rb_is_red(tmp)) {
                /* Case 2: Uncle is red */
                rb_set_parent_color(tmp, gparent, RB_BLACK);
                rb_set_parent_color(parent, gparent, RB_BLACK);
                node = gparent;
                parent = rb_parent(node);
                rb_set_parent_color(node, parent, RB_RED);
                continue;
            }

            tmp = parent->rb_left;
            if (node == tmp) {
                /* Case 3: Node is left child - right rotate at parent */
                tmp = node->rb_right;
                parent->rb_left = tmp;
                node->rb_right = parent;
                if (tmp) {
                    rb_set_parent_color(tmp, parent, RB_BLACK);
                }
                rb_set_parent_color(parent, node, RB_RED);
                parent = node;
                tmp = node->rb_left;
            }

            /* Case 4: Node is right child - left rotate at grandparent */
            gparent->rb_right = tmp;
            parent->rb_left = gparent;
            if (tmp) {
                rb_set_parent_color(tmp, gparent, RB_BLACK);
            }
            __rb_rotate_set_parents(gparent, parent, root, RB_RED);
            break;
        }
    }
}

/**
 * Helper for rb_erase - rebalance after removing a black node
 */
static void __rb_erase_color(struct rb_node *parent, struct rb_root *root)
{
    struct rb_node *node = NULL, *sibling, *tmp1, *tmp2;

    while (true) {
        /*
         * Loop invariants:
         * - node is black (or NULL on first iteration)
         * - node is not root
         * - All paths through parent have one fewer black node
         */
        sibling = parent->rb_right;
        if (node != sibling) {
            /* node == parent->rb_left */
            if (rb_is_red(sibling)) {
                /*
                 * Case 1: Sibling is red
                 * Left rotate at parent.
                 */
                tmp1 = sibling->rb_left;
                parent->rb_right = tmp1;
                sibling->rb_left = parent;
                rb_set_parent_color(tmp1, parent, RB_BLACK);
                __rb_rotate_set_parents(parent, sibling, root, RB_RED);
                sibling = tmp1;
            }

            tmp1 = sibling->rb_right;
            if (!tmp1 || rb_is_black(tmp1)) {
                tmp2 = sibling->rb_left;
                if (!tmp2 || rb_is_black(tmp2)) {
                    /*
                     * Case 2: Sibling's children are black
                     * Recolor sibling red.
                     */
                    rb_set_parent_color(sibling, parent, RB_RED);
                    if (rb_is_red(parent)) {
                        rb_set_parent_color(parent, rb_parent(parent), RB_BLACK);
                    } else {
                        node = parent;
                        parent = rb_parent(node);
                        if (parent) {
                            continue;
                        }
                    }
                    break;
                }

                /*
                 * Case 3: Sibling's left child is red
                 * Right rotate at sibling.
                 */
                tmp1 = tmp2->rb_right;
                sibling->rb_left = tmp1;
                tmp2->rb_right = sibling;
                parent->rb_right = tmp2;
                if (tmp1) {
                    rb_set_parent_color(tmp1, sibling, RB_BLACK);
                }
                tmp1 = sibling;
                sibling = tmp2;
            }

            /*
             * Case 4: Sibling's right child is red
             * Left rotate at parent.
             */
            tmp2 = sibling->rb_left;
            parent->rb_right = tmp2;
            sibling->rb_left = parent;
            rb_set_parent_color(tmp1, sibling, RB_BLACK);
            if (tmp2) {
                rb_set_parent(tmp2, parent);
            }
            __rb_rotate_set_parents(parent, sibling, root, RB_BLACK);
            break;
        } else {
            /* node == parent->rb_right */
            sibling = parent->rb_left;
            if (rb_is_red(sibling)) {
                /* Case 1: Sibling is red */
                tmp1 = sibling->rb_right;
                parent->rb_left = tmp1;
                sibling->rb_right = parent;
                rb_set_parent_color(tmp1, parent, RB_BLACK);
                __rb_rotate_set_parents(parent, sibling, root, RB_RED);
                sibling = tmp1;
            }

            tmp1 = sibling->rb_left;
            if (!tmp1 || rb_is_black(tmp1)) {
                tmp2 = sibling->rb_right;
                if (!tmp2 || rb_is_black(tmp2)) {
                    /* Case 2 */
                    rb_set_parent_color(sibling, parent, RB_RED);
                    if (rb_is_red(parent)) {
                        rb_set_parent_color(parent, rb_parent(parent), RB_BLACK);
                    } else {
                        node = parent;
                        parent = rb_parent(node);
                        if (parent) {
                            continue;
                        }
                    }
                    break;
                }

                /* Case 3 */
                tmp1 = tmp2->rb_left;
                sibling->rb_right = tmp1;
                tmp2->rb_left = sibling;
                parent->rb_left = tmp2;
                if (tmp1) {
                    rb_set_parent_color(tmp1, sibling, RB_BLACK);
                }
                tmp1 = sibling;
                sibling = tmp2;
            }

            /* Case 4 */
            tmp2 = sibling->rb_right;
            parent->rb_left = tmp2;
            sibling->rb_right = parent;
            rb_set_parent_color(tmp1, sibling, RB_BLACK);
            if (tmp2) {
                rb_set_parent(tmp2, parent);
            }
            __rb_rotate_set_parents(parent, sibling, root, RB_BLACK);
            break;
        }
    }
}

/**
 * rb_erase - Remove a node from the tree
 * @node: the node to remove
 * @root: the tree root
 */
void rb_erase(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *child = node->rb_right;
    struct rb_node *tmp = node->rb_left;
    struct rb_node *parent, *rebalance;
    unsigned long pc;

    if (!tmp) {
        /*
         * Case 1: Node has at most one child (right).
         * Replace node with its right child.
         */
        pc = node->__rb_parent_color;
        parent = rb_parent(node);
        __rb_change_child(node, child, parent, root);
        if (child) {
            child->__rb_parent_color = pc;
            rebalance = NULL;
        } else {
            rebalance = __rb_is_black(pc) ? parent : NULL;
        }
    } else if (!child) {
        /*
         * Case 2: Node has only left child.
         * Replace node with its left child.
         */
        pc = node->__rb_parent_color;
        parent = rb_parent(node);
        tmp->__rb_parent_color = pc;
        __rb_change_child(node, tmp, parent, root);
        rebalance = NULL;
    } else {
        /*
         * Case 3: Node has two children.
         * Find successor (leftmost in right subtree).
         */
        struct rb_node *successor = child, *child2;

        tmp = child->rb_left;
        if (!tmp) {
            /*
             * Successor is node's immediate right child.
             */
            parent = successor;
            child2 = successor->rb_right;
        } else {
            /*
             * Find leftmost node in right subtree.
             */
            do {
                parent = successor;
                successor = tmp;
                tmp = tmp->rb_left;
            } while (tmp);

            child2 = successor->rb_right;
            parent->rb_left = child2;
            successor->rb_right = child;
            rb_set_parent(child, successor);
        }

        /* Transplant successor */
        tmp = node->rb_left;
        successor->rb_left = tmp;
        rb_set_parent(tmp, successor);

        pc = node->__rb_parent_color;
        tmp = rb_parent(node);
        __rb_change_child(node, successor, tmp, root);

        if (child2) {
            rb_set_parent_color(child2, parent, RB_BLACK);
            rebalance = NULL;
        } else {
            rebalance = rb_is_black(successor) ? parent : NULL;
        }
        successor->__rb_parent_color = pc;
    }

    if (rebalance) {
        __rb_erase_color(rebalance, root);
    }
}

/**
 * rb_first - Find the leftmost (minimum) node
 * @root: the tree root
 *
 * Returns NULL if tree is empty.
 */
struct rb_node *rb_first(const struct rb_root *root)
{
    struct rb_node *n = root->rb_node;

    if (!n) {
        return NULL;
    }

    while (n->rb_left) {
        n = n->rb_left;
    }

    return n;
}

/**
 * rb_last - Find the rightmost (maximum) node
 * @root: the tree root
 *
 * Returns NULL if tree is empty.
 */
struct rb_node *rb_last(const struct rb_root *root)
{
    struct rb_node *n = root->rb_node;

    if (!n) {
        return NULL;
    }

    while (n->rb_right) {
        n = n->rb_right;
    }

    return n;
}

/**
 * rb_next - Find the successor of a node
 * @node: the node
 *
 * Returns NULL if node is the maximum.
 */
struct rb_node *rb_next(const struct rb_node *node)
{
    struct rb_node *parent;

    if (!node) {
        return NULL;
    }

    /*
     * If we have a right child, the next node is the leftmost
     * node in the right subtree.
     */
    if (node->rb_right) {
        node = node->rb_right;
        while (node->rb_left) {
            node = node->rb_left;
        }
        return (struct rb_node *)node;
    }

    /*
     * Otherwise, we need to go up. Go up through ancestors where
     * we're on the right, until we find one where we're on the left.
     */
    while ((parent = rb_parent(node)) && node == parent->rb_right) {
        node = parent;
    }

    return parent;
}

/**
 * rb_prev - Find the predecessor of a node
 * @node: the node
 *
 * Returns NULL if node is the minimum.
 */
struct rb_node *rb_prev(const struct rb_node *node)
{
    struct rb_node *parent;

    if (!node) {
        return NULL;
    }

    /*
     * If we have a left child, the previous node is the rightmost
     * node in the left subtree.
     */
    if (node->rb_left) {
        node = node->rb_left;
        while (node->rb_right) {
            node = node->rb_right;
        }
        return (struct rb_node *)node;
    }

    /*
     * Otherwise, go up through ancestors where we're on the left,
     * until we find one where we're on the right.
     */
    while ((parent = rb_parent(node)) && node == parent->rb_left) {
        node = parent;
    }

    return parent;
}

/**
 * rb_replace_node - Replace a node with another
 * @victim: the node to replace
 * @new: the replacement node
 * @root: the tree root
 *
 * The replacement takes victim's position in the tree.
 * The caller is responsible for updating any references to victim.
 */
void rb_replace_node(struct rb_node *victim, struct rb_node *new,
                     struct rb_root *root)
{
    struct rb_node *parent = rb_parent(victim);

    /* Update parent's child pointer */
    __rb_change_child(victim, new, parent, root);

    /* Copy victim's links to new */
    if (victim->rb_left) {
        rb_set_parent(victim->rb_left, new);
    }
    if (victim->rb_right) {
        rb_set_parent(victim->rb_right, new);
    }

    /* Copy the entire node structure */
    *new = *victim;
}
