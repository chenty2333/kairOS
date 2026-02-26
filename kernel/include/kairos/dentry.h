/**
 * kernel/include/kairos/dentry.h - Dentry cache (skeleton)
 */

#ifndef _KAIROS_DENTRY_H
#define _KAIROS_DENTRY_H

#include <kairos/atomic.h>
#include <kairos/config.h>
#include <kairos/handle.h>
#include <kairos/list.h>
#include <kairos/sync.h>
#include <kairos/types.h>

struct vnode;
struct mount;

#define VFS_KOBJ_TYPE_DENTRY 0x101U

enum dentry_flags {
    DENTRY_NEGATIVE = 1u << 0,
    DENTRY_MOUNTPOINT = 1u << 1,
};

struct dentry {
    struct dentry *parent;
    struct vnode *vnode;
    struct mount *mnt;
    struct mount *mounted;
    uint32_t flags;
    atomic_t refcount;
    uint64_t neg_expire;
    char name[CONFIG_NAME_MAX];
    struct list_head children;
    struct list_head child;
    struct list_head hash;
    struct list_head lru;
    bool hashed;
    struct mutex lock;
    struct kobj *kobj;
    atomic_t kobj_state;
};

struct path {
    struct mount *mnt;
    struct dentry *dentry;
};

void dentry_init(void);
struct dentry *dentry_alloc(struct dentry *parent, const char *name);
void dentry_get(struct dentry *d);
void dentry_put(struct dentry *d);
struct dentry *dentry_lookup(struct dentry *parent, const char *name,
                             struct mount *mnt);
void dentry_add(struct dentry *d, struct vnode *vn);
void dentry_add_negative(struct dentry *d);
void dentry_drop(struct dentry *d);
void dentry_move(struct dentry *d, struct dentry *new_parent,
                 const char *new_name);
struct kobj *dentry_kobj(struct dentry *d);
struct dentry *dentry_from_kobj(struct kobj *obj);

static inline void path_init(struct path *path) {
    if (path) {
        path->mnt = NULL;
        path->dentry = NULL;
    }
}

#endif
