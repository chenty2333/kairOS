/**
 * kernel/fs/vfs/dentry.c - Dentry cache (skeleton)
 */

#include <kairos/dentry.h>
#include <kairos/arch.h>
#include <kairos/hashtable.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/vfs.h>

#define DCACHE_HASH_BITS 8
#define DCACHE_HASH_SIZE (1u << DCACHE_HASH_BITS)
#define DENTRY_KOBJ_STATE_UNINIT  0U
#define DENTRY_KOBJ_STATE_INITING 1U
#define DENTRY_KOBJ_STATE_READY   2U
#define DENTRY_KOBJ_STATE_FAILED  3U

static struct kmem_cache *dentry_cache;
KHASH_DECLARE(dentry_hash, DCACHE_HASH_BITS);
static struct list_head dentry_lru;
static struct mutex dcache_lock;
static size_t dcache_count;

static void dcache_evict(void);
static void dentry_kobj_init(struct dentry *d);
static inline bool dentry_kobj_is_ready(struct dentry *d);
static void dentry_attach_child(struct dentry *parent, struct dentry *child);
static void dentry_detach_child(struct dentry *parent, struct dentry *child);
static void dentry_hash_reinsert_preserve_ref(struct dentry *d);

struct dentry_kobj_bridge {
    struct kobj obj;
    struct dentry *owner;
};

static void dentry_kobj_release(struct kobj *obj) {
    if (!obj)
        return;
    kfree((struct dentry_kobj_bridge *)obj);
}

static const struct kobj_ops dentry_kobj_ops = {
    .release = dentry_kobj_release,
};

static inline struct dentry *dentry_lru_last(void) {
    return list_entry(dentry_lru.prev, struct dentry, lru);
}

static uint32_t dcache_hash_key(struct dentry *parent, const char *name,
                                struct mount *mnt) {
    uint32_t h = (uint32_t)((uintptr_t)parent >> 4);
    h ^= (uint32_t)((uintptr_t)mnt >> 4);
    while (name && *name) {
        h = (h * 33u) ^ (uint8_t)(*name++);
    }
    return h;
}

void dentry_init(void) {
    if (!dentry_cache)
        dentry_cache = kmem_cache_create("dentry", sizeof(struct dentry), NULL);
    KHASH_INIT(dentry_hash);
    INIT_LIST_HEAD(&dentry_lru);
    dcache_count = 0;
    mutex_init(&dcache_lock, "dcache");
}

static void dentry_init_struct(struct dentry *d) {
    memset(d, 0, sizeof(*d));
    atomic_init(&d->refcount, 1);
    d->kobj = NULL;
    atomic_init(&d->kobj_state, DENTRY_KOBJ_STATE_UNINIT);
    INIT_LIST_HEAD(&d->children);
    INIT_LIST_HEAD(&d->child);
    INIT_LIST_HEAD(&d->hash);
    INIT_LIST_HEAD(&d->lru);
    d->hashed = false;
    mutex_init(&d->lock, "dentry");
}

static inline bool dentry_kobj_is_ready(struct dentry *d) {
    return d && atomic_read(&d->kobj_state) == DENTRY_KOBJ_STATE_READY &&
           d->kobj != NULL;
}

static inline void dentry_ref_get_noinit(struct dentry *d) {
    if (!d)
        return;
    atomic_inc(&d->refcount);
    if (dentry_kobj_is_ready(d))
        kobj_get(d->kobj);
}

static void dentry_attach_child(struct dentry *parent, struct dentry *child) {
    if (!parent || !child)
        return;
    mutex_lock(&parent->lock);
    list_add_tail(&child->child, &parent->children);
    mutex_unlock(&parent->lock);
}

static void dentry_detach_child(struct dentry *parent, struct dentry *child) {
    if (!parent || !child)
        return;
    mutex_lock(&parent->lock);
    list_del(&child->child);
    mutex_unlock(&parent->lock);
}

static void dentry_hash_reinsert_preserve_ref(struct dentry *d) {
    if (!d || d->hashed)
        return;
    uint32_t key = dcache_hash_key(d->parent, d->name, d->mnt);
    mutex_lock(&dcache_lock);
    if (!d->hashed) {
        list_add(&d->hash, KHASH_HEAD_U32(dentry_hash, key));
        list_add(&d->lru, &dentry_lru);
        d->hashed = true;
        dcache_count++;
    }
    mutex_unlock(&dcache_lock);
    dcache_evict();
}

static void dentry_kobj_init(struct dentry *d) {
    if (!d)
        return;
    while (1) {
        uint32_t state = atomic_read(&d->kobj_state);
        if (state == DENTRY_KOBJ_STATE_READY)
            return;
        if (state == DENTRY_KOBJ_STATE_UNINIT) {
            uint32_t expected = DENTRY_KOBJ_STATE_UNINIT;
            if (atomic_cmpxchg(&d->kobj_state, &expected,
                               DENTRY_KOBJ_STATE_INITING)) {
                struct dentry_kobj_bridge *bridge = kzalloc(sizeof(*bridge));
                if (!bridge) {
                    atomic_set(&d->kobj_state, DENTRY_KOBJ_STATE_FAILED);
                    return;
                }
                __atomic_store_n(&bridge->owner, d, __ATOMIC_RELEASE);
                kobj_init(&bridge->obj, VFS_KOBJ_TYPE_DENTRY, &dentry_kobj_ops);
                d->kobj = &bridge->obj;
                uint32_t refs = atomic_read(&d->refcount);
                for (uint32_t i = 1; i < refs; i++)
                    kobj_get(d->kobj);
                kobj_track_register(d->kobj);
                atomic_set(&d->kobj_state, DENTRY_KOBJ_STATE_READY);
                return;
            }
            continue;
        }
        if (state == DENTRY_KOBJ_STATE_INITING) {
            arch_cpu_relax();
            continue;
        }
        if (state == DENTRY_KOBJ_STATE_FAILED)
            return;
        atomic_set(&d->kobj_state, DENTRY_KOBJ_STATE_UNINIT);
    }
}

struct kobj *dentry_kobj(struct dentry *d) {
    dentry_kobj_init(d);
    if (!dentry_kobj_is_ready(d))
        return NULL;
    return d->kobj;
}

struct dentry *dentry_from_kobj(struct kobj *obj) {
    if (!obj || obj->type != VFS_KOBJ_TYPE_DENTRY)
        return NULL;
    struct dentry_kobj_bridge *bridge = (struct dentry_kobj_bridge *)obj;
    return __atomic_load_n(&bridge->owner, __ATOMIC_ACQUIRE);
}

struct dentry *dentry_alloc(struct dentry *parent, const char *name) {
    if (!dentry_cache)
        return NULL;
    struct dentry *d = kmem_cache_alloc(dentry_cache);
    if (!d)
        return NULL;
    dentry_init_struct(d);
    if (parent) {
        d->parent = parent;
        dentry_get(parent);
        dentry_attach_child(parent, d);
    }
    if (name && name[0]) {
        strncpy(d->name, name, sizeof(d->name) - 1);
        d->name[sizeof(d->name) - 1] = '\0';
    }
    return d;
}

void dentry_set_mnt(struct dentry *d, struct mount *mnt) {
    if (!d || d->mnt == mnt)
        return;

    if (mnt)
        vfs_mount_hold(mnt);

    struct mount *old = d->mnt;
    d->mnt = mnt;

    if (old)
        vfs_mount_put(old);
}

void dentry_get(struct dentry *d) {
    if (!d)
        return;
    dentry_kobj_init(d);
    WARN_ON(atomic_read(&d->refcount) == 0);
    atomic_inc(&d->refcount);
    if (dentry_kobj_is_ready(d))
        kobj_get(d->kobj);
}

static void dentry_unhash(struct dentry *d) {
    if (!d || !d->hashed)
        return;
    mutex_lock(&dcache_lock);
    if (d->hashed) {
        list_del(&d->hash);
        list_del(&d->lru);
        d->hashed = false;
        if (dcache_count > 0)
            dcache_count--;
    }
    mutex_unlock(&dcache_lock);
}

void dentry_put(struct dentry *d) {
    while (d) {
        uint32_t state = atomic_read(&d->kobj_state);
        if (state != DENTRY_KOBJ_STATE_UNINIT)
            dentry_kobj_init(d);
        uint32_t old = atomic_read(&d->refcount);
        if (old == 0)
            panic("dentry_put: refcount underflow on dentry '%s'", d->name);
        old = atomic_fetch_sub(&d->refcount, 1);
        bool kobj_ready = dentry_kobj_is_ready(d);
        if (old == 1 && kobj_ready) {
            struct dentry_kobj_bridge *bridge =
                (struct dentry_kobj_bridge *)d->kobj;
            __atomic_store_n(&bridge->owner, NULL, __ATOMIC_RELEASE);
        }
        if (kobj_ready)
            kobj_put(d->kobj);
        if (old != 1)
            break;
        struct dentry *parent = d->parent;
        struct vnode *vn = d->vnode;
        dentry_detach_child(parent, d);
        d->parent = NULL;
        d->vnode = NULL;
        dentry_unhash(d);
        dentry_set_mnt(d, NULL);
        if (vn)
            vnode_put(vn);
        kmem_cache_free(dentry_cache, d);
        d = parent;
    }
}

struct dentry *dentry_lookup(struct dentry *parent, const char *name,
                             struct mount *mnt) {
    if (!name)
        return NULL;
    uint32_t key = dcache_hash_key(parent, name, mnt);
    mutex_lock(&dcache_lock);
    struct dentry *d;
    khash_for_each_possible_u32(dentry_hash, d, hash, key) {
        if (d->parent == parent && d->mnt == mnt &&
            strcmp(d->name, name) == 0) {
            if ((d->flags & DENTRY_NEGATIVE) && d->neg_expire) {
                uint64_t now = arch_timer_ticks();
                if (now >= d->neg_expire) {
                    list_del(&d->hash);
                    list_del(&d->lru);
                    d->hashed = false;
                    if (dcache_count > 0)
                        dcache_count--;
                    mutex_unlock(&dcache_lock);
                    dentry_put(d);
                    return NULL;
                }
            }
            dentry_get(d);
            if (d->hashed) {
                list_del(&d->lru);
                list_add(&d->lru, &dentry_lru);
            }
            mutex_unlock(&dcache_lock);
            return d;
        }
    }
    mutex_unlock(&dcache_lock);
    return NULL;
}

static void dentry_hash_insert(struct dentry *d) {
    if (!d || d->hashed)
        return;
    uint32_t key = dcache_hash_key(d->parent, d->name, d->mnt);
    mutex_lock(&dcache_lock);
    if (!d->hashed) {
        list_add(&d->hash, KHASH_HEAD_U32(dentry_hash, key));
        list_add(&d->lru, &dentry_lru);
        d->hashed = true;
        dentry_ref_get_noinit(d);
        dcache_count++;
    }
    mutex_unlock(&dcache_lock);
    dcache_evict();
}

static void dcache_evict(void) {
    struct list_head victims;
    INIT_LIST_HEAD(&victims);

    mutex_lock(&dcache_lock);
    size_t scanned = 0;
    while (dcache_count > CONFIG_DCACHE_MAX && !list_empty(&dentry_lru) &&
           scanned < dcache_count) {
        struct dentry *d = dentry_lru_last();
        scanned++;
        if (!mutex_trylock(&d->lock)) {
            list_del(&d->lru);
            list_add(&d->lru, &dentry_lru);
            continue;
        }
        bool can_evict = !(d->flags & DENTRY_MOUNTPOINT) &&
                         d->parent != NULL;
        mutex_unlock(&d->lock);
        if (!can_evict) {
            list_del(&d->lru);
            list_add(&d->lru, &dentry_lru);
            continue;
        }
        uint32_t state = atomic_read(&d->kobj_state);
        if (state != DENTRY_KOBJ_STATE_UNINIT)
            dentry_kobj_init(d);
        /* Atomically transition refcount 1→0 to close the TOCTOU window.
         * If another thread grabbed a reference after we released d->lock,
         * the cmpxchg fails and we simply skip this dentry. */
        uint32_t expected = 1;
        if (!atomic_cmpxchg(&d->refcount, &expected, 0)) {
            list_del(&d->lru);
            list_add(&d->lru, &dentry_lru);
            continue;
        }
        if (dentry_kobj_is_ready(d))
            kobj_put(d->kobj);
        /* refcount is now 0 — safe to unhash and reclaim */
        list_del(&d->hash);
        list_del(&d->lru);
        d->hashed = false;
        if (dcache_count > 0)
            dcache_count--;
        list_add(&d->lru, &victims);
    }
    mutex_unlock(&dcache_lock);

    /* Clean up victims directly — refcount is already 0, so we must NOT
     * call dentry_put (that would underflow). */
    struct dentry *d, *tmp;
    list_for_each_entry_safe(d, tmp, &victims, lru) {
        list_del(&d->lru);
        struct dentry *parent = d->parent;
        struct vnode *vn = d->vnode;
        dentry_detach_child(parent, d);
        d->parent = NULL;
        d->vnode = NULL;
        dentry_set_mnt(d, NULL);
        if (vn)
            vnode_put(vn);
        if (parent)
            dentry_put(parent);
        kmem_cache_free(dentry_cache, d);
    }
}

void dentry_add(struct dentry *d, struct vnode *vn) {
    if (!d)
        return;
    mutex_lock(&d->lock);
    d->vnode = vn;
    d->flags &= ~DENTRY_NEGATIVE;
    d->neg_expire = 0;
    mutex_unlock(&d->lock);
    if (vn) {
        vnode_kobj_init(vn);
        vnode_get(vn);
    }
    dentry_hash_insert(d);
}

void dentry_add_negative(struct dentry *d) {
    if (!d)
        return;
    mutex_lock(&d->lock);
    d->vnode = NULL;
    d->flags |= DENTRY_NEGATIVE;
    if (CONFIG_DCACHE_NEG_TTL_SEC) {
        uint64_t delta =
            arch_timer_ns_to_ticks(CONFIG_DCACHE_NEG_TTL_SEC * 1000000000ULL);
        d->neg_expire = arch_timer_ticks() + delta;
    } else {
        d->neg_expire = 0;
    }
    mutex_unlock(&d->lock);
    dentry_hash_insert(d);
}

void dentry_drop(struct dentry *d) {
    if (!d)
        return;
    if (d->hashed) {
        dentry_unhash(d);
        dentry_put(d);
    }
}

void dentry_prune_mount(struct mount *mnt) {
    if (!mnt)
        return;

    struct list_head victims;
    INIT_LIST_HEAD(&victims);

    mutex_lock(&dcache_lock);
    for (size_t i = 0; i < DCACHE_HASH_SIZE; i++) {
        struct dentry *d, *tmp;
        list_for_each_entry_safe(d, tmp, &dentry_hash[i], hash) {
            if (d->mnt != mnt || !d->hashed)
                continue;
            if (d == mnt->root_dentry)
                continue;
            list_del(&d->hash);
            list_del(&d->lru);
            d->hashed = false;
            if (dcache_count > 0)
                dcache_count--;
            list_add_tail(&d->lru, &victims);
        }
    }
    mutex_unlock(&dcache_lock);

    struct dentry *d, *tmp;
    list_for_each_entry_safe(d, tmp, &victims, lru) {
        list_del(&d->lru);
        dentry_put(d);
    }
}

void dentry_move(struct dentry *d, struct dentry *new_parent,
                 const char *new_name) {
    if (!d || !new_parent || !new_name || !new_name[0])
        return;
    bool was_hashed = d->hashed;
    dentry_unhash(d);
    mutex_lock(&d->lock);
    if (d->parent) {
        dentry_detach_child(d->parent, d);
        dentry_put(d->parent);
        d->parent = NULL;
    }
    d->parent = new_parent;
    dentry_get(new_parent);
    dentry_attach_child(new_parent, d);
    strncpy(d->name, new_name, sizeof(d->name) - 1);
    d->name[sizeof(d->name) - 1] = '\0';
    mutex_unlock(&d->lock);
    if (d->vnode && new_parent->vnode) {
        rwlock_write_lock(&d->vnode->lock);
        vnode_set_parent(d->vnode, new_parent->vnode, new_name);
        rwlock_write_unlock(&d->vnode->lock);
    }
    if (was_hashed)
        dentry_hash_reinsert_preserve_ref(d);
    else
        dentry_hash_insert(d);
}
