/**
 * kernel/fs/vfs/dentry.c - Dentry cache (skeleton)
 */

#include <kairos/dentry.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/vfs.h>

#define DCACHE_HASH_BITS 8
#define DCACHE_HASH_SIZE (1u << DCACHE_HASH_BITS)

static struct kmem_cache *dentry_cache;
static struct list_head dentry_hash[DCACHE_HASH_SIZE];
static struct list_head dentry_lru;
static struct mutex dcache_lock;
static size_t dcache_count;

static void dcache_evict(void);

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
    return h & (DCACHE_HASH_SIZE - 1u);
}

void dentry_init(void) {
    if (!dentry_cache)
        dentry_cache = kmem_cache_create("dentry", sizeof(struct dentry), NULL);
    for (size_t i = 0; i < DCACHE_HASH_SIZE; i++)
        INIT_LIST_HEAD(&dentry_hash[i]);
    INIT_LIST_HEAD(&dentry_lru);
    dcache_count = 0;
    mutex_init(&dcache_lock, "dcache");
}

static void dentry_init_struct(struct dentry *d) {
    memset(d, 0, sizeof(*d));
    atomic_init(&d->refcount, 1);
    INIT_LIST_HEAD(&d->children);
    INIT_LIST_HEAD(&d->child);
    INIT_LIST_HEAD(&d->hash);
    INIT_LIST_HEAD(&d->lru);
    d->hashed = false;
    mutex_init(&d->lock, "dentry");
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
    }
    if (name && name[0]) {
        strncpy(d->name, name, sizeof(d->name) - 1);
        d->name[sizeof(d->name) - 1] = '\0';
    }
    return d;
}

void dentry_get(struct dentry *d) {
    if (!d)
        return;
    WARN_ON(atomic_read(&d->refcount) == 0);
    atomic_inc(&d->refcount);
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
    if (!d)
        return;
    uint32_t old = atomic_read(&d->refcount);
    if (old == 0)
        panic("dentry_put: refcount underflow on dentry '%s'", d->name);
    old = atomic_fetch_sub(&d->refcount, 1);
    if (old == 1) {
        struct dentry *parent = d->parent;
        struct vnode *vn = d->vnode;
        d->parent = NULL;
        d->vnode = NULL;
        dentry_unhash(d);
        if (vn)
            vnode_put(vn);
        if (parent)
            dentry_put(parent);
        kmem_cache_free(dentry_cache, d);
    }
}

struct dentry *dentry_lookup(struct dentry *parent, const char *name,
                             struct mount *mnt) {
    if (!name)
        return NULL;
    uint32_t idx = dcache_hash_key(parent, name, mnt);
    mutex_lock(&dcache_lock);
    struct dentry *d;
    list_for_each_entry(d, &dentry_hash[idx], hash) {
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
    uint32_t idx = dcache_hash_key(d->parent, d->name, d->mnt);
    mutex_lock(&dcache_lock);
    if (!d->hashed) {
        list_add(&d->hash, &dentry_hash[idx]);
        list_add(&d->lru, &dentry_lru);
        d->hashed = true;
        dentry_get(d);
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
        /* Atomically transition refcount 1→0 to close the TOCTOU window.
         * If another thread grabbed a reference after we released d->lock,
         * the cmpxchg fails and we simply skip this dentry. */
        uint32_t expected = 1;
        if (!atomic_cmpxchg(&d->refcount, &expected, 0)) {
            list_del(&d->lru);
            list_add(&d->lru, &dentry_lru);
            continue;
        }
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
        d->parent = NULL;
        d->vnode = NULL;
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
    if (vn)
        vnode_get(vn);
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

void dentry_move(struct dentry *d, struct dentry *new_parent,
                 const char *new_name) {
    if (!d || !new_parent || !new_name || !new_name[0])
        return;
    dentry_unhash(d);
    mutex_lock(&d->lock);
    if (d->parent) {
        dentry_put(d->parent);
        d->parent = NULL;
    }
    d->parent = new_parent;
    dentry_get(new_parent);
    strncpy(d->name, new_name, sizeof(d->name) - 1);
    d->name[sizeof(d->name) - 1] = '\0';
    mutex_unlock(&d->lock);
    if (d->vnode && new_parent->vnode) {
        rwlock_write_lock(&d->vnode->lock);
        vnode_set_parent(d->vnode, new_parent->vnode, new_name);
        rwlock_write_unlock(&d->vnode->lock);
    }
    dentry_hash_insert(d);
}
