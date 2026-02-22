/**
 * kernel/core/mm/kmalloc.c - Generic SLUB Allocator
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/types.h>

#define KMALLOC_BATCH 16
#define KMALLOC_LIMIT 32

struct kmem_cache {
    char name[32];
    size_t obj_size;
    void (*ctor)(void *);
    void *freelist;
    size_t num_free, num_allocated;
    spinlock_t lock;

    struct {
        void *entries[KMALLOC_LIMIT];
        int count;
    } pcp[CONFIG_MAX_CPUS];
};

/* Generic kmalloc size classes */
static const size_t kmalloc_sizes[] = {32,  64,  96,   128, 192,
                                       256, 512, 1024, 2048};
#define NUM_KMALLOC_CACHES ARRAY_SIZE(kmalloc_sizes)
static struct kmem_cache *kmalloc_caches[NUM_KMALLOC_CACHES];
static uint8_t kmalloc_bootstrap[4096 * 16];
static size_t kmalloc_bootstrap_off;

/* --- Internal Core --- */

static int cache_grow(struct kmem_cache *c) {
    spin_unlock(&c->lock);
    struct page *pg = alloc_page();
    spin_lock(&c->lock);
    if (!pg)
        return -ENOMEM;

    pg->flags |= PG_SLAB;
    pg->list.prev = (struct list_head *)c;
    pmm_debug_mark_slab_page(pg, true);

    uint8_t *base = (uint8_t *)phys_to_virt(page_to_phys(pg));
    for (size_t i = 0; i < CONFIG_PAGE_SIZE / c->obj_size; i++) {
        void *obj = base + i * c->obj_size;
        if (c->ctor)
            c->ctor(obj);
        *(void **)obj = c->freelist;
        c->freelist = obj;
    }
    c->num_free += CONFIG_PAGE_SIZE / c->obj_size;
    return 0;
}

static void *kmalloc_bootstrap_alloc(size_t size) {
    size = ALIGN_UP(size, sizeof(void *));
    if (kmalloc_bootstrap_off + size > sizeof(kmalloc_bootstrap))
        return NULL;
    void *ptr = &kmalloc_bootstrap[kmalloc_bootstrap_off];
    kmalloc_bootstrap_off += size;
    return ptr;
}

struct kmem_cache *kmem_cache_create(const char *name, size_t size,
                                     void (*ctor)(void *)) {
    struct kmem_cache *c = kmalloc(sizeof(*c));
    if (!c)
        return NULL;

    memset(c, 0, sizeof(*c));
    strncpy(c->name, name, sizeof(c->name) - 1);
    c->obj_size = MAX(size, sizeof(void *));
    c->ctor = ctor;
    spin_init(&c->lock);
    return c;
}

void *kmem_cache_alloc(struct kmem_cache *c) {
    bool irq = arch_irq_save();
    int cpu = arch_cpu_id();
    if (unlikely(cpu < 0 || cpu >= CONFIG_MAX_CPUS))
        cpu = 0;

    if (unlikely(c->pcp[cpu].count == 0)) {
        spin_lock(&c->lock);
        if (!c->freelist && cache_grow(c) < 0) {
            spin_unlock(&c->lock);
            arch_irq_restore(irq);
            return NULL;
        }
        while (c->pcp[cpu].count < KMALLOC_BATCH && c->freelist) {
            void *obj = c->freelist;
            c->freelist = *(void **)obj;
            c->pcp[cpu].entries[c->pcp[cpu].count++] = obj;
            c->num_free--;
            c->num_allocated++;
        }
        spin_unlock(&c->lock);
    }

    void *obj = (c->pcp[cpu].count > 0)
                    ? c->pcp[cpu].entries[--c->pcp[cpu].count]
                    : NULL;
    arch_irq_restore(irq);
    return obj;
}

void kmem_cache_free(struct kmem_cache *c, void *obj) {
    if (!obj)
        return;
    bool irq = arch_irq_save();
    int cpu = arch_cpu_id();
    if (unlikely(cpu < 0 || cpu >= CONFIG_MAX_CPUS))
        cpu = 0;

    if (unlikely(c->pcp[cpu].count >= KMALLOC_LIMIT)) {
        spin_lock(&c->lock);
        for (int i = 0; i < KMALLOC_BATCH; i++) {
            void *o = c->pcp[cpu].entries[--c->pcp[cpu].count];
            *(void **)o = c->freelist;
            c->freelist = o;
            c->num_free++;
            c->num_allocated--;
        }
        spin_unlock(&c->lock);
    }
    c->pcp[cpu].entries[c->pcp[cpu].count++] = obj;
    arch_irq_restore(irq);
}

/* --- kmalloc/kfree Wrappers --- */

void *kmalloc(size_t size) {
    if (unlikely(!size))
        return NULL;
    if (size > 2048) {
        unsigned int order = 0;
        while (((size_t)CONFIG_PAGE_SIZE << order) < size)
            order++;
        struct page *pg = alloc_pages(order);
        return pg ? (void *)phys_to_virt(page_to_phys(pg)) : NULL;
    }

    for (size_t i = 0; i < NUM_KMALLOC_CACHES; i++) {
        if (size <= kmalloc_sizes[i])
            return kmem_cache_alloc(kmalloc_caches[i]);
    }
    return NULL;
}

void kfree(void *ptr) {
    if (!ptr)
        return;
    struct page *pg = phys_to_page(virt_to_phys(ptr));
    if (unlikely(!pg))
        return;

    if (!(pg->flags & PG_SLAB)) {
        free_pages(pg, pg->order);
        return;
    }
    kmem_cache_free((struct kmem_cache *)pg->list.prev, ptr);
}

void kmalloc_init(void) {
    for (size_t i = 0; i < NUM_KMALLOC_CACHES; i++) {
        /* We use a specialized create boot logic to avoid recursion */
        kmalloc_caches[i] = kmalloc_bootstrap_alloc(sizeof(struct kmem_cache));
        if (!kmalloc_caches[i]) {
            panic("kmalloc: bootstrap buffer too small");
        }
        memset(kmalloc_caches[i], 0, sizeof(struct kmem_cache));
        kmalloc_caches[i]->obj_size = kmalloc_sizes[i];
        spin_init(&kmalloc_caches[i]->lock);
    }
    pr_info("kmalloc: %lu classes init\n", NUM_KMALLOC_CACHES);
}

void *kzalloc(size_t size) {
    void *ptr = kmalloc(size);
    if (ptr)
        memset(ptr, 0, size);
    return ptr;
}

void *kmalloc_aligned(size_t size, size_t align) {
    if (!size)
        return NULL;
    if (align < sizeof(void *))
        align = sizeof(void *);
    if ((align & (align - 1)) != 0)
        return NULL;
    if (align <= sizeof(void *))
        return kmalloc(size);

    size_t total = size + align - 1 + sizeof(void *);
    void *raw = kmalloc(total);
    if (!raw)
        return NULL;

    uintptr_t base = (uintptr_t)raw + sizeof(void *);
    uintptr_t aligned = ALIGN_UP(base, align);
    ((void **)aligned)[-1] = raw;
    return (void *)aligned;
}

void kfree_aligned(void *ptr) {
    if (!ptr)
        return;
    void *raw = ((void **)ptr)[-1];
    if (!raw)
        raw = ptr;
    kfree(raw);
}
