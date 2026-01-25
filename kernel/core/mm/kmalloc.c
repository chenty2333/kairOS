/**
 * kmalloc.c - Kernel Memory Allocator
 */

#include <kairos/types.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/config.h>
#include <kairos/string.h>
#include <kairos/arch.h>

#ifdef CONFIG_SLUB_DEBUG
#define REDZONE_SIZE  sizeof(void *)
#define RZ_MAGIC      0xCC
#define POISON_MAGIC  0xA5
#else
#define REDZONE_SIZE  0
#endif

#define KMALLOC_BATCH 16
#define KMALLOC_LIMIT 32

static const size_t kmalloc_sizes[] = { 32, 64, 96, 128, 192, 256, 512, 1024, 2048 };
#define NUM_SIZE_CLASSES (sizeof(kmalloc_sizes) / sizeof(size_t))

struct size_class {
    void *freelist;
    size_t block_size;
    size_t num_free, num_allocated;
    spinlock_t lock;
};

struct kmalloc_pcp {
    void *entries[KMALLOC_LIMIT];
    int count;
};

static struct size_class size_classes[NUM_SIZE_CLASSES];
static struct kmalloc_pcp pcp_caches[NUM_SIZE_CLASSES][CONFIG_MAX_CPUS];
static spinlock_t kmalloc_lock;
static size_t total_alloc, total_freed;

/* --- Helpers --- */

static inline int size_to_class(size_t size) {
    size += REDZONE_SIZE * 2;
    for (size_t i = 0; i < NUM_SIZE_CLASSES; i++)
        if (size <= kmalloc_sizes[i]) return i;
    return -1;
}

static inline void *block_to_obj(void *block) { return (uint8_t *)block + REDZONE_SIZE; }
static inline void *obj_to_block(void *obj) { return (uint8_t *)obj - REDZONE_SIZE; }

#ifdef CONFIG_SLUB_DEBUG
static void dbg_set_rz(void *b, size_t s) {
    memset(b, RZ_MAGIC, REDZONE_SIZE);
    memset((uint8_t *)b + s - REDZONE_SIZE, RZ_MAGIC, REDZONE_SIZE);
}

static void dbg_check_rz(void *b, size_t s) {
    uint8_t *p = b, *e = (uint8_t *)b + s - REDZONE_SIZE;
    for (int i = 0; i < (int)REDZONE_SIZE; i++)
        if (p[i] != RZ_MAGIC || e[i] != RZ_MAGIC) panic("kmalloc: redzone violation at %p", b);
}
#else
#define dbg_set_rz(b, s)
#define dbg_check_rz(b, s)
#endif

/* --- Core --- */

static int grow_cache(struct size_class *sc) {
    spin_unlock(&sc->lock);
    struct page *page = alloc_page();
    spin_lock(&sc->lock);
    if (!page) return -ENOMEM;

    page->flags |= PG_SLAB;
    page->list.prev = (struct list_head *)sc;
    
    uint8_t *base = (uint8_t *)page_to_phys(page);
    for (size_t i = 0; i < CONFIG_PAGE_SIZE / sc->block_size; i++) {
        void *b = base + i * sc->block_size;
        *(void **)b = sc->freelist;
        sc->freelist = b;
    }
    sc->num_free += CONFIG_PAGE_SIZE / sc->block_size;
    return 0;
}

void *kmalloc(size_t size) {
    if (!size) return NULL;
    if (size > 2048) {
        unsigned int order = 0;
        while (((size_t)CONFIG_PAGE_SIZE << order) < size) order++;
        bool irq = arch_irq_save();
        spin_lock(&kmalloc_lock);
        struct page *p = alloc_pages(order);
        if (p) total_alloc += ((size_t)CONFIG_PAGE_SIZE << order);
        spin_unlock(&kmalloc_lock);
        arch_irq_restore(irq);
        return p ? (void *)page_to_phys(p) : NULL;
    }

    int ci = size_to_class(size);
    if (ci < 0) return NULL;
    
    struct size_class *sc = &size_classes[ci];
    struct kmalloc_pcp *pcp = &pcp_caches[ci][arch_cpu_id()];
    bool irq = arch_irq_save();

    if (pcp->count == 0) {
        spin_lock(&sc->lock);
        if (!sc->freelist && grow_cache(sc) < 0) {
            spin_unlock(&sc->lock);
            arch_irq_restore(irq);
            return NULL;
        }
        while (pcp->count < KMALLOC_BATCH && sc->freelist) {
            void *b = sc->freelist;
            sc->freelist = *(void **)b;
            pcp->entries[pcp->count++] = b;
            sc->num_free--; sc->num_allocated++;
            total_alloc += sc->block_size;
        }
        spin_unlock(&sc->lock);
    }

    if (pcp->count == 0) { arch_irq_restore(irq); return NULL; }
    void *block = pcp->entries[--pcp->count];
    arch_irq_restore(irq);
    dbg_set_rz(block, sc->block_size);
    return block_to_obj(block);
}

void kfree(void *ptr) {
    if (!ptr) return;
    struct page *p = phys_to_page((paddr_t)obj_to_block(ptr));
    if (!p) return;

    if (!(p->flags & PG_SLAB)) {
        bool irq = arch_irq_save();
        spin_lock(&kmalloc_lock);
        total_freed += ((size_t)CONFIG_PAGE_SIZE << p->order);
        free_pages(p, p->order);
        spin_unlock(&kmalloc_lock);
        arch_irq_restore(irq);
        return;
    }

    void *block = obj_to_block(ptr);
    struct size_class *sc = (struct size_class *)p->list.prev;
    dbg_check_rz(block, sc->block_size);
#ifdef CONFIG_SLUB_DEBUG
    memset(block, POISON_MAGIC, sc->block_size);
#endif

    bool irq = arch_irq_save();
    struct kmalloc_pcp *pcp = &pcp_caches[sc - size_classes][arch_cpu_id()];
    if (pcp->count >= KMALLOC_LIMIT) {
        spin_lock(&sc->lock);
        for (int i = 0; i < KMALLOC_BATCH; i++) {
            void *b = pcp->entries[--pcp->count];
            *(void **)b = sc->freelist;
            sc->freelist = b;
            sc->num_free++; sc->num_allocated--;
            total_freed += sc->block_size;
        }
        spin_unlock(&sc->lock);
    }
    pcp->entries[pcp->count++] = block;
    arch_irq_restore(irq);
}

void kmalloc_init(void) {
    spin_init(&kmalloc_lock);
    for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
        struct size_class *sc = &size_classes[i];
        sc->block_size = kmalloc_sizes[i];
        spin_init(&sc->lock);
        for (int cpu = 0; cpu < CONFIG_MAX_CPUS; cpu++) pcp_caches[i][cpu].count = 0;
    }
    pr_info("kmalloc: %lu classes init\n", NUM_SIZE_CLASSES);
}

void *kzalloc(size_t size) {
    void *ptr = kmalloc(size);
    if (ptr) memset(ptr, 0, size);
    return ptr;
}

void *kmalloc_aligned(size_t size, size_t align) {
    if (align <= sizeof(void *)) return kmalloc(size);
    void *raw = kmalloc(size + align + sizeof(void *));
    if (!raw) return NULL;
    uintptr_t addr = ALIGN_UP((uintptr_t)raw + sizeof(void *), align);
    ((void **)addr)[-1] = raw;
    return (void *)addr;
}

void kfree_aligned(void *ptr) { if (ptr) kfree(((void **)ptr)[-1]); }

void kmalloc_stats(void) {
    pr_info("kmalloc: in_use %lu\n", total_alloc - total_freed);
    for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
        struct size_class *sc = &size_classes[i];
        if (sc->num_allocated) pr_info("  %lu: %lu allocated\n", sc->block_size, sc->num_allocated);
    }
}