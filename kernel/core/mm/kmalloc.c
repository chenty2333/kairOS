/**
 * kmalloc.c - Kernel Memory Allocator
 *
 * Simple power-of-2 allocator using the buddy system for page allocation.
 * For small allocations, uses a set of fixed-size caches (slab-like).
 * For large allocations (> PAGE_SIZE/2), allocates full pages directly.
 *
 * Size classes: 32, 64, 128, 256, 512, 1024, 2048 bytes
 */

#include <kairos/types.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/config.h>

#define PAGE_SIZE       CONFIG_PAGE_SIZE
#define PAGE_SHIFT      CONFIG_PAGE_SHIFT

/* Minimum allocation size (must be power of 2, >= sizeof(void*)) */
#define MIN_ALLOC_SIZE      32
#define MIN_ALLOC_SHIFT     5

/* Maximum size for small allocation cache */
#define MAX_SMALL_SIZE      2048
#define MAX_SMALL_SHIFT     11

/* Number of size classes */
#define NUM_SIZE_CLASSES    (MAX_SMALL_SHIFT - MIN_ALLOC_SHIFT + 1)

/* Block header for tracking allocations */
struct block_header {
    uint32_t size;          /* Allocation size (or size class for cached) */
    uint32_t flags;
    struct block_header *next;  /* Free list link for cached blocks */
};

#define BLOCK_FLAG_LARGE    (1 << 0)    /* Large (page-aligned) allocation */
#define BLOCK_FLAG_CACHED   (1 << 1)    /* From size class cache */

/* Size class cache */
struct size_class {
    struct block_header *freelist;
    size_t block_size;              /* Size of each block */
    size_t blocks_per_page;         /* Blocks that fit in one page */
    size_t num_free;                /* Number of free blocks */
    size_t num_allocated;           /* Number of allocated blocks */
    spinlock_t lock;
};

static struct size_class size_classes[NUM_SIZE_CLASSES];

/* Global allocator lock (for large allocations) */
static spinlock_t kmalloc_lock;

/* Statistics */
static size_t total_allocated;
static size_t total_freed;

/**
 * size_to_class - Get size class index for a given size
 */
static inline int size_to_class(size_t size)
{
    if (size <= MIN_ALLOC_SIZE) {
        return 0;
    }

    /* Find the smallest power of 2 that fits */
    int class_idx = 0;
    size_t class_size = MIN_ALLOC_SIZE;

    while (class_size < size && class_idx < NUM_SIZE_CLASSES - 1) {
        class_size <<= 1;
        class_idx++;
    }

    return class_idx;
}

/**
 * class_to_size - Get block size for a class
 */
static inline size_t class_to_size(int class_idx)
{
    return MIN_ALLOC_SIZE << class_idx;
}

/**
 * grow_cache - Add more blocks to a size class cache
 */
static int grow_cache(struct size_class *sc)
{
    struct page *page = alloc_page();
    if (!page) {
        return -ENOMEM;
    }

    page->flags |= PG_SLAB;
    paddr_t pa = page_to_phys(page);

    /* Divide page into blocks */
    size_t block_size = sc->block_size;
    size_t num_blocks = PAGE_SIZE / block_size;

    for (size_t i = 0; i < num_blocks; i++) {
        struct block_header *block = (struct block_header *)(pa + i * block_size);
        block->size = block_size;
        block->flags = BLOCK_FLAG_CACHED;
        block->next = sc->freelist;
        sc->freelist = block;
        sc->num_free++;
    }

    return 0;
}

/**
 * kmalloc_init - Initialize the kernel memory allocator
 */
void kmalloc_init(void)
{
    spin_init(&kmalloc_lock);

    for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
        struct size_class *sc = &size_classes[i];
        sc->freelist = NULL;
        sc->block_size = class_to_size(i) + sizeof(struct block_header);
        sc->blocks_per_page = PAGE_SIZE / sc->block_size;
        sc->num_free = 0;
        sc->num_allocated = 0;
        spin_init(&sc->lock);
    }

    total_allocated = 0;
    total_freed = 0;

    pr_info("kmalloc: initialized with %d size classes (%u - %u bytes)\n",
            NUM_SIZE_CLASSES, MIN_ALLOC_SIZE, MAX_SMALL_SIZE);
}

/**
 * kmalloc - Allocate kernel memory
 * @size: Number of bytes to allocate
 *
 * Returns pointer to allocated memory, or NULL on failure.
 */
void *kmalloc(size_t size)
{
    if (size == 0) {
        return NULL;
    }

    /* Large allocation: directly from buddy allocator */
    if (size > MAX_SMALL_SIZE) {
        size_t total_size = size + sizeof(struct block_header);
        unsigned int order = 0;

        while ((size_t)(PAGE_SIZE << order) < total_size && order < MAX_ORDER) {
            order++;
        }

        if (order >= MAX_ORDER) {
            return NULL;
        }

        bool irq_state = arch_irq_save();
        spin_lock(&kmalloc_lock);

        struct page *page = alloc_pages(order);
        if (!page) {
            spin_unlock(&kmalloc_lock);
            arch_irq_restore(irq_state);
            return NULL;
        }

        paddr_t pa = page_to_phys(page);
        struct block_header *hdr = (struct block_header *)pa;
        hdr->size = (PAGE_SIZE << order);
        hdr->flags = BLOCK_FLAG_LARGE;
        hdr->next = NULL;

        total_allocated += hdr->size;

        spin_unlock(&kmalloc_lock);
        arch_irq_restore(irq_state);

        return (void *)(hdr + 1);
    }

    /* Small allocation: from size class cache */
    int class_idx = size_to_class(size + sizeof(struct block_header));
    struct size_class *sc = &size_classes[class_idx];

    bool irq_state = arch_irq_save();
    spin_lock(&sc->lock);

    /* Grow cache if empty */
    if (!sc->freelist) {
        if (grow_cache(sc) < 0) {
            spin_unlock(&sc->lock);
            arch_irq_restore(irq_state);
            return NULL;
        }
    }

    /* Take block from freelist */
    struct block_header *block = sc->freelist;
    sc->freelist = block->next;
    sc->num_free--;
    sc->num_allocated++;

    total_allocated += sc->block_size;

    spin_unlock(&sc->lock);
    arch_irq_restore(irq_state);

    return (void *)(block + 1);
}

/**
 * kfree - Free kernel memory
 * @ptr: Pointer to memory to free
 */
void kfree(void *ptr)
{
    if (!ptr) {
        return;
    }

    struct block_header *hdr = (struct block_header *)ptr - 1;

    if (hdr->flags & BLOCK_FLAG_LARGE) {
        /* Large allocation: return to buddy allocator */
        bool irq_state = arch_irq_save();
        spin_lock(&kmalloc_lock);

        total_freed += hdr->size;

        /* Find order from size */
        unsigned int order = 0;
        size_t page_count = hdr->size >> PAGE_SHIFT;
        while ((1UL << order) < page_count) {
            order++;
        }

        struct page *page = phys_to_page((paddr_t)hdr);
        free_pages(page, order);

        spin_unlock(&kmalloc_lock);
        arch_irq_restore(irq_state);
    } else if (hdr->flags & BLOCK_FLAG_CACHED) {
        /* Small allocation: return to size class cache */
        int class_idx = size_to_class(hdr->size);
        struct size_class *sc = &size_classes[class_idx];

        bool irq_state = arch_irq_save();
        spin_lock(&sc->lock);

        total_freed += sc->block_size;
        sc->num_allocated--;

        hdr->next = sc->freelist;
        sc->freelist = hdr;
        sc->num_free++;

        spin_unlock(&sc->lock);
        arch_irq_restore(irq_state);
    } else {
        pr_warn("kfree: invalid block at %p (flags=%x)\n", ptr, hdr->flags);
    }
}

/**
 * kzalloc - Allocate zeroed kernel memory
 * @size: Number of bytes to allocate
 */
void *kzalloc(size_t size)
{
    void *ptr = kmalloc(size);
    if (ptr) {
        /* Zero the memory */
        uint8_t *p = ptr;
        for (size_t i = 0; i < size; i++) {
            p[i] = 0;
        }
    }
    return ptr;
}

/**
 * kmalloc_aligned - Allocate aligned kernel memory
 * @size: Number of bytes to allocate
 * @align: Required alignment (must be power of 2)
 */
void *kmalloc_aligned(size_t size, size_t align)
{
    if (align <= sizeof(struct block_header)) {
        /* Standard allocation is sufficient */
        return kmalloc(size);
    }

    /* Allocate extra space for alignment */
    size_t total = size + align + sizeof(void *);
    void *raw = kmalloc(total);
    if (!raw) {
        return NULL;
    }

    /* Align the pointer */
    uintptr_t addr = (uintptr_t)raw + sizeof(void *);
    addr = ALIGN_UP(addr, align);

    /* Store original pointer before aligned address */
    ((void **)addr)[-1] = raw;

    return (void *)addr;
}

/**
 * kfree_aligned - Free aligned memory
 * @ptr: Pointer to free (must have been allocated with kmalloc_aligned)
 */
void kfree_aligned(void *ptr)
{
    if (!ptr) {
        return;
    }

    /* Retrieve original pointer */
    void *raw = ((void **)ptr)[-1];
    kfree(raw);
}

/**
 * kmalloc_stats - Print allocator statistics
 */
void kmalloc_stats(void)
{
    pr_info("kmalloc statistics:\n");
    pr_info("  Total allocated: %lu bytes\n", total_allocated);
    pr_info("  Total freed: %lu bytes\n", total_freed);
    pr_info("  In use: %lu bytes\n", total_allocated - total_freed);

    for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
        struct size_class *sc = &size_classes[i];
        if (sc->num_allocated > 0 || sc->num_free > 0) {
            pr_info("  Class %d (%lu bytes): %lu free, %lu allocated\n",
                    i, sc->block_size, sc->num_free, sc->num_allocated);
        }
    }
}
