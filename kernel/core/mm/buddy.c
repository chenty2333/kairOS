/**
 * buddy.c - Buddy System Physical Memory Allocator
 *
 * Implements a binary buddy allocator for physical page management.
 * Supports allocation of 2^order contiguous pages (order 0-10).
 *
 * The buddy system works by:
 * 1. Maintaining free lists for each order (0 to MAX_ORDER-1)
 * 2. When allocating, finding the smallest sufficient block and splitting
 * 3. When freeing, coalescing adjacent buddy blocks into larger ones
 */

#include <kairos/types.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/config.h>

/* Page size constants */
#define PAGE_SHIFT      CONFIG_PAGE_SHIFT
#define PAGE_SIZE       CONFIG_PAGE_SIZE
#define PAGE_MASK       (~(PAGE_SIZE - 1))

/* Maximum physical memory we support (1GB) */
#define MAX_PHYS_MEM    (1UL << 30)
#define MAX_PAGES       (MAX_PHYS_MEM / PAGE_SIZE)

/* Free lists for each order */
static struct list_head free_lists[MAX_ORDER];

/* Page array - one struct page per physical page */
static struct page *page_array;
static size_t page_array_pages;  /* Number of pages used by page array */

/* Memory range */
static paddr_t mem_start;
static paddr_t mem_end;
static size_t total_pages;
static size_t num_free_pages;

/* Lock for allocator */
static spinlock_t buddy_lock;

/* External symbols from linker script */
extern char _kernel_start[];
extern char _kernel_end[];

/**
 * page_to_phys - Convert page struct to physical address
 */
paddr_t page_to_phys(struct page *page)
{
    size_t pfn = page - page_array;
    return mem_start + (pfn << PAGE_SHIFT);
}

/**
 * phys_to_page - Convert physical address to page struct
 */
struct page *phys_to_page(paddr_t addr)
{
    if (addr < mem_start || addr >= mem_end) {
        return NULL;
    }
    size_t pfn = (addr - mem_start) >> PAGE_SHIFT;
    return &page_array[pfn];
}

/**
 * pfn_to_page - Convert page frame number to page struct
 */
static inline struct page *pfn_to_page(size_t pfn)
{
    return &page_array[pfn];
}

/**
 * page_to_pfn - Convert page struct to page frame number
 */
static inline size_t page_to_pfn(struct page *page)
{
    return page - page_array;
}

/**
 * get_buddy_pfn - Get the page frame number of the buddy page
 */
static inline size_t get_buddy_pfn(size_t pfn, unsigned int order)
{
    return pfn ^ (1UL << order);
}

/**
 * pages_are_buddies - Check if two pages are buddies at given order
 */
static bool pages_are_buddies(struct page *page, struct page *buddy,
                              unsigned int order)
{
    size_t pfn = page_to_pfn(page);
    size_t buddy_pfn = page_to_pfn(buddy);

    /* Check if addresses are aligned for this order */
    if (buddy_pfn != get_buddy_pfn(pfn, order)) {
        return false;
    }

    /* Buddy must be free and same order */
    if (buddy->flags & PG_RESERVED) {
        return false;
    }
    if (buddy->order != order) {
        return false;
    }

    /* Check if buddy is in a free list (refcount == 0 means free) */
    if (buddy->refcount != 0) {
        return false;
    }

    return true;
}

/**
 * __alloc_pages - Internal allocation (lock must be held)
 */
static struct page *__alloc_pages(unsigned int order)
{
    unsigned int current_order;
    struct page *page;

    if (order >= MAX_ORDER) {
        return NULL;
    }

    /* Find a free block of sufficient size */
    for (current_order = order; current_order < MAX_ORDER; current_order++) {
        if (list_empty(&free_lists[current_order])) {
            continue;
        }

        /* Found a block, remove from free list */
        page = list_first_entry(&free_lists[current_order],
                                struct page, list);
        list_del(&page->list);
        page->refcount = 1;

        /* Split the block down to requested size */
        while (current_order > order) {
            current_order--;
            size_t pfn = page_to_pfn(page);
            size_t buddy_pfn = pfn + (1UL << current_order);

            if (buddy_pfn < total_pages) {
                struct page *buddy = pfn_to_page(buddy_pfn);
                buddy->order = current_order;
                buddy->refcount = 0;
                buddy->flags = 0;
                list_add(&buddy->list, &free_lists[current_order]);
            }
        }

        page->order = order;
        num_free_pages -= (1UL << order);
        return page;
    }

    return NULL;  /* Out of memory */
}

/**
 * __free_pages - Internal free (lock must be held)
 */
static void __free_pages(struct page *page, unsigned int order)
{
    size_t pfn = page_to_pfn(page);

    if (page->flags & PG_RESERVED) {
        pr_warn("buddy: trying to free reserved page %p\n",
                (void *)page_to_phys(page));
        return;
    }

    page->refcount = 0;
    num_free_pages += (1UL << order);

    /* Try to coalesce with buddy */
    while (order < MAX_ORDER - 1) {
        size_t buddy_pfn = get_buddy_pfn(pfn, order);

        /* Check if buddy exists */
        if (buddy_pfn >= total_pages) {
            break;
        }

        struct page *buddy = pfn_to_page(buddy_pfn);

        /* Check if we can merge */
        if (!pages_are_buddies(page, buddy, order)) {
            break;
        }

        /* Remove buddy from free list */
        list_del(&buddy->list);

        /* Combine into larger block */
        if (buddy_pfn < pfn) {
            page = buddy;
            pfn = buddy_pfn;
        }

        order++;
    }

    /* Add to appropriate free list */
    page->order = order;
    list_add(&page->list, &free_lists[order]);
}

/**
 * alloc_pages - Allocate 2^order contiguous pages
 */
struct page *alloc_pages(unsigned int order)
{
    bool irq_state = arch_irq_save();
    spin_lock(&buddy_lock);

    struct page *page = __alloc_pages(order);
    if (page) {
        page->flags |= PG_KERNEL;
    }

    spin_unlock(&buddy_lock);
    arch_irq_restore(irq_state);
    return page;
}

/**
 * free_pages - Free pages allocated with alloc_pages
 */
void free_pages(struct page *page, unsigned int order)
{
    if (!page) {
        return;
    }

    bool irq_state = arch_irq_save();
    spin_lock(&buddy_lock);

    page->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB);
    __free_pages(page, order);

    spin_unlock(&buddy_lock);
    arch_irq_restore(irq_state);
}

/**
 * pmm_total_pages - Get total number of managed pages
 */
size_t pmm_total_pages(void)
{
    return total_pages;
}

/**
 * pmm_num_free_pages - Get number of free pages
 */
size_t pmm_num_free_pages(void)
{
    return num_free_pages;
}

/*
 * Legacy API compatibility (Phase 0 interface)
 */

/**
 * pmm_alloc_page - Allocate a single page (legacy API)
 */
paddr_t pmm_alloc_page(void)
{
    struct page *page = alloc_pages(0);
    return page ? page_to_phys(page) : 0;
}

/**
 * pmm_alloc_pages - Allocate contiguous pages (legacy API)
 */
paddr_t pmm_alloc_pages(size_t count)
{
    if (count == 0) {
        return 0;
    }

    /* Find the order that fits count pages */
    unsigned int order = 0;
    while ((1UL << order) < count && order < MAX_ORDER) {
        order++;
    }

    if (order >= MAX_ORDER) {
        return 0;
    }

    struct page *page = alloc_pages(order);
    return page ? page_to_phys(page) : 0;
}

/**
 * pmm_free_page - Free a single page (legacy API)
 */
void pmm_free_page(paddr_t pa)
{
    struct page *page = phys_to_page(pa);
    if (page) {
        free_pages(page, 0);
    }
}

/**
 * pmm_free_pages - Free contiguous pages (legacy API)
 */
void pmm_free_pages(paddr_t pa, size_t count)
{
    if (count == 0) {
        return;
    }

    /* Find the order that fits count pages */
    unsigned int order = 0;
    while ((1UL << order) < count && order < MAX_ORDER) {
        order++;
    }

    struct page *page = phys_to_page(pa);
    if (page) {
        free_pages(page, order);
    }
}

/**
 * pmm_get_free_pages - Get number of free pages (legacy API)
 */
size_t pmm_get_free_pages(void)
{
    return num_free_pages;
}

/**
 * pmm_get_total_pages - Get total number of pages (legacy API)
 */
size_t pmm_get_total_pages(void)
{
    return total_pages;
}

/**
 * pmm_reserve_range - Mark a range as reserved (legacy API)
 */
void pmm_reserve_range(paddr_t start, paddr_t end)
{
    if (start >= mem_end || end <= mem_start) {
        return;
    }

    start = MAX(start, mem_start);
    end = MIN(end, mem_end);

    start = ALIGN_DOWN(start, PAGE_SIZE);
    end = ALIGN_UP(end, PAGE_SIZE);

    bool irq_state = arch_irq_save();
    spin_lock(&buddy_lock);

    for (paddr_t addr = start; addr < end; addr += PAGE_SIZE) {
        struct page *page = phys_to_page(addr);
        if (page && !(page->flags & PG_RESERVED)) {
            page->flags |= PG_RESERVED;
            /* Note: We don't adjust free count here as reserved
             * pages were never added to free lists */
        }
    }

    spin_unlock(&buddy_lock);
    arch_irq_restore(irq_state);
}

/**
 * buddy_init_zone - Initialize a zone of pages into free lists
 */
static void buddy_init_zone(size_t start_pfn, size_t end_pfn)
{
    size_t pfn = start_pfn;

    while (pfn < end_pfn) {
        /* Find the largest order that fits and is aligned */
        unsigned int order = MAX_ORDER - 1;

        while (order > 0) {
            size_t block_size = 1UL << order;
            /* Check alignment and fit */
            if ((pfn & (block_size - 1)) == 0 &&
                pfn + block_size <= end_pfn) {
                break;
            }
            order--;
        }

        struct page *page = pfn_to_page(pfn);
        page->flags = 0;
        page->order = order;
        page->refcount = 0;
        INIT_LIST_HEAD(&page->list);
        list_add_tail(&page->list, &free_lists[order]);

        size_t block_size = 1UL << order;
        num_free_pages += block_size;
        pfn += block_size;
    }
}

/**
 * pmm_init - Initialize the buddy allocator
 * @start: Start of usable physical memory
 * @end: End of usable physical memory
 */
void pmm_init(paddr_t start, paddr_t end)
{
    /* Initialize lock */
    spin_init(&buddy_lock);

    /* Initialize free lists */
    for (int i = 0; i < MAX_ORDER; i++) {
        INIT_LIST_HEAD(&free_lists[i]);
    }

    /* Align memory boundaries */
    mem_start = ALIGN_UP(start, PAGE_SIZE);
    mem_end = ALIGN_DOWN(end, PAGE_SIZE);

    if (mem_end <= mem_start) {
        panic("pmm_init: invalid memory range");
    }

    total_pages = (mem_end - mem_start) >> PAGE_SHIFT;
    if (total_pages > MAX_PAGES) {
        total_pages = MAX_PAGES;
        mem_end = mem_start + (total_pages << PAGE_SHIFT);
    }

    /* Calculate space needed for page array */
    size_t page_array_size = total_pages * sizeof(struct page);
    page_array_pages = ALIGN_UP(page_array_size, PAGE_SIZE) >> PAGE_SHIFT;

    /* Place page array at start of memory */
    page_array = (struct page *)mem_start;

    /* Initialize all page structs */
    for (size_t i = 0; i < total_pages; i++) {
        page_array[i].flags = 0;
        page_array[i].order = 0;
        page_array[i].refcount = 0;
        INIT_LIST_HEAD(&page_array[i].list);
    }

    /* Mark page array pages as reserved */
    for (size_t i = 0; i < page_array_pages; i++) {
        page_array[i].flags = PG_RESERVED;
    }

    /* Reserve kernel pages */
    paddr_t kernel_start = (paddr_t)_kernel_start;
    paddr_t kernel_end_addr = (paddr_t)_kernel_end;

    if (kernel_start >= mem_start && kernel_start < mem_end) {
        size_t start_pfn = (kernel_start - mem_start) >> PAGE_SHIFT;
        size_t end_pfn = (ALIGN_UP(kernel_end_addr, PAGE_SIZE) - mem_start) >> PAGE_SHIFT;

        for (size_t i = start_pfn; i < end_pfn && i < total_pages; i++) {
            page_array[i].flags = PG_RESERVED | PG_KERNEL;
        }
    }

    num_free_pages = 0;

    /* Initialize free memory into buddy lists */
    /* Start after page array */
    size_t first_free_pfn = page_array_pages;

    /* Skip kernel if it's within our range */
    size_t kernel_start_pfn = 0;
    size_t kernel_end_pfn = 0;

    if (kernel_start >= mem_start && kernel_start < mem_end) {
        kernel_start_pfn = (kernel_start - mem_start) >> PAGE_SHIFT;
        kernel_end_pfn = (ALIGN_UP(kernel_end_addr, PAGE_SIZE) - mem_start) >> PAGE_SHIFT;
    }

    /* Add free pages to buddy system */
    if (kernel_start_pfn > first_free_pfn) {
        /* Memory before kernel */
        buddy_init_zone(first_free_pfn, kernel_start_pfn);
    }

    if (kernel_end_pfn > 0 && kernel_end_pfn < total_pages) {
        /* Memory after kernel */
        size_t start_after_kernel = MAX(kernel_end_pfn, first_free_pfn);
        if (start_after_kernel < total_pages) {
            buddy_init_zone(start_after_kernel, total_pages);
        }
    } else if (kernel_end_pfn == 0) {
        /* Kernel not in our range, add all after page array */
        buddy_init_zone(first_free_pfn, total_pages);
    }

    pr_info("PMM: Buddy allocator initialized\n");
    pr_info("PMM: %lu pages (%lu MB), %lu free, page_array uses %lu pages\n",
            total_pages,
            (total_pages * PAGE_SIZE) >> 20,
            num_free_pages,
            page_array_pages);

    /* Print free list statistics */
    for (int i = 0; i < MAX_ORDER; i++) {
        size_t count = 0;
        struct list_head *pos;
        list_for_each(pos, &free_lists[i]) {
            count++;
        }
        if (count > 0) {
            pr_debug("  Order %d (%lu KB): %lu blocks\n",
                     i, (unsigned long)((PAGE_SIZE << i) >> 10), count);
        }
    }
}
