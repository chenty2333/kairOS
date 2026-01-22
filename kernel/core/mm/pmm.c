/**
 * pmm.c - Physical Memory Manager (bitmap-based)
 *
 * Simple bitmap allocator for Phase 0. Will be replaced by buddy
 * allocator in Phase 1.
 *
 * Each bit represents one page (4KB). 1 = used, 0 = free.
 */

#include <kairos/types.h>
#include <kairos/mm.h>
#include <kairos/printk.h>

/* Page size constants */
#define PAGE_SHIFT  12
#define PAGE_SIZE   (1UL << PAGE_SHIFT)
#define PAGE_MASK   (~(PAGE_SIZE - 1))

/* Maximum physical memory we support (1GB for now) */
#define MAX_PHYS_MEM    (1UL << 30)
#define MAX_PAGES       (MAX_PHYS_MEM / PAGE_SIZE)

/* Bitmap: 1 bit per page, so 32KB for 1GB */
#define BITMAP_SIZE     (MAX_PAGES / 8)
static uint8_t page_bitmap[BITMAP_SIZE];

/* Memory statistics */
static paddr_t mem_start;
static paddr_t mem_end;
static size_t total_pages;
static size_t num_free_pages;

/* External symbols */
extern char _kernel_start[];
extern char _kernel_end[];

/* Bitmap operations */
static inline void bitmap_set(size_t page)
{
    page_bitmap[page / 8] |= (1 << (page % 8));
}

static inline void bitmap_clear(size_t page)
{
    page_bitmap[page / 8] &= ~(1 << (page % 8));
}

static inline int bitmap_test(size_t page)
{
    return (page_bitmap[page / 8] >> (page % 8)) & 1;
}

/* Convert physical address to page number */
static inline size_t pa_to_page(paddr_t pa)
{
    return (pa - mem_start) >> PAGE_SHIFT;
}

/* Convert page number to physical address */
static inline paddr_t page_to_pa(size_t page)
{
    return mem_start + (page << PAGE_SHIFT);
}

/**
 * pmm_init - Initialize physical memory manager
 * @start: Start of usable physical memory
 * @end: End of usable physical memory
 */
void pmm_init(paddr_t start, paddr_t end)
{
    /* Align to page boundaries */
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

    /* Clear bitmap (all pages free) */
    for (size_t i = 0; i < BITMAP_SIZE; i++) {
        page_bitmap[i] = 0;
    }

    /* Mark pages beyond our range as used */
    for (size_t i = total_pages; i < MAX_PAGES; i++) {
        bitmap_set(i);
    }

    num_free_pages = total_pages;

    /* Reserve kernel memory */
    paddr_t kernel_start = (paddr_t)_kernel_start;
    paddr_t kernel_end = (paddr_t)_kernel_end;

    if (kernel_start >= mem_start && kernel_start < mem_end) {
        size_t start_page = pa_to_page(kernel_start);
        size_t end_page = pa_to_page(ALIGN_UP(kernel_end, PAGE_SIZE));

        for (size_t i = start_page; i < end_page && i < total_pages; i++) {
            if (!bitmap_test(i)) {
                bitmap_set(i);
                num_free_pages--;
            }
        }
    }

    pr_info("PMM: %lu pages (%lu MB), %lu free\n",
            total_pages,
            (total_pages * PAGE_SIZE) >> 20,
            num_free_pages);
}

/**
 * pmm_alloc_page - Allocate a single physical page
 *
 * Returns physical address or 0 on failure.
 */
paddr_t pmm_alloc_page(void)
{
    /* Simple first-fit search */
    for (size_t i = 0; i < total_pages; i++) {
        if (!bitmap_test(i)) {
            bitmap_set(i);
            num_free_pages--;
            return page_to_pa(i);
        }
    }
    return 0; /* Out of memory */
}

/**
 * pmm_alloc_pages - Allocate contiguous physical pages
 * @count: Number of pages to allocate
 *
 * Returns physical address of first page, or 0 on failure.
 */
paddr_t pmm_alloc_pages(size_t count)
{
    if (count == 0) {
        return 0;
    }
    if (count == 1) {
        return pmm_alloc_page();
    }

    /* Find contiguous free region */
    size_t start = 0;
    size_t found = 0;

    for (size_t i = 0; i < total_pages; i++) {
        if (!bitmap_test(i)) {
            if (found == 0) {
                start = i;
            }
            found++;
            if (found == count) {
                /* Found enough pages, mark them as used */
                for (size_t j = start; j < start + count; j++) {
                    bitmap_set(j);
                }
                num_free_pages -= count;
                return page_to_pa(start);
            }
        } else {
            found = 0;
        }
    }

    return 0; /* Not enough contiguous memory */
}

/**
 * pmm_free_page - Free a single physical page
 * @pa: Physical address of page to free
 */
void pmm_free_page(paddr_t pa)
{
    if (pa < mem_start || pa >= mem_end) {
        pr_warn("pmm_free_page: invalid address %p\n", (void *)pa);
        return;
    }

    size_t page = pa_to_page(pa);
    if (!bitmap_test(page)) {
        pr_warn("pmm_free_page: double free at %p\n", (void *)pa);
        return;
    }

    bitmap_clear(page);
    num_free_pages++;
}

/**
 * pmm_free_pages - Free contiguous physical pages
 * @pa: Physical address of first page
 * @count: Number of pages to free
 */
void pmm_free_pages(paddr_t pa, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        pmm_free_page(pa + (i << PAGE_SHIFT));
    }
}

/**
 * pmm_get_free_pages - Get number of free pages
 */
size_t pmm_get_free_pages(void)
{
    return num_free_pages;
}

/**
 * pmm_get_total_pages - Get total number of pages
 */
size_t pmm_get_total_pages(void)
{
    return total_pages;
}

/**
 * pmm_reserve_range - Mark a physical memory range as reserved
 * @start: Start address (page-aligned)
 * @end: End address (page-aligned)
 */
void pmm_reserve_range(paddr_t start, paddr_t end)
{
    if (start >= mem_end || end <= mem_start) {
        return;
    }

    start = MAX(start, mem_start);
    end = MIN(end, mem_end);

    size_t start_page = pa_to_page(start);
    size_t end_page = pa_to_page(end);

    for (size_t i = start_page; i < end_page; i++) {
        if (!bitmap_test(i)) {
            bitmap_set(i);
            num_free_pages--;
        }
    }
}
