/**
 * buddy.c - Buddy System Physical Memory Allocator
 */

#include <kairos/types.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/boot.h>
#include <kairos/spinlock.h>
#include <kairos/config.h>
#include <kairos/arch.h>

#define PAGE_SHIFT      CONFIG_PAGE_SHIFT
#define PAGE_SIZE       CONFIG_PAGE_SIZE

#define MAX_PHYS_MEM    (1UL << 30)
#define MAX_PAGES       (MAX_PHYS_MEM / PAGE_SIZE)

#define PCP_BATCH       16
#define PCP_HIGH        64

static struct list_head free_lists[MAX_ORDER];
static struct page *page_array;
static paddr_t mem_start, mem_end;
static size_t total_pages, num_free_pages;
static spinlock_t buddy_lock;

static struct pcp_area {
    struct list_head list;
    int count;
} pcp_areas[CONFIG_MAX_CPUS];

static bool pcp_enabled = true;

extern char _kernel_start[], _kernel_end[];

static void pmm_init_common(void) {
    spin_init(&buddy_lock);
    for (int i = 0; i < MAX_ORDER; i++)
        INIT_LIST_HEAD(&free_lists[i]);
    for (int i = 0; i < CONFIG_MAX_CPUS; i++) {
        INIT_LIST_HEAD(&pcp_areas[i].list);
        pcp_areas[i].count = 0;
    }
}

/* --- Conversions --- */

paddr_t page_to_phys(struct page *page) {
    return mem_start + ((size_t)(page - page_array) << PAGE_SHIFT);
}

struct page *phys_to_page(paddr_t addr) {
    if (addr < mem_start || addr >= mem_end) return NULL;
    return &page_array[(addr - mem_start) >> PAGE_SHIFT];
}

static inline size_t page_to_pfn(struct page *page) { return page - page_array; }
static inline struct page *pfn_to_page(size_t pfn) { return &page_array[pfn]; }

static bool pages_are_buddies(struct page *page, struct page *buddy, unsigned int order) {
    return (buddy >= page_array && buddy < page_array + total_pages &&
            buddy->order == order && buddy->refcount == 0 &&
            !(buddy->flags & PG_RESERVED) &&
            (page_to_pfn(page) ^ (1UL << order)) == page_to_pfn(buddy));
}

static inline bool page_ptr_valid(struct page *page) {
    return page >= page_array && page < page_array + total_pages;
}

static void pcp_disable(const char *reason, int cpu) {
    if (!pcp_enabled)
        return;
    pr_warn("pmm: disabling PCP on cpu %d (%s)\n", cpu, reason);
    pcp_enabled = false;
    for (int i = 0; i < CONFIG_MAX_CPUS; i++) {
        INIT_LIST_HEAD(&pcp_areas[i].list);
        pcp_areas[i].count = 0;
    }
}

/* --- Internal Alloc/Free (buddy_lock must be held) --- */

static struct page *__alloc_pages(unsigned int order) {
    for (unsigned int o = order; o < MAX_ORDER; o++) {
        if (list_empty(&free_lists[o])) continue;

        struct page *page = list_first_entry(&free_lists[o], struct page, list);
        list_del(&page->list);
        
        while (o > order) {
            o--;
            struct page *buddy = page + (1UL << o);
            buddy->order = o;
            buddy->refcount = 0;
            buddy->flags = 0;
            list_add(&buddy->list, &free_lists[o]);
        }

        page->order = order;
        page->refcount = 1;
        num_free_pages -= (1UL << order);
        return page;
    }
    return NULL;
}

static void __free_pages(struct page *page, unsigned int order) {
    size_t pfn = page_to_pfn(page);
    num_free_pages += (1UL << order);

    while (order < MAX_ORDER - 1) {
        struct page *buddy = pfn_to_page(pfn ^ (1UL << order));
        if (!pages_are_buddies(page, buddy, order)) break;

        list_del(&buddy->list);
        if (buddy < page) page = buddy;
        pfn = page_to_pfn(page);
        order++;
    }

    page->order = order;
    page->refcount = 0;
    list_add(&page->list, &free_lists[order]);
}

/* --- Public API --- */

struct page *alloc_pages(unsigned int order) {
    struct page *page = NULL;
    bool irq = arch_irq_save();
    int cpu = (int)arch_cpu_id();
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        cpu = 0;

    if (order == 0 && pcp_enabled) {
        struct pcp_area *pcp = &pcp_areas[cpu];
        if (pcp->count > 0 && list_empty(&pcp->list)) {
            pr_warn("pmm: pcp list empty on cpu %d (count=%d), resetting\n",
                    cpu, pcp->count);
            INIT_LIST_HEAD(&pcp->list);
            pcp->count = 0;
            pcp_disable("pcp list corruption", cpu);
        }
        if (pcp->count == 0) {
            spin_lock(&buddy_lock);
            for (int i = 0; i < PCP_BATCH; i++) {
                struct page *p = __alloc_pages(0);
                if (!p)
                    break;
                if (!page_ptr_valid(p)) {
                    pr_err("pmm: invalid page from buddy list (%p)\n", p);
                    pcp_disable("invalid buddy page", cpu);
                    break;
                }
                list_add(&p->list, &pcp->list);
                pcp->count++;
            }
            spin_unlock(&buddy_lock);
        }
        if (pcp->count > 0 && !list_empty(&pcp->list)) {
            page = list_first_entry(&pcp->list, struct page, list);
            if (!page_ptr_valid(page)) {
                pr_err("pmm: invalid page in pcp list (%p), resetting\n", page);
                INIT_LIST_HEAD(&pcp->list);
                pcp->count = 0;
                pcp_disable("invalid pcp page", cpu);
                page = NULL;
            } else {
                list_del(&page->list);
                pcp->count--;
                page->order = 0;
                page->refcount = 1;
            }
        }
        if (!page) {
            spin_lock(&buddy_lock);
            page = __alloc_pages(0);
            spin_unlock(&buddy_lock);
            if (page && !page_ptr_valid(page)) {
                pr_err("pmm: invalid page from buddy list (%p)\n", page);
                pcp_disable("invalid buddy page", cpu);
                page = NULL;
            }
        }
    } else {
        spin_lock(&buddy_lock);
        page = __alloc_pages(order);
        spin_unlock(&buddy_lock);
        if (page && !page_ptr_valid(page)) {
            pr_err("pmm: invalid page from buddy list (%p)\n", page);
            pcp_disable("invalid buddy page", cpu);
            page = NULL;
        }
    }

    if (page) page->flags |= PG_KERNEL;
    arch_irq_restore(irq);
    return page;
}

void free_pages(struct page *page, unsigned int order) {
    if (!page) return;
    bool irq = arch_irq_save();
    if (!page_ptr_valid(page)) {
        pr_err("pmm: free_pages with invalid page %p (order=%u)\n", page, order);
        arch_irq_restore(irq);
        return;
    }
    page->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB);
    page->refcount = 0;
    page->order = order;

    if (order == 0 && pcp_enabled) {
        int cpu = (int)arch_cpu_id();
        if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
            cpu = 0;
        struct pcp_area *pcp = &pcp_areas[cpu];
        list_add(&page->list, &pcp->list);
        if (++pcp->count >= PCP_HIGH) {
            spin_lock(&buddy_lock);
            for (int i = 0; i < PCP_BATCH; i++) {
                if (list_empty(&pcp->list)) {
                    pcp->count = 0;
                    break;
                }
                struct page *p = list_first_entry(&pcp->list, struct page, list);
                list_del(&p->list);
                pcp->count--;
                __free_pages(p, 0);
            }
            spin_unlock(&buddy_lock);
        }
    } else {
        spin_lock(&buddy_lock);
        __free_pages(page, order);
        spin_unlock(&buddy_lock);
    }
    arch_irq_restore(irq);
}

/* --- Stats & Legacy --- */

size_t pmm_total_pages(void) { return total_pages; }

size_t pmm_num_free_pages(void) {
    size_t total = num_free_pages;
    int ncpus = arch_cpu_count();
    for (int i = 0; i < ncpus; i++) {
        total += pcp_areas[i].count;
    }
    return total;
}

paddr_t pmm_alloc_page(void) { return pmm_alloc_pages(1); }

paddr_t pmm_alloc_pages(size_t count) {
    if (!count) return 0;
    unsigned int order = 0;
    while ((1UL << order) < count && order < MAX_ORDER) order++;
    if (order >= MAX_ORDER) return 0;
    struct page *p = alloc_pages(order);
    return p ? page_to_phys(p) : 0;
}

void pmm_get_page(paddr_t pa) {
    struct page *p = phys_to_page(pa);
    if (p)
        __atomic_add_fetch(&p->refcount, 1, __ATOMIC_RELAXED);
}

void pmm_put_page(paddr_t pa) {
    struct page *p = phys_to_page(pa);
    if (!p)
        return;
    if (__atomic_sub_fetch(&p->refcount, 1, __ATOMIC_RELAXED) == 0) {
        free_pages(p, 0);
    }
}

int pmm_page_refcount(paddr_t pa) {
    struct page *p = phys_to_page(pa);
    return p ? __atomic_load_n(&p->refcount, __ATOMIC_RELAXED) : 0;
}

void pmm_free_page(paddr_t pa) { pmm_put_page(pa); }

void pmm_free_pages(paddr_t pa, size_t count) {
    if (!count) return;
    unsigned int order = 0;
    while ((1UL << order) < count && order < MAX_ORDER) order++;
    struct page *p = phys_to_page(pa);
    if (p) free_pages(p, order);
}

void pmm_reserve_range(paddr_t start, paddr_t end) {
    start = MAX(ALIGN_DOWN(start, PAGE_SIZE), mem_start);
    end = MIN(ALIGN_UP(end, PAGE_SIZE), mem_end);
    
    bool irq = arch_irq_save();
    spin_lock(&buddy_lock);
    for (paddr_t a = start; a < end; a += PAGE_SIZE) {
        struct page *p = phys_to_page(a);
        if (p) p->flags |= PG_RESERVED;
    }
    spin_unlock(&buddy_lock);
    arch_irq_restore(irq);
}

/* --- Init --- */

static void buddy_init_zone(size_t start_pfn, size_t end_pfn) {
    size_t pfn = start_pfn;
    while (pfn < end_pfn) {
        unsigned int order = MAX_ORDER - 1;
        while (order > 0 && ((pfn & ((1UL << order) - 1)) || pfn + (1UL << order) > end_pfn))
            order--;

        struct page *p = pfn_to_page(pfn);
        p->order = order;
        p->refcount = 0;
        list_add_tail(&p->list, &free_lists[order]);
        num_free_pages += (1UL << order);
        pfn += (1UL << order);
    }
}

void pmm_init(paddr_t start, paddr_t end) {
    pmm_init_common();

    mem_start = ALIGN_UP(start, PAGE_SIZE);
    mem_end = ALIGN_DOWN(end, PAGE_SIZE);
    total_pages = MIN((mem_end - mem_start) >> PAGE_SHIFT, MAX_PAGES);
    mem_end = mem_start + (total_pages << PAGE_SHIFT);

    size_t array_pages =
        ALIGN_UP(total_pages * sizeof(struct page), PAGE_SIZE) >> PAGE_SHIFT;
    page_array = (struct page *)phys_to_virt(mem_start);

    for (size_t i = 0; i < total_pages; i++) {
        page_array[i].flags = (i < array_pages) ? PG_RESERVED : 0;
        page_array[i].refcount = 0;
        INIT_LIST_HEAD(&page_array[i].list);
    }

    paddr_t ks = virt_to_phys(_kernel_start);
    paddr_t ke = virt_to_phys(_kernel_end);
    ke = ALIGN_UP(ke, PAGE_SIZE);
    if (ks >= mem_start && ks < mem_end) {
        for (size_t i = (ks - mem_start) >> PAGE_SHIFT; i < (ke - mem_start) >> PAGE_SHIFT && i < total_pages; i++)
            page_array[i].flags |= PG_RESERVED | PG_KERNEL;
    }

    size_t kernel_start_pfn = (ks >= mem_start && ks < mem_end) ? (ks - mem_start) >> PAGE_SHIFT : 0;
    size_t kernel_end_pfn = (ks >= mem_start && ks < mem_end) ? (ke - mem_start) >> PAGE_SHIFT : 0;

    if (kernel_start_pfn > array_pages) buddy_init_zone(array_pages, kernel_start_pfn);
    if (kernel_end_pfn < total_pages) buddy_init_zone(MAX(kernel_end_pfn, array_pages), total_pages);

    pr_info("PMM: Buddy init, %lu MB, %lu free\n", (total_pages * PAGE_SIZE) >> 20, pmm_num_free_pages());
}

void pmm_init_from_memmap(const struct boot_info *bi) {
    if (!bi || bi->memmap_count == 0) {
        panic("pmm: no boot memmap");
    }

    pmm_init_common();

    paddr_t min = 0;
    paddr_t max = 0;
    bool first = true;
    for (uint32_t i = 0; i < bi->memmap_count; i++) {
        const struct boot_memmap_entry *e = &bi->memmap[i];
        if (e->type != BOOT_MEM_USABLE)
            continue;
        if (first) {
            min = e->base;
            max = e->base + e->length;
            first = false;
        } else {
            if (e->base < min)
                min = e->base;
            if (e->base + e->length > max)
                max = e->base + e->length;
        }
    }
    if (first) {
        panic("pmm: no usable memory");
    }

    mem_start = ALIGN_UP(min, PAGE_SIZE);
    mem_end = ALIGN_DOWN(max, PAGE_SIZE);
    total_pages = MIN((mem_end - mem_start) >> PAGE_SHIFT, MAX_PAGES);
    mem_end = mem_start + (total_pages << PAGE_SHIFT);

    size_t array_pages =
        ALIGN_UP(total_pages * sizeof(struct page), PAGE_SIZE) >> PAGE_SHIFT;
    page_array = (struct page *)phys_to_virt(mem_start);

    for (size_t i = 0; i < total_pages; i++) {
        page_array[i].flags = PG_RESERVED;
        page_array[i].refcount = 0;
        INIT_LIST_HEAD(&page_array[i].list);
    }

    /* Mark usable pages from memmap */
    for (uint32_t i = 0; i < bi->memmap_count; i++) {
        const struct boot_memmap_entry *e = &bi->memmap[i];
        if (e->type != BOOT_MEM_USABLE)
            continue;

        paddr_t start = MAX(e->base, mem_start);
        paddr_t end = MIN(e->base + e->length, mem_end);
        if (end <= start)
            continue;

        start = ALIGN_UP(start, PAGE_SIZE);
        end = ALIGN_DOWN(end, PAGE_SIZE);
        if (end <= start)
            continue;

        size_t pfn_start = (start - mem_start) >> PAGE_SHIFT;
        size_t pfn_end = (end - mem_start) >> PAGE_SHIFT;
        if (pfn_start >= total_pages)
            continue;
        if (pfn_end > total_pages)
            pfn_end = total_pages;

        for (size_t pfn = pfn_start; pfn < pfn_end; pfn++) {
            page_array[pfn].flags = 0;
        }
    }

    /* Reserve page array itself */
    for (size_t i = 0; i < array_pages && i < total_pages; i++) {
        page_array[i].flags |= PG_RESERVED;
    }

    /* Reserve kernel image */
    paddr_t ks = virt_to_phys(_kernel_start);
    paddr_t ke = ALIGN_UP(virt_to_phys(_kernel_end), PAGE_SIZE);
    if (ks >= mem_start && ks < mem_end) {
        size_t s = (ks - mem_start) >> PAGE_SHIFT;
        size_t e = (ke - mem_start) >> PAGE_SHIFT;
        if (e > total_pages)
            e = total_pages;
        for (size_t pfn = s; pfn < e; pfn++) {
            page_array[pfn].flags |= PG_RESERVED | PG_KERNEL;
        }
    }

    num_free_pages = 0;
    size_t run_start = (size_t)-1;
    for (size_t pfn = 0; pfn <= total_pages; pfn++) {
        bool free = (pfn < total_pages) && !(page_array[pfn].flags & PG_RESERVED);
        if (free) {
            if (run_start == (size_t)-1)
                run_start = pfn;
        } else if (run_start != (size_t)-1) {
            buddy_init_zone(run_start, pfn);
            run_start = (size_t)-1;
        }
    }

    pr_info("PMM: memmap init, %lu MB, %lu free\n",
            (total_pages * PAGE_SIZE) >> 20, pmm_num_free_pages());
}
