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
#include <kairos/string.h>

#define PAGE_SHIFT      CONFIG_PAGE_SHIFT
#define PAGE_SIZE       CONFIG_PAGE_SIZE

#define MAX_PHYS_MEM    (1UL << 30)
#define MAX_PAGES       (MAX_PHYS_MEM / PAGE_SIZE)

#define PCP_BATCH       16
#define PCP_HIGH        64
#define REMOTE_FREE_BATCH CONFIG_PMM_REMOTE_FREE_BATCH
#define REMOTE_FREE_HIGH CONFIG_PMM_REMOTE_FREE_HIGH

#if (CONFIG_PMM_PCP_MODE < 0) || (CONFIG_PMM_PCP_MODE > 2)
#error "CONFIG_PMM_PCP_MODE must be 0, 1, or 2"
#endif

static struct list_head free_lists[MAX_ORDER];
static struct page *page_array;
static paddr_t mem_start, mem_end;
static size_t total_pages, num_free_pages;
static spinlock_t buddy_lock;
static spinlock_t pcp_lock;

static struct pcp_area {
    struct list_head list;
    int count;
    uint64_t refill_count;
    uint64_t push_count;
    uint64_t pop_count;
    uint64_t drain_count;
} pcp_areas[CONFIG_MAX_CPUS];

static struct remote_free_queue {
    struct list_head list;
    spinlock_t lock;
    int depth;
    uint64_t enqueue_count;
    uint64_t dequeue_count;
    uint64_t drop_count;
    uint64_t drain_count;
    uint64_t high_water;
} remote_free_queues[CONFIG_MAX_CPUS];

static bool pcp_enabled = (CONFIG_PMM_PCP_MODE != 0);
static uint64_t pcp_disable_count;
static uint64_t pcp_integrity_failures;
static int pcp_last_bad_cpu = -1;
static paddr_t pcp_last_bad_pa;
static char pcp_last_bad_reason[64];

enum pmm_dbg_state {
    PMM_DBG_RESERVED = 0,
    PMM_DBG_BUDDY_FREE = 1,
    PMM_DBG_PCP_FREE = 2,
    PMM_DBG_ALLOCATED = 3,
    PMM_DBG_SLAB = 4,
    PMM_DBG_REMOTE_FREE = 5,
};

static void __free_pages(struct page *page, unsigned int order);
static inline bool page_ptr_valid(struct page *page);
static inline int pmm_sanitize_cpu(int cpu);
static bool pcp_push_page_locked(int cpu, struct page *page);

extern char _kernel_start[], _kernel_end[];

static inline int pcp_mode(void) {
    return CONFIG_PMM_PCP_MODE;
}

static inline int pmm_active_cpus(void) {
    int ncpus = arch_cpu_count();
    if (ncpus < 1)
        ncpus = 1;
    if (ncpus > CONFIG_MAX_CPUS)
        ncpus = CONFIG_MAX_CPUS;
    return ncpus;
}

static inline int pmm_sanitize_cpu(int cpu) {
    int ncpus = pmm_active_cpus();
    if (cpu < 0 || cpu >= ncpus)
        return 0;
    return cpu;
}

static inline bool pcp_debug_enabled(void) {
    return pcp_mode() == 1;
}

#if CONFIG_PMM_DEBUG
static inline void pmm_dbg_set_state(struct page *page, uint16_t state, int cpu) {
    if (!page || page < page_array || page >= page_array + total_pages)
        return;
    page->dbg_state = state;
    page->dbg_last_cpu = (int16_t)cpu;
    page->dbg_seq++;
}
#else
static inline void pmm_dbg_set_state(struct page *page __attribute__((unused)),
                                     uint16_t state __attribute__((unused)),
                                     int cpu __attribute__((unused))) {}
#endif

static void pcp_record_integrity_error(const char *reason, int cpu,
                                       struct page *page) {
    pcp_integrity_failures++;
    pcp_last_bad_cpu = cpu;
    pcp_last_bad_pa = page_ptr_valid(page) ? page_to_phys(page) : 0;
    strncpy(pcp_last_bad_reason, reason, sizeof(pcp_last_bad_reason) - 1);
    pcp_last_bad_reason[sizeof(pcp_last_bad_reason) - 1] = '\0';
    pr_err("pmm: PCP integrity failure on cpu %d: %s (page=%p pa=%p)\n",
           cpu, reason, page, (void *)pcp_last_bad_pa);
#if CONFIG_PMM_INTEGRITY_PANIC
    panic("pmm: PCP integrity failure on cpu %d: %s", cpu, reason);
#endif
}

static int pcp_list_count_locked(struct pcp_area *pcp) {
    int n = 0;
    struct list_head *pos;
    list_for_each(pos, &pcp->list) {
        n++;
        if (n > (int)total_pages)
            break;
    }
    return n;
}

static bool pcp_validate_locked(int cpu, const char *ctx) {
    if (!pcp_debug_enabled())
        return true;
    struct pcp_area *pcp = &pcp_areas[cpu];
    int list_count = pcp_list_count_locked(pcp);
    if (list_count != pcp->count) {
        pcp_record_integrity_error(ctx, cpu, NULL);
        return false;
    }
    struct list_head *pos;
    int seen = 0;
    list_for_each(pos, &pcp->list) {
        struct page *p = list_entry(pos, struct page, list);
        if (!page_ptr_valid(p) || !(p->flags & PG_PCP) || p->refcount != 0 ||
            p->pcp_home_cpu != cpu) {
            pcp_record_integrity_error(ctx, cpu, p);
            return false;
        }
        seen++;
        if (seen > (int)total_pages) {
            pcp_record_integrity_error(ctx, cpu, p);
            return false;
        }
    }
    return true;
}

static void pmm_init_common(void) {
    spin_init(&buddy_lock);
    spin_init(&pcp_lock);
    pcp_enabled = (pcp_mode() != 0);
    pcp_disable_count = 0;
    pcp_integrity_failures = 0;
    pcp_last_bad_cpu = -1;
    pcp_last_bad_pa = 0;
    pcp_last_bad_reason[0] = '\0';
    for (int i = 0; i < MAX_ORDER; i++)
        INIT_LIST_HEAD(&free_lists[i]);
    for (int i = 0; i < CONFIG_MAX_CPUS; i++) {
        INIT_LIST_HEAD(&pcp_areas[i].list);
        pcp_areas[i].count = 0;
        pcp_areas[i].refill_count = 0;
        pcp_areas[i].push_count = 0;
        pcp_areas[i].pop_count = 0;
        pcp_areas[i].drain_count = 0;
        INIT_LIST_HEAD(&remote_free_queues[i].list);
        spin_init(&remote_free_queues[i].lock);
        remote_free_queues[i].depth = 0;
        remote_free_queues[i].enqueue_count = 0;
        remote_free_queues[i].dequeue_count = 0;
        remote_free_queues[i].drop_count = 0;
        remote_free_queues[i].drain_count = 0;
        remote_free_queues[i].high_water = 0;
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
            !(buddy->flags & (PG_RESERVED | PG_PCP)) &&
            (page_to_pfn(page) ^ (1UL << order)) == page_to_pfn(buddy));
}

static inline bool page_ptr_valid(struct page *page) {
    return page && page >= page_array && page < page_array + total_pages;
}

static bool pmm_remote_free_enqueue_locked(struct page *page, int target_cpu) {
    target_cpu = pmm_sanitize_cpu(target_cpu);
    if (!page_ptr_valid(page))
        return false;
    if (page->flags & (PG_RESERVED | PG_PCP)) {
        pcp_record_integrity_error("remote free enqueue invalid flags",
                                   target_cpu, page);
        return false;
    }
    struct remote_free_queue *rq = &remote_free_queues[target_cpu];

    spin_lock(&rq->lock);
    if (rq->depth >= REMOTE_FREE_HIGH) {
        rq->drop_count++;
        spin_unlock(&rq->lock);
        return false;
    }

    page->pcp_home_cpu = (int16_t)target_cpu;
    INIT_LIST_HEAD(&page->list);
    list_add_tail(&page->list, &rq->list);
    rq->depth++;
    rq->enqueue_count++;
    if ((uint64_t)rq->depth > rq->high_water)
        rq->high_water = (uint64_t)rq->depth;
    spin_unlock(&rq->lock);
    pmm_dbg_set_state(page, PMM_DBG_REMOTE_FREE, target_cpu);
    return true;
}

static void pmm_remote_free_flush_cpu_locked(int cpu) {
    cpu = pmm_sanitize_cpu(cpu);
    struct remote_free_queue *rq = &remote_free_queues[cpu];

    while (!list_empty(&rq->list)) {
        struct page *p = list_first_entry(&rq->list, struct page, list);
        list_del(&p->list);
        if (rq->depth > 0)
            rq->depth--;
        rq->dequeue_count++;
        if (!page_ptr_valid(p)) {
            pcp_record_integrity_error("remote free invalid page", cpu, p);
            continue;
        }
        p->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB | PG_PCP);
        p->refcount = 0;
        p->order = 0;
        p->pcp_home_cpu = -1;
        pmm_dbg_set_state(p, PMM_DBG_BUDDY_FREE, cpu);
        __free_pages(p, 0);
    }
}

static size_t pmm_remote_free_drain_local_locked(int cpu, size_t budget) {
    if (budget == 0)
        return 0;

    cpu = pmm_sanitize_cpu(cpu);
    struct remote_free_queue *rq = &remote_free_queues[cpu];
    size_t moved = 0;

    while (moved < budget) {
        struct page *p = NULL;

        spin_lock(&rq->lock);
        if (!list_empty(&rq->list)) {
            p = list_first_entry(&rq->list, struct page, list);
            list_del(&p->list);
            if (rq->depth > 0)
                rq->depth--;
            rq->dequeue_count++;
            rq->drain_count++;
        }
        spin_unlock(&rq->lock);

        if (!p)
            break;

        if (!page_ptr_valid(p)) {
            pcp_record_integrity_error("remote free drain invalid page", cpu, p);
            continue;
        }

        moved++;
        bool pushed_to_pcp = false;
        if (pcp_enabled && pcp_areas[cpu].count < PCP_HIGH) {
            pushed_to_pcp = pcp_push_page_locked(cpu, p);
            if (!pushed_to_pcp)
                pcp_record_integrity_error("remote free push failed", cpu, p);
        }
        if (!pushed_to_pcp) {
            spin_lock(&buddy_lock);
            p->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB | PG_PCP);
            p->refcount = 0;
            p->order = 0;
            p->pcp_home_cpu = -1;
            pmm_dbg_set_state(p, PMM_DBG_BUDDY_FREE, cpu);
            __free_pages(p, 0);
            spin_unlock(&buddy_lock);
        }
    }

    return moved;
}

static void pcp_flush_cpu_locked(int cpu) {
    struct pcp_area *pcp = &pcp_areas[cpu];

    while (!list_empty(&pcp->list)) {
        struct page *p = list_first_entry(&pcp->list, struct page, list);
        list_del(&p->list);
        if (pcp->count > 0)
            pcp->count--;
        if (!page_ptr_valid(p)) {
            pr_err("pmm: invalid page in cpu%d pcp list during flush: %p\n",
                   cpu, p);
            continue;
        }
        p->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB | PG_PCP);
        p->refcount = 0;
        p->order = 0;
        p->pcp_home_cpu = -1;
        pmm_dbg_set_state(p, PMM_DBG_BUDDY_FREE, cpu);
        __free_pages(p, 0);
    }

    pcp->count = 0;
    INIT_LIST_HEAD(&pcp->list);
}

static bool pcp_push_page_locked(int cpu, struct page *page) {
    cpu = pmm_sanitize_cpu(cpu);
    struct pcp_area *pcp = &pcp_areas[cpu];
    if (!page_ptr_valid(page)) {
        pcp_record_integrity_error("pcp push invalid page", cpu, page);
        return false;
    }
    if (page->flags & PG_RESERVED) {
        pcp_record_integrity_error("pcp push reserved page", cpu, page);
        return false;
    }
    if (page->flags & PG_PCP) {
        pcp_record_integrity_error("pcp double free", cpu, page);
        return false;
    }
    page->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB);
    page->flags |= PG_PCP;
    page->refcount = 0;
    page->order = 0;
    page->pcp_home_cpu = (int16_t)cpu;
    INIT_LIST_HEAD(&page->list);
    list_add(&page->list, &pcp->list);
    pcp->count++;
    pcp->push_count++;
    pmm_dbg_set_state(page, PMM_DBG_PCP_FREE, cpu);
    return true;
}

static struct page *pcp_pop_page_locked(int cpu) {
    struct pcp_area *pcp = &pcp_areas[cpu];
    if (list_empty(&pcp->list) || pcp->count <= 0)
        return NULL;
    struct page *page = list_first_entry(&pcp->list, struct page, list);
    list_del(&page->list);
    pcp->count--;
    pcp->pop_count++;
    if (!page_ptr_valid(page)) {
        pcp_record_integrity_error("pcp pop invalid page", cpu, page);
        return NULL;
    }
    if (!(page->flags & PG_PCP)) {
        pcp_record_integrity_error("pcp pop missing PG_PCP", cpu, page);
        return NULL;
    }
    page->flags &= ~PG_PCP;
    page->order = 0;
    page->refcount = 1;
    page->pcp_home_cpu = (int16_t)cpu;
    pmm_dbg_set_state(page, PMM_DBG_ALLOCATED, cpu);
    return page;
}

static void pcp_disable_locked(const char *reason, int cpu) {
    if (!pcp_enabled)
        return;
    pr_warn("pmm: disabling PCP on cpu %d (%s)\n", cpu, reason);
    pcp_disable_count++;
    spin_lock(&buddy_lock);
    for (int i = 0; i < CONFIG_MAX_CPUS; i++) {
        pcp_flush_cpu_locked(i);
        spin_lock(&remote_free_queues[i].lock);
        pmm_remote_free_flush_cpu_locked(i);
        spin_unlock(&remote_free_queues[i].lock);
    }
    spin_unlock(&buddy_lock);
    pcp_enabled = false;
}

static void pcp_disable(const char *reason, int cpu) {
    spin_lock(&pcp_lock);
    pcp_disable_locked(reason, cpu);
    spin_unlock(&pcp_lock);
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
            buddy->pcp_home_cpu = -1;
            buddy->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB | PG_PCP);
            pmm_dbg_set_state(buddy, PMM_DBG_BUDDY_FREE, -1);
            list_add(&buddy->list, &free_lists[o]);
        }

        page->order = order;
        page->refcount = 1;
        page->pcp_home_cpu = -1;
        page->flags &= ~PG_PCP;
        pmm_dbg_set_state(page, PMM_DBG_ALLOCATED, -1);
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
    page->pcp_home_cpu = -1;
    page->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB | PG_PCP);
    pmm_dbg_set_state(page, PMM_DBG_BUDDY_FREE, -1);
    list_add(&page->list, &free_lists[order]);
}

/* Reserve a single free PFN by splitting the containing buddy block. */
static bool reserve_free_pfn_locked(size_t target_pfn) {
    struct page *block = NULL;
    unsigned int order = 0;

    for (unsigned int o = 0; o < MAX_ORDER; o++) {
        struct list_head *pos;
        list_for_each(pos, &free_lists[o]) {
            struct page *cand = list_entry(pos, struct page, list);
            size_t start = page_to_pfn(cand);
            size_t span = 1UL << o;
            if (target_pfn >= start && target_pfn < start + span) {
                block = cand;
                order = o;
                break;
            }
        }
        if (block)
            break;
    }

    if (!block)
        return false;

    list_del(&block->list);
    num_free_pages -= (1UL << order);
    size_t block_pfn = page_to_pfn(block);
    for (size_t i = 0; i < (1UL << order); i++) {
        size_t pfn = block_pfn + i;
        if (pfn != target_pfn && (pfn_to_page(pfn)->flags & PG_RESERVED)) {
            list_add(&block->list, &free_lists[order]);
            num_free_pages += (1UL << order);
            return false;
        }
    }

    while (order > 0) {
        order--;
        size_t right_pfn = block_pfn + (1UL << order);
        bool take_right = target_pfn >= right_pfn;
        struct page *right = pfn_to_page(right_pfn);
        struct page *free_half = take_right ? block : right;
        struct page *keep_half = take_right ? right : block;

        free_half->order = order;
        free_half->refcount = 0;
        free_half->pcp_home_cpu = -1;
        free_half->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB | PG_PCP | PG_RESERVED);
        pmm_dbg_set_state(free_half, PMM_DBG_BUDDY_FREE, -1);
        list_add(&free_half->list, &free_lists[order]);
        num_free_pages += (1UL << order);

        block = keep_half;
        if (take_right)
            block_pfn = right_pfn;
    }

    block->order = 0;
    block->refcount = 0;
    block->flags |= PG_RESERVED;
    block->flags &= ~PG_PCP;
    block->pcp_home_cpu = -1;
    INIT_LIST_HEAD(&block->list);
    pmm_dbg_set_state(block, PMM_DBG_RESERVED, -1);
    return true;
}

/* --- Public API --- */

struct page *alloc_pages(unsigned int order) {
    struct page *page = NULL;
    bool irq = arch_irq_save();
    int cpu = pmm_sanitize_cpu((int)arch_cpu_id());

    if (order == 0) {
        spin_lock(&pcp_lock);
        if (pcp_enabled) {
            pmm_remote_free_drain_local_locked(cpu, REMOTE_FREE_BATCH);
            struct pcp_area *pcp = &pcp_areas[cpu];
            if (!pcp_validate_locked(cpu, "alloc precheck"))
                pcp_disable_locked("alloc precheck failed", cpu);
            if (pcp_enabled && pcp->count == 0) {
                bool bad_page = false;
                spin_lock(&buddy_lock);
                for (int i = 0; i < PCP_BATCH; i++) {
                    struct page *p = __alloc_pages(0);
                    if (!p)
                        break;
                    if (!page_ptr_valid(p)) {
                        pr_err("pmm: invalid page from buddy list (%p)\n", p);
                        bad_page = true;
                        break;
                    }
                    p->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB | PG_PCP);
                    p->refcount = 0;
                    p->order = 0;
                    p->pcp_home_cpu = (int16_t)cpu;
                    if (!pcp_push_page_locked(cpu, p)) {
                        bad_page = true;
                        break;
                    }
                }
                pcp->refill_count++;
                spin_unlock(&buddy_lock);
                if (bad_page)
                    pcp_disable_locked("invalid buddy page", cpu);
            }
            if (pcp_enabled)
                page = pcp_pop_page_locked(cpu);
            if (pcp_enabled && !pcp_validate_locked(cpu, "alloc postcheck"))
                pcp_disable_locked("alloc postcheck failed", cpu);
        }
        spin_unlock(&pcp_lock);
        if (!page) {
            spin_lock(&buddy_lock);
            page = __alloc_pages(0);
            spin_unlock(&buddy_lock);
            if (page && !page_ptr_valid(page)) {
                pr_err("pmm: invalid page from buddy list (%p)\n", page);
                page = NULL;
                pcp_disable("invalid buddy page", cpu);
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

    if (page) {
        page->flags |= PG_KERNEL;
        page->pcp_home_cpu = (int16_t)cpu;
        pmm_dbg_set_state(page, (page->flags & PG_SLAB) ? PMM_DBG_SLAB
                                                         : PMM_DBG_ALLOCATED,
                          cpu);
    }
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
    int cpu = pmm_sanitize_cpu((int)arch_cpu_id());
    page->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB);
    page->refcount = 0;
    page->order = order;
    if (page->flags & PG_RESERVED) {
        page->pcp_home_cpu = -1;
        INIT_LIST_HEAD(&page->list);
        pmm_dbg_set_state(page, PMM_DBG_RESERVED, cpu);
        arch_irq_restore(irq);
        return;
    }

    if (order == 0) {
        bool queued_to_pcp = false;
        bool queued_to_remote = false;
        spin_lock(&pcp_lock);
        if (pcp_enabled) {
            pmm_remote_free_drain_local_locked(cpu, REMOTE_FREE_BATCH);
            struct pcp_area *pcp = &pcp_areas[cpu];
            if (!pcp_validate_locked(cpu, "free precheck"))
                pcp_disable_locked("free precheck failed", cpu);
            if (pcp_enabled) {
                int target_cpu = pmm_sanitize_cpu((int)page->pcp_home_cpu);
                if (target_cpu != cpu)
                    queued_to_remote =
                        pmm_remote_free_enqueue_locked(page, target_cpu);
                if (!queued_to_remote) {
                    if (pcp_push_page_locked(cpu, page)) {
                        queued_to_pcp = true;
                    } else {
                        pcp_disable_locked("free push failed", cpu);
                    }
                }
            }
            if (pcp_enabled && pcp->count >= PCP_HIGH) {
                spin_lock(&buddy_lock);
                for (int i = 0; i < PCP_BATCH; i++) {
                    struct page *p = pcp_pop_page_locked(cpu);
                    if (!p)
                        break;
                    p->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB | PG_PCP);
                    p->refcount = 0;
                    p->order = 0;
                    p->pcp_home_cpu = -1;
                    __free_pages(p, 0);
                    pcp->drain_count++;
                }
                spin_unlock(&buddy_lock);
            }
            if (pcp_enabled && !pcp_validate_locked(cpu, "free postcheck"))
                pcp_disable_locked("free postcheck failed", cpu);
        }
        if (!queued_to_pcp && !queued_to_remote) {
            page->flags &= ~PG_PCP;
            page->pcp_home_cpu = -1;
            spin_lock(&buddy_lock);
            __free_pages(page, order);
            spin_unlock(&buddy_lock);
        }
        spin_unlock(&pcp_lock);
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
    bool irq = arch_irq_save();
    spin_lock(&pcp_lock);
    spin_lock(&buddy_lock);
    size_t total = num_free_pages;
    int ncpus = pmm_active_cpus();
    for (int i = 0; i < ncpus; i++) {
        total += (size_t)pcp_areas[i].count;
        total += (size_t)remote_free_queues[i].depth;
    }
    spin_unlock(&buddy_lock);
    spin_unlock(&pcp_lock);
    arch_irq_restore(irq);
    return total;
}

int pmm_pcp_report(char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    bool irq = arch_irq_save();
    spin_lock(&pcp_lock);
    int ncpus = pmm_active_cpus();
    int len = snprintf(buf, bufsz,
                       "pcp_mode=%d pcp_enabled=%d disable_count=%llu "
                       "integrity_failures=%llu\n",
                       pcp_mode(), pcp_enabled ? 1 : 0,
                       (unsigned long long)pcp_disable_count,
                       (unsigned long long)pcp_integrity_failures);
    for (int i = 0; i < ncpus && (size_t)len < bufsz; i++) {
        struct pcp_area *pcp = &pcp_areas[i];
        len += snprintf(buf + len, bufsz - (size_t)len,
                        "cpu%d count=%d refill=%llu push=%llu pop=%llu drain=%llu\n",
                        i, pcp->count,
                        (unsigned long long)pcp->refill_count,
                        (unsigned long long)pcp->push_count,
                        (unsigned long long)pcp->pop_count,
                        (unsigned long long)pcp->drain_count);
    }
    spin_unlock(&pcp_lock);
    arch_irq_restore(irq);
    return len;
}

int pmm_remote_free_report(char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    bool irq = arch_irq_save();
    spin_lock(&pcp_lock);
    int ncpus = pmm_active_cpus();
    uint64_t total_depth = 0;
    uint64_t total_drop = 0;
    int len = snprintf(buf, bufsz,
                       "remote_free_batch=%d remote_free_high=%d\n",
                       REMOTE_FREE_BATCH, REMOTE_FREE_HIGH);
    for (int i = 0; i < ncpus && (size_t)len < bufsz; i++) {
        struct remote_free_queue *rq = &remote_free_queues[i];
        total_depth += (uint64_t)rq->depth;
        total_drop += rq->drop_count;
        len += snprintf(buf + len, bufsz - (size_t)len,
                        "cpu%d depth=%d enq=%llu deq=%llu drop=%llu "
                        "drain=%llu high=%llu\n",
                        i, rq->depth,
                        (unsigned long long)rq->enqueue_count,
                        (unsigned long long)rq->dequeue_count,
                        (unsigned long long)rq->drop_count,
                        (unsigned long long)rq->drain_count,
                        (unsigned long long)rq->high_water);
    }
    if ((size_t)len < bufsz) {
        len += snprintf(buf + len, bufsz - (size_t)len,
                        "total_depth=%llu total_drop=%llu\n",
                        (unsigned long long)total_depth,
                        (unsigned long long)total_drop);
    }
    spin_unlock(&pcp_lock);
    arch_irq_restore(irq);
    return len;
}

int pmm_integrity_report(char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    bool irq = arch_irq_save();
    spin_lock(&pcp_lock);
    spin_lock(&buddy_lock);
    uint64_t bad_flags = 0;
    uint64_t bad_refcount = 0;
    uint64_t bad_cpu_hint = 0;
    uint64_t debug_state_mismatch = 0;
    uint64_t state_count[6] = {0};
    int ncpus = pmm_active_cpus();
    for (size_t i = 0; i < total_pages; i++) {
        struct page *p = &page_array[i];
        if (p->pcp_home_cpu < -1 || p->pcp_home_cpu >= ncpus)
            bad_cpu_hint++;
        if ((p->flags & PG_PCP) && (p->flags & (PG_RESERVED | PG_SLAB)))
            bad_flags++;
        if ((p->flags & PG_PCP) && p->refcount != 0)
            bad_refcount++;
#if CONFIG_PMM_DEBUG
        if (p->dbg_state <= PMM_DBG_REMOTE_FREE)
            state_count[p->dbg_state]++;
        switch (p->dbg_state) {
        case PMM_DBG_RESERVED:
            if (!(p->flags & PG_RESERVED))
                debug_state_mismatch++;
            break;
        case PMM_DBG_BUDDY_FREE:
            if ((p->flags & (PG_RESERVED | PG_PCP | PG_SLAB)) || p->refcount)
                debug_state_mismatch++;
            break;
        case PMM_DBG_PCP_FREE:
            if (!(p->flags & PG_PCP) || p->refcount)
                debug_state_mismatch++;
            break;
        case PMM_DBG_REMOTE_FREE:
            if ((p->flags & (PG_PCP | PG_RESERVED)) || p->refcount)
                debug_state_mismatch++;
            break;
        case PMM_DBG_ALLOCATED:
            if ((p->flags & (PG_RESERVED | PG_PCP)) || p->refcount == 0)
                debug_state_mismatch++;
            break;
        case PMM_DBG_SLAB:
            if (!(p->flags & PG_SLAB))
                debug_state_mismatch++;
            break;
        default:
            debug_state_mismatch++;
            break;
        }
#endif
    }
    int len = snprintf(
        buf, bufsz,
        "pcp_integrity_failures=%llu\n"
        "pcp_last_bad_cpu=%d\n"
        "pcp_last_bad_pa=%p\n"
        "pcp_last_bad_reason=%s\n"
        "bad_flags=%llu\n"
        "bad_refcount=%llu\n"
        "bad_cpu_hint=%llu\n"
        "debug_state_mismatch=%llu\n"
        "status=%s\n",
        (unsigned long long)pcp_integrity_failures,
        pcp_last_bad_cpu,
        (void *)pcp_last_bad_pa,
        pcp_last_bad_reason[0] ? pcp_last_bad_reason : "none",
        (unsigned long long)bad_flags,
        (unsigned long long)bad_refcount,
        (unsigned long long)bad_cpu_hint,
        (unsigned long long)debug_state_mismatch,
        (pcp_integrity_failures || bad_flags || bad_refcount || bad_cpu_hint ||
         debug_state_mismatch)
            ? "fail"
            : "pass");
#if CONFIG_PMM_DEBUG
    if ((size_t)len < bufsz) {
        len += snprintf(buf + len, bufsz - (size_t)len,
                        "state_reserved=%llu state_buddy_free=%llu "
                        "state_pcp_free=%llu state_allocated=%llu "
                        "state_slab=%llu state_remote_free=%llu\n",
                        (unsigned long long)state_count[PMM_DBG_RESERVED],
                        (unsigned long long)state_count[PMM_DBG_BUDDY_FREE],
                        (unsigned long long)state_count[PMM_DBG_PCP_FREE],
                        (unsigned long long)state_count[PMM_DBG_ALLOCATED],
                        (unsigned long long)state_count[PMM_DBG_SLAB],
                        (unsigned long long)state_count[PMM_DBG_REMOTE_FREE]);
    }
#endif
    spin_unlock(&buddy_lock);
    spin_unlock(&pcp_lock);
    arch_irq_restore(irq);
    return len;
}

size_t pmm_remote_free_drain_local(size_t budget) {
    if (budget == 0)
        return 0;
    bool irq = arch_irq_save();
    spin_lock(&pcp_lock);
    int cpu = pmm_sanitize_cpu((int)arch_cpu_id());
    size_t drained = pmm_remote_free_drain_local_locked(cpu, budget);
    spin_unlock(&pcp_lock);
    arch_irq_restore(irq);
    return drained;
}

void pmm_debug_mark_slab_page(struct page *page, bool active) {
    if (!page_ptr_valid(page))
        return;
    int cpu = pmm_sanitize_cpu((int)arch_cpu_id());
    pmm_dbg_set_state(page, active ? PMM_DBG_SLAB : PMM_DBG_ALLOCATED, cpu);
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
    uint32_t old;
    for (;;) {
        old = __atomic_load_n(&p->refcount, __ATOMIC_RELAXED);
        if (old == 0) {
            pr_err("pmm: put on free page %p (pa=%p)\n", p, (void *)pa);
            return;
        }
        if (__atomic_compare_exchange_n(&p->refcount, &old, old - 1,
                                        false, __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
            break;
    }
    if (old == 1)
        free_pages(p, 0);
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
    spin_lock(&pcp_lock);
    spin_lock(&buddy_lock);
    int ncpus = pmm_active_cpus();
    for (int i = 0; i < ncpus; i++) {
        pcp_flush_cpu_locked(i);
        spin_lock(&remote_free_queues[i].lock);
        pmm_remote_free_flush_cpu_locked(i);
        spin_unlock(&remote_free_queues[i].lock);
    }
    for (paddr_t a = start; a < end; a += PAGE_SIZE) {
        struct page *p = phys_to_page(a);
        if (p) {
            if (!(p->flags & PG_RESERVED) && p->refcount == 0 &&
                !(p->flags & (PG_PCP | PG_SLAB))) {
                reserve_free_pfn_locked(page_to_pfn(p));
            }
            p->flags |= PG_RESERVED;
            p->flags &= ~PG_PCP;
            p->pcp_home_cpu = -1;
            pmm_dbg_set_state(p, PMM_DBG_RESERVED, (int)arch_cpu_id());
        }
    }
    spin_unlock(&buddy_lock);
    spin_unlock(&pcp_lock);
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
        p->flags &= ~(PG_KERNEL | PG_USER | PG_SLAB | PG_PCP);
        pmm_dbg_set_state(p, PMM_DBG_BUDDY_FREE, -1);
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
        page_array[i].pcp_home_cpu = -1;
        INIT_LIST_HEAD(&page_array[i].list);
#if CONFIG_PMM_DEBUG
        page_array[i].dbg_state = (i < array_pages) ? PMM_DBG_RESERVED : PMM_DBG_BUDDY_FREE;
        page_array[i].dbg_last_cpu = -1;
        page_array[i].dbg_seq = 0;
#endif
    }

    paddr_t ks = virt_to_phys(_kernel_start);
    paddr_t ke = virt_to_phys(_kernel_end);
    ke = ALIGN_UP(ke, PAGE_SIZE);
    if (ks >= mem_start && ks < mem_end) {
        for (size_t i = (ks - mem_start) >> PAGE_SHIFT; i < (ke - mem_start) >> PAGE_SHIFT && i < total_pages; i++)
            page_array[i].flags |= PG_RESERVED | PG_KERNEL;
#if CONFIG_PMM_DEBUG
        for (size_t i = (ks - mem_start) >> PAGE_SHIFT; i < (ke - mem_start) >> PAGE_SHIFT && i < total_pages; i++)
            page_array[i].dbg_state = PMM_DBG_RESERVED;
#endif
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

    paddr_t ks = virt_to_phys(_kernel_start);
    paddr_t ke = ALIGN_UP(virt_to_phys(_kernel_end), PAGE_SIZE);

    size_t array_bytes = array_pages * PAGE_SIZE;
    paddr_t array_base = 0;
    for (uint32_t i = 0; i < bi->memmap_count; i++) {
        const struct boot_memmap_entry *e = &bi->memmap[i];
        if (e->type != BOOT_MEM_USABLE)
            continue;
        paddr_t start = MAX(e->base, mem_start);
        paddr_t end = MIN(e->base + e->length, mem_end);
        start = ALIGN_UP(start, PAGE_SIZE);
        end = ALIGN_DOWN(end, PAGE_SIZE);
        if (end <= start)
            continue;
        if (start <= ks && ks < end) {
            if (ks > start && (size_t)(ks - start) >= array_bytes) {
                array_base = start;
                break;
            }
            paddr_t after = ALIGN_UP(ke, PAGE_SIZE);
            if (after < end && (size_t)(end - after) >= array_bytes) {
                array_base = after;
                break;
            }
            continue;
        }
        if ((size_t)(end - start) >= array_bytes) {
            array_base = start;
            break;
        }
    }
    if (!array_base) {
        panic("pmm: no space for page array");
    }

    page_array = (struct page *)phys_to_virt(array_base);


    for (size_t i = 0; i < total_pages; i++) {
        page_array[i].flags = PG_RESERVED;
        page_array[i].refcount = 0;
        page_array[i].pcp_home_cpu = -1;
        INIT_LIST_HEAD(&page_array[i].list);
#if CONFIG_PMM_DEBUG
        page_array[i].dbg_state = PMM_DBG_RESERVED;
        page_array[i].dbg_last_cpu = -1;
        page_array[i].dbg_seq = 0;
#endif
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
#if CONFIG_PMM_DEBUG
            page_array[pfn].dbg_state = PMM_DBG_BUDDY_FREE;
#endif
        }
    }

    /* Reserve page array itself */
    size_t array_start_pfn = (array_base - mem_start) >> PAGE_SHIFT;
    for (size_t i = 0; i < array_pages && (array_start_pfn + i) < total_pages;
         i++) {
        page_array[array_start_pfn + i].flags |= PG_RESERVED;
#if CONFIG_PMM_DEBUG
        page_array[array_start_pfn + i].dbg_state = PMM_DBG_RESERVED;
#endif
    }

    /* Reserve kernel image */
    if (ks >= mem_start && ks < mem_end) {
        size_t s = (ks - mem_start) >> PAGE_SHIFT;
        size_t e = (ke - mem_start) >> PAGE_SHIFT;
        if (e > total_pages)
            e = total_pages;
        for (size_t pfn = s; pfn < e; pfn++) {
            page_array[pfn].flags |= PG_RESERVED | PG_KERNEL;
#if CONFIG_PMM_DEBUG
            page_array[pfn].dbg_state = PMM_DBG_RESERVED;
#endif
        }
    }

    if (mem_start == 0 && total_pages > 0) {
        page_array[0].flags |= PG_RESERVED;
#if CONFIG_PMM_DEBUG
        page_array[0].dbg_state = PMM_DBG_RESERVED;
#endif
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
