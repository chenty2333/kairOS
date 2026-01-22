/**
 * kairos/mm.h - Memory management interfaces
 */

#ifndef _KAIROS_MM_H
#define _KAIROS_MM_H

#include <kairos/types.h>
#include <kairos/config.h>
#include <kairos/list.h>
#include <kairos/spinlock.h>

/*
 * Physical Page Allocator (Buddy System)
 */

#define MAX_ORDER       11          /* Up to 2^10 = 1024 pages = 4MB */

/* Page flags */
#define PG_RESERVED     (1 << 0)    /* Cannot be allocated */
#define PG_KERNEL       (1 << 1)    /* Kernel use */
#define PG_USER         (1 << 2)    /* User space */
#define PG_SLAB         (1 << 3)    /* Used by slab allocator */

struct page {
    uint32_t flags;
    uint32_t order;                 /* Buddy order if free */
    uint32_t refcount;
    struct list_head list;          /* Free list linkage */
};

/* Initialize physical memory manager */
void pmm_init(paddr_t start, paddr_t end);

/*
 * Phase 0: Simple bitmap allocator
 * These will be replaced by buddy allocator in Phase 1.
 */
paddr_t pmm_alloc_page(void);
paddr_t pmm_alloc_pages(size_t count);
void pmm_free_page(paddr_t pa);
void pmm_free_pages(paddr_t pa, size_t count);
size_t pmm_get_free_pages(void);
size_t pmm_get_total_pages(void);
void pmm_reserve_range(paddr_t start, paddr_t end);

/* Allocate 2^order contiguous pages (Phase 1+) */
struct page *alloc_pages(unsigned int order);

/* Free pages allocated with alloc_pages */
void free_pages(struct page *page, unsigned int order);

/* Single page allocation helpers */
static inline struct page *alloc_page(void)
{
    return alloc_pages(0);
}

static inline void free_page(struct page *page)
{
    free_pages(page, 0);
}

/* Convert between page struct and physical address */
paddr_t page_to_phys(struct page *page);
struct page *phys_to_page(paddr_t addr);

/* Get total/free memory (Phase 1+ API) */
size_t pmm_total_pages(void);
size_t pmm_num_free_pages(void);

/*
 * Kernel Heap Initialization
 */

/* Initialize kernel heap allocator */
void kmalloc_init(void);

/* Print allocator statistics */
void kmalloc_stats(void);

/* Free aligned memory */
void kfree_aligned(void *ptr);

/*
 * Virtual Memory Manager Initialization
 */

/* Initialize virtual memory manager */
void vmm_init(void);

/*
 * Kernel Heap (kmalloc)
 */

/* Allocate kernel memory */
void *kmalloc(size_t size);

/* Free kernel memory */
void kfree(void *ptr);

/* Allocate zeroed memory */
void *kzalloc(size_t size);

/* Allocate aligned memory */
void *kmalloc_aligned(size_t size, size_t align);

/*
 * Virtual Memory
 */

/* Page table entry flags */
#define PTE_VALID       (1 << 0)
#define PTE_READ        (1 << 1)
#define PTE_WRITE       (1 << 2)
#define PTE_EXEC        (1 << 3)
#define PTE_USER        (1 << 4)
#define PTE_GLOBAL      (1 << 5)
#define PTE_ACCESSED    (1 << 6)
#define PTE_DIRTY       (1 << 7)

/* Memory region flags for mmap */
#define VM_READ         (1 << 0)
#define VM_WRITE        (1 << 1)
#define VM_EXEC         (1 << 2)
#define VM_SHARED       (1 << 3)
#define VM_GROWSDOWN    (1 << 4)    /* Stack */

/* Virtual memory area (VMA) */
struct vm_area {
    vaddr_t start;
    vaddr_t end;
    uint32_t flags;
    struct list_head list;

    /* For file-backed mappings */
    struct vnode *vnode;
    off_t offset;
};

/* Process address space */
struct mm_struct {
    paddr_t pgdir;                  /* Page directory physical address */
    struct list_head vma_list;      /* List of VMAs */
    spinlock_t lock;

    vaddr_t brk;                    /* Current brk (heap end) */
    vaddr_t start_stack;            /* Stack start */

    uint32_t refcount;              /* For shared address spaces (threads) */
};

/* Create new address space */
struct mm_struct *mm_create(void);

/* Destroy address space */
void mm_destroy(struct mm_struct *mm);

/* Clone address space (for fork) */
struct mm_struct *mm_clone(struct mm_struct *src);

/* Map virtual address to physical */
int mm_map_page(struct mm_struct *mm, vaddr_t va, paddr_t pa, uint32_t flags);

/* Unmap virtual address */
int mm_unmap_page(struct mm_struct *mm, vaddr_t va);

/* Handle page fault */
int mm_handle_fault(struct mm_struct *mm, vaddr_t addr, uint32_t flags);

/* brk syscall implementation */
vaddr_t mm_brk(struct mm_struct *mm, vaddr_t newbrk);

/* mmap syscall implementation */
vaddr_t mm_mmap(struct mm_struct *mm, vaddr_t addr, size_t len,
                uint32_t prot, uint32_t flags, struct vnode *vn, off_t offset);

/* munmap syscall implementation */
int mm_munmap(struct mm_struct *mm, vaddr_t addr, size_t len);

/*
 * Kernel Virtual Memory
 */

/* Map physical memory into kernel space */
void *phys_to_virt(paddr_t addr);
paddr_t virt_to_phys(void *addr);

/* Map device MMIO */
void *ioremap(paddr_t phys, size_t size);
void iounmap(void *virt);

#endif /* _KAIROS_MM_H */
