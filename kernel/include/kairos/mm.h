/**
 * kernel/include/kairos/mm.h - Memory management interfaces
 */

#ifndef _KAIROS_MM_H
#define _KAIROS_MM_H

#include <kairos/list.h>
#include <kairos/rbtree.h>
#include <kairos/spinlock.h>
#include <kairos/sync.h>
#include <kairos/types.h>

struct boot_info;

#define MAX_ORDER 11
#define PG_RESERVED (1 << 0)
#define PG_KERNEL (1 << 1)
#define PG_USER (1 << 2)
#define PG_SLAB (1 << 3)

struct page {
    uint32_t flags, order, refcount;
    struct list_head list;
};

void pmm_init(paddr_t start, paddr_t end);
void pmm_init_from_memmap(const struct boot_info *bi);
paddr_t pmm_alloc_page(void);
paddr_t pmm_alloc_pages(size_t count);
void pmm_free_page(paddr_t pa);
void pmm_free_pages(paddr_t pa, size_t count);
void pmm_get_page(paddr_t pa);
void pmm_put_page(paddr_t pa);
int pmm_page_refcount(paddr_t pa);
size_t pmm_num_free_pages(void);
size_t pmm_total_pages(void);
struct page *alloc_pages(unsigned int order);
void free_pages(struct page *page, unsigned int order);
static inline struct page *alloc_page(void) {
    return alloc_pages(0);
}
static inline void free_page(struct page *page) {
    free_pages(page, 0);
}
paddr_t page_to_phys(struct page *page);
struct page *phys_to_page(paddr_t addr);

/* Kernel Heap Initialization */
void kmalloc_init(void);
void *kmalloc(size_t size);
void kfree(void *ptr);
void *kzalloc(size_t size);
void *kmalloc_aligned(size_t size, size_t align);
void kfree_aligned(void *ptr);

/* kmem_cache (SLUB) Allocator */
struct kmem_cache;

struct kmem_cache *kmem_cache_create(const char *name, size_t size,
                                     void (*ctor)(void *));
void *kmem_cache_alloc(struct kmem_cache *cache);
void kmem_cache_free(struct kmem_cache *cache, void *obj);

/* Virtual Memory Manager */
void vmm_init(void);

#define PTE_VALID (1 << 0)
#define PTE_READ (1 << 1)
#define PTE_WRITE (1 << 2)
#define PTE_EXEC (1 << 3)
#define PTE_USER (1 << 4)
#define PTE_GLOBAL (1 << 5)
#define PTE_COW (1 << 8)

#define VM_READ (1 << 0)
#define VM_WRITE (1 << 1)
#define VM_EXEC (1 << 2)
#define VM_SHARED (1 << 3)
#define VM_STACK (1 << 4)

/* User address space layout */
#define USER_SPACE_START 0x00000000UL
#define USER_SPACE_END 0x0000003FFFFFFFFFULL
#define USER_HEAP_START 0x00000001000000UL
#define USER_STACK_TOP 0x0000003FF0000000ULL
#define USER_STACK_SIZE (64 * 1024)

/* Virtual Memory Area (VMA) */
struct vm_area {
    vaddr_t start, end;
    uint32_t flags;
    struct list_head list;
    struct rb_node rb_node;
    struct vnode *vnode;
    off_t offset;
    vaddr_t file_start;
    vaddr_t file_end;
};

struct mm_struct {
    paddr_t pgdir;
    struct list_head vma_list;
    struct rb_root mm_rb;
    struct mutex lock;
    vaddr_t brk, start_stack;
    uint32_t refcount;
};

struct mm_struct *mm_create(void);
void mm_destroy(struct mm_struct *mm);
struct mm_struct *mm_clone(struct mm_struct *src);
struct vm_area *mm_find_vma(struct mm_struct *mm, vaddr_t addr);
void mm_unmap_range(paddr_t pgdir, vaddr_t start, vaddr_t end);
void mm_unmap_range_noflush(paddr_t pgdir, vaddr_t start, vaddr_t end);
int mm_handle_fault(struct mm_struct *mm, vaddr_t addr, uint32_t flags);
int mm_add_vma(struct mm_struct *mm, vaddr_t start, vaddr_t end,
               uint32_t flags, struct vnode *vn, off_t offset);
int mm_add_vma_file(struct mm_struct *mm, vaddr_t start, vaddr_t end,
                    uint32_t flags, struct vnode *vn, off_t offset,
                    vaddr_t file_start, vaddr_t file_end);
int mm_mmap(struct mm_struct *mm, vaddr_t addr, size_t len, uint32_t prot,
            uint32_t flags, struct vnode *vn, off_t offset, bool fixed,
            vaddr_t *out);
int mm_munmap(struct mm_struct *mm, vaddr_t addr, size_t len);
int mm_mremap(struct mm_struct *mm, vaddr_t old_addr, size_t old_len,
              size_t new_len, uint32_t flags, vaddr_t new_addr,
              vaddr_t *out);
int mm_mprotect(struct mm_struct *mm, vaddr_t addr, size_t len,
                uint32_t prot);

void *phys_to_virt(paddr_t addr);
paddr_t virt_to_phys(void *addr);
void *ioremap(paddr_t phys, size_t size);
void iounmap(void *virt);

#endif
