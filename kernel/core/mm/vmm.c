/**
 * vmm.c - Virtual Memory Management
 *
 * Implements process address space management including:
 * - mm_struct creation and destruction
 * - VMA (Virtual Memory Area) management
 * - Page fault handling
 * - mmap/munmap/brk syscall support
 */

#include <kairos/types.h>
#include <kairos/mm.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/config.h>

#define PAGE_SIZE       CONFIG_PAGE_SIZE
#define PAGE_SHIFT      CONFIG_PAGE_SHIFT
#define PAGE_MASK       (~(PAGE_SIZE - 1))

/* User space address limits (for Sv39) */
#define USER_SPACE_START    0x00000000UL
#define USER_SPACE_END      0x0000003FFFFFFFFFULL  /* 256GB user space */

/* Default heap and stack locations */
#define USER_HEAP_START     0x00000001000000UL      /* 16MB */
#define USER_STACK_TOP      0x0000003FF0000000ULL   /* Near top of user space */

/* Maximum number of VMAs per process */
#define MAX_VMAS            128

/* VMA cache for quick allocation */
static struct vm_area vma_cache[MAX_VMAS * CONFIG_MAX_PROCESSES];
static struct list_head free_vmas;
static spinlock_t vma_lock;

/**
 * vma_alloc - Allocate a VMA structure
 */
static struct vm_area *vma_alloc(void)
{
    spin_lock(&vma_lock);

    if (list_empty(&free_vmas)) {
        spin_unlock(&vma_lock);
        return NULL;
    }

    struct vm_area *vma = list_first_entry(&free_vmas, struct vm_area, list);
    list_del(&vma->list);

    spin_unlock(&vma_lock);
    return vma;
}

/**
 * vma_free - Return a VMA to the cache
 */
static void vma_free(struct vm_area *vma)
{
    spin_lock(&vma_lock);
    list_add(&vma->list, &free_vmas);
    spin_unlock(&vma_lock);
}

/**
 * vmm_init - Initialize the virtual memory manager
 */
void vmm_init(void)
{
    spin_init(&vma_lock);
    INIT_LIST_HEAD(&free_vmas);

    /* Initialize VMA cache */
    for (size_t i = 0; i < ARRAY_SIZE(vma_cache); i++) {
        list_add(&vma_cache[i].list, &free_vmas);
    }

    pr_info("VMM: Initialized with %lu VMAs available\n", ARRAY_SIZE(vma_cache));
}

/**
 * mm_create - Create a new address space
 *
 * Returns pointer to new mm_struct, or NULL on failure.
 */
struct mm_struct *mm_create(void)
{
    struct mm_struct *mm = kzalloc(sizeof(struct mm_struct));
    if (!mm) {
        return NULL;
    }

    /* Create page table */
    mm->pgdir = arch_mmu_create_table();
    if (mm->pgdir == 0) {
        kfree(mm);
        return NULL;
    }

    INIT_LIST_HEAD(&mm->vma_list);
    spin_init(&mm->lock);
    mm->brk = USER_HEAP_START;
    mm->start_stack = USER_STACK_TOP;
    mm->refcount = 1;

    return mm;
}

/**
 * mm_destroy - Destroy an address space
 * @mm: Address space to destroy
 */
void mm_destroy(struct mm_struct *mm)
{
    if (!mm) {
        return;
    }

    spin_lock(&mm->lock);

    if (--mm->refcount > 0) {
        spin_unlock(&mm->lock);
        return;
    }

    /* Free all VMAs */
    struct vm_area *vma, *tmp;
    list_for_each_entry_safe(vma, tmp, &mm->vma_list, list) {
        /* Unmap and free pages in this VMA */
        for (vaddr_t va = vma->start; va < vma->end; va += PAGE_SIZE) {
            paddr_t pa = arch_mmu_translate(mm->pgdir, va);
            if (pa) {
                arch_mmu_unmap(mm->pgdir, va);
                pmm_free_page(pa);
            }
        }

        list_del(&vma->list);
        vma_free(vma);
    }

    /* Destroy page table */
    arch_mmu_destroy_table(mm->pgdir);

    spin_unlock(&mm->lock);

    kfree(mm);
}

/**
 * find_vma - Find VMA containing given address
 */
static struct vm_area *find_vma(struct mm_struct *mm, vaddr_t addr)
{
    struct vm_area *vma;

    list_for_each_entry(vma, &mm->vma_list, list) {
        if (addr >= vma->start && addr < vma->end) {
            return vma;
        }
    }

    return NULL;
}

/**
 * find_vma_intersection - Find VMA that overlaps with range
 */
static struct vm_area *find_vma_intersection(struct mm_struct *mm,
                                             vaddr_t start, vaddr_t end)
{
    struct vm_area *vma;

    list_for_each_entry(vma, &mm->vma_list, list) {
        if (vma->start < end && vma->end > start) {
            return vma;
        }
    }

    return NULL;
}

/**
 * insert_vma - Insert VMA into address space (sorted by address)
 */
static void insert_vma(struct mm_struct *mm, struct vm_area *new_vma)
{
    struct vm_area *vma;

    list_for_each_entry(vma, &mm->vma_list, list) {
        if (new_vma->start < vma->start) {
            list_add_tail(&new_vma->list, &vma->list);
            return;
        }
    }

    list_add_tail(&new_vma->list, &mm->vma_list);
}

/**
 * mm_clone - Clone an address space (for fork)
 * @src: Source address space
 *
 * Returns new cloned mm_struct, or NULL on failure.
 */
struct mm_struct *mm_clone(struct mm_struct *src)
{
    struct mm_struct *dst = mm_create();
    if (!dst) {
        return NULL;
    }

    spin_lock(&src->lock);

    dst->brk = src->brk;
    dst->start_stack = src->start_stack;

    /* Clone all VMAs */
    struct vm_area *src_vma;
    list_for_each_entry(src_vma, &src->vma_list, list) {
        struct vm_area *dst_vma = vma_alloc();
        if (!dst_vma) {
            goto fail;
        }

        dst_vma->start = src_vma->start;
        dst_vma->end = src_vma->end;
        dst_vma->flags = src_vma->flags;
        dst_vma->vnode = src_vma->vnode;
        dst_vma->offset = src_vma->offset;

        insert_vma(dst, dst_vma);

        /* Copy page mappings */
        for (vaddr_t va = src_vma->start; va < src_vma->end; va += PAGE_SIZE) {
            paddr_t src_pa = arch_mmu_translate(src->pgdir, va);
            if (src_pa == 0) {
                continue;
            }

            /* Allocate new page */
            paddr_t dst_pa = pmm_alloc_page();
            if (dst_pa == 0) {
                goto fail;
            }

            /* Copy page contents */
            uint8_t *src_ptr = (uint8_t *)phys_to_virt(src_pa);
            uint8_t *dst_ptr = (uint8_t *)phys_to_virt(dst_pa);
            for (size_t i = 0; i < PAGE_SIZE; i++) {
                dst_ptr[i] = src_ptr[i];
            }

            /* Map in destination */
            uint64_t flags = PTE_READ;
            if (dst_vma->flags & VM_WRITE) {
                flags |= PTE_WRITE;
            }
            if (dst_vma->flags & VM_EXEC) {
                flags |= PTE_EXEC;
            }
            flags |= PTE_USER;

            if (arch_mmu_map(dst->pgdir, va, dst_pa, flags) < 0) {
                pmm_free_page(dst_pa);
                goto fail;
            }
        }
    }

    spin_unlock(&src->lock);
    return dst;

fail:
    spin_unlock(&src->lock);
    mm_destroy(dst);
    return NULL;
}

/**
 * mm_map_page - Map a single page in the address space
 * @mm: Address space
 * @va: Virtual address to map
 * @pa: Physical address to map to
 * @flags: Page flags
 */
int mm_map_page(struct mm_struct *mm, vaddr_t va, paddr_t pa, uint32_t flags)
{
    spin_lock(&mm->lock);
    int ret = arch_mmu_map(mm->pgdir, va, pa, flags);
    spin_unlock(&mm->lock);
    return ret;
}

/**
 * mm_unmap_page - Unmap a single page from the address space
 * @mm: Address space
 * @va: Virtual address to unmap
 */
int mm_unmap_page(struct mm_struct *mm, vaddr_t va)
{
    spin_lock(&mm->lock);
    int ret = arch_mmu_unmap(mm->pgdir, va);
    spin_unlock(&mm->lock);
    return ret;
}

/**
 * mm_handle_fault - Handle a page fault
 * @mm: Address space
 * @addr: Faulting address
 * @flags: Fault flags (write, user, etc.)
 *
 * Returns 0 if fault handled, negative error otherwise.
 */
int mm_handle_fault(struct mm_struct *mm, vaddr_t addr, uint32_t flags)
{
    spin_lock(&mm->lock);

    struct vm_area *vma = find_vma(mm, addr);
    if (!vma) {
        spin_unlock(&mm->lock);
        return -EFAULT;  /* SIGSEGV */
    }

    /* Check permissions */
    bool is_write = (flags & PTE_WRITE) != 0;
    if (is_write && !(vma->flags & VM_WRITE)) {
        spin_unlock(&mm->lock);
        return -EACCES;  /* SIGSEGV */
    }

    vaddr_t page_va = ALIGN_DOWN(addr, PAGE_SIZE);

    /* Check if already mapped */
    if (arch_mmu_translate(mm->pgdir, page_va)) {
        /* Already mapped - could be COW or permission issue */
        spin_unlock(&mm->lock);
        return -EEXIST;
    }

    /* Allocate a page */
    paddr_t pa = pmm_alloc_page();
    if (pa == 0) {
        spin_unlock(&mm->lock);
        return -ENOMEM;
    }

    /* Zero the page */
    uint8_t *ptr = phys_to_virt(pa);
    for (size_t i = 0; i < PAGE_SIZE; i++) {
        ptr[i] = 0;
    }

    /* Map the page */
    uint64_t pte_flags = PTE_USER | PTE_READ;
    if (vma->flags & VM_WRITE) {
        pte_flags |= PTE_WRITE;
    }
    if (vma->flags & VM_EXEC) {
        pte_flags |= PTE_EXEC;
    }

    int ret = arch_mmu_map(mm->pgdir, page_va, pa, pte_flags);
    if (ret < 0) {
        pmm_free_page(pa);
    }

    spin_unlock(&mm->lock);
    return ret;
}

/**
 * mm_brk - Implement brk() syscall
 * @mm: Address space
 * @newbrk: New brk value (0 to query current)
 *
 * Returns new brk value, or current brk on failure.
 */
vaddr_t mm_brk(struct mm_struct *mm, vaddr_t newbrk)
{
    spin_lock(&mm->lock);

    vaddr_t oldbrk = mm->brk;

    if (newbrk == 0 || newbrk < USER_HEAP_START) {
        spin_unlock(&mm->lock);
        return oldbrk;
    }

    /* Align to page boundary */
    newbrk = ALIGN_UP(newbrk, PAGE_SIZE);

    /* Check limits */
    if (newbrk >= mm->start_stack) {
        spin_unlock(&mm->lock);
        return oldbrk;
    }

    /* Shrinking heap */
    if (newbrk < oldbrk) {
        for (vaddr_t va = newbrk; va < oldbrk; va += PAGE_SIZE) {
            paddr_t pa = arch_mmu_translate(mm->pgdir, va);
            if (pa) {
                arch_mmu_unmap(mm->pgdir, va);
                pmm_free_page(pa);
            }
        }
    }

    mm->brk = newbrk;

    /* Find or create heap VMA */
    struct vm_area *heap_vma = find_vma(mm, USER_HEAP_START);
    if (!heap_vma) {
        heap_vma = vma_alloc();
        if (heap_vma) {
            heap_vma->start = USER_HEAP_START;
            heap_vma->end = newbrk;
            heap_vma->flags = VM_READ | VM_WRITE;
            heap_vma->vnode = NULL;
            heap_vma->offset = 0;
            insert_vma(mm, heap_vma);
        }
    } else {
        heap_vma->end = newbrk;
    }

    spin_unlock(&mm->lock);
    return newbrk;
}

/**
 * mm_mmap - Implement mmap() syscall
 * @mm: Address space
 * @addr: Requested address (hint, may be 0)
 * @len: Length of mapping
 * @prot: Protection flags (VM_READ, VM_WRITE, VM_EXEC)
 * @flags: Mapping flags (VM_SHARED, etc.)
 * @vn: File vnode (NULL for anonymous)
 * @offset: File offset
 *
 * Returns mapped address, or 0 on failure.
 */
vaddr_t mm_mmap(struct mm_struct *mm, vaddr_t addr, size_t len,
                uint32_t prot, uint32_t flags, struct vnode *vn, off_t offset)
{
    if (len == 0) {
        return 0;
    }

    len = ALIGN_UP(len, PAGE_SIZE);

    spin_lock(&mm->lock);

    /* Find a suitable address if none specified */
    if (addr == 0) {
        /* Start from after heap, search for free space */
        addr = ALIGN_UP(mm->brk, PAGE_SIZE);

        while (addr + len < mm->start_stack) {
            if (!find_vma_intersection(mm, addr, addr + len)) {
                break;
            }
            addr += PAGE_SIZE;
        }

        if (addr + len >= mm->start_stack) {
            spin_unlock(&mm->lock);
            return 0;
        }
    } else {
        /* Check if requested address is available */
        addr = ALIGN_DOWN(addr, PAGE_SIZE);
        if (find_vma_intersection(mm, addr, addr + len)) {
            spin_unlock(&mm->lock);
            return 0;
        }
    }

    /* Create VMA */
    struct vm_area *vma = vma_alloc();
    if (!vma) {
        spin_unlock(&mm->lock);
        return 0;
    }

    vma->start = addr;
    vma->end = addr + len;
    vma->flags = prot | flags;
    vma->vnode = vn;
    vma->offset = offset;

    insert_vma(mm, vma);

    spin_unlock(&mm->lock);
    return addr;
}

/**
 * mm_munmap - Implement munmap() syscall
 * @mm: Address space
 * @addr: Start address of region to unmap
 * @len: Length of region
 *
 * Returns 0 on success, negative error on failure.
 */
int mm_munmap(struct mm_struct *mm, vaddr_t addr, size_t len)
{
    if (len == 0) {
        return -EINVAL;
    }

    addr = ALIGN_DOWN(addr, PAGE_SIZE);
    len = ALIGN_UP(len, PAGE_SIZE);
    vaddr_t end = addr + len;

    spin_lock(&mm->lock);

    /* Find and remove VMAs in range */
    struct vm_area *vma, *tmp;
    list_for_each_entry_safe(vma, tmp, &mm->vma_list, list) {
        if (vma->start >= end || vma->end <= addr) {
            continue;
        }

        /* VMA overlaps with unmap range */
        if (vma->start >= addr && vma->end <= end) {
            /* VMA completely within range - remove it */
            for (vaddr_t va = vma->start; va < vma->end; va += PAGE_SIZE) {
                paddr_t pa = arch_mmu_translate(mm->pgdir, va);
                if (pa) {
                    arch_mmu_unmap(mm->pgdir, va);
                    pmm_free_page(pa);
                }
            }
            list_del(&vma->list);
            vma_free(vma);
        } else if (vma->start < addr && vma->end > end) {
            /* VMA contains the range - split it */
            struct vm_area *new_vma = vma_alloc();
            if (!new_vma) {
                spin_unlock(&mm->lock);
                return -ENOMEM;
            }

            /* Unmap the middle section */
            for (vaddr_t va = addr; va < end; va += PAGE_SIZE) {
                paddr_t pa = arch_mmu_translate(mm->pgdir, va);
                if (pa) {
                    arch_mmu_unmap(mm->pgdir, va);
                    pmm_free_page(pa);
                }
            }

            /* Create new VMA for the end portion */
            new_vma->start = end;
            new_vma->end = vma->end;
            new_vma->flags = vma->flags;
            new_vma->vnode = vma->vnode;
            new_vma->offset = vma->offset + (end - vma->start);

            /* Shrink original VMA */
            vma->end = addr;

            insert_vma(mm, new_vma);
        } else if (vma->start < addr) {
            /* VMA starts before range - shrink from end */
            for (vaddr_t va = addr; va < vma->end; va += PAGE_SIZE) {
                paddr_t pa = arch_mmu_translate(mm->pgdir, va);
                if (pa) {
                    arch_mmu_unmap(mm->pgdir, va);
                    pmm_free_page(pa);
                }
            }
            vma->end = addr;
        } else {
            /* VMA ends after range - shrink from start */
            for (vaddr_t va = vma->start; va < end; va += PAGE_SIZE) {
                paddr_t pa = arch_mmu_translate(mm->pgdir, va);
                if (pa) {
                    arch_mmu_unmap(mm->pgdir, va);
                    pmm_free_page(pa);
                }
            }
            vma->start = end;
        }
    }

    spin_unlock(&mm->lock);
    return 0;
}
