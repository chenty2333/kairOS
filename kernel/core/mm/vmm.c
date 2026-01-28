/**
 * vmm.c - Virtual Memory Management
 */

#include <kairos/types.h>
#include <kairos/mm.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/sync.h>
#include <kairos/config.h>
#include <kairos/string.h>
#include <kairos/vfs.h>

/* --- Core mm_struct --- */

void vmm_init(void) {}

struct mm_struct *mm_create(void) {
    struct mm_struct *mm = kzalloc(sizeof(*mm));
    if (!mm) return NULL;
    if (!(mm->pgdir = arch_mmu_create_table())) { kfree(mm); return NULL; }
    INIT_LIST_HEAD(&mm->vma_list);
    mm->mm_rb = RB_ROOT;
    mutex_init(&mm->lock, "mm_lock");
    mm->brk = USER_HEAP_START;
    mm->start_stack = USER_STACK_TOP;
    mm->refcount = 1;
    return mm;
}

void mm_destroy(struct mm_struct *mm) {
    if (!mm) return;
    mutex_lock(&mm->lock);
    if (--mm->refcount > 0) { mutex_unlock(&mm->lock); return; }
    struct vm_area *vma, *tmp;
    list_for_each_entry_safe(vma, tmp, &mm->vma_list, list) {
        mm_unmap_range(mm->pgdir, vma->start, vma->end);
        if (vma->vnode)
            vnode_put(vma->vnode);
        kfree(vma);
    }
    arch_mmu_destroy_table(mm->pgdir);
    mutex_unlock(&mm->lock);
    kfree(mm);
}

struct mm_struct *mm_clone(struct mm_struct *src) {
    struct mm_struct *dst = mm_create();
    if (!dst) return NULL;
    mutex_lock(&src->lock);
    dst->brk = src->brk;
    dst->start_stack = src->start_stack;
    bool cow_updated = false;

    struct vm_area *sv;
    list_for_each_entry(sv, &src->vma_list, list) {
        int vret;
        if (sv->vnode) {
            vret = mm_add_vma_file(dst, sv->start, sv->end, sv->flags,
                                   sv->vnode, sv->offset, sv->file_start,
                                   sv->file_end);
        } else {
            vret = mm_add_vma(dst, sv->start, sv->end, sv->flags, NULL, 0);
        }
        if (vret < 0) goto fail;

        for (vaddr_t va = sv->start; va < sv->end; va += CONFIG_PAGE_SIZE) {
            paddr_t spa = arch_mmu_translate(src->pgdir, va);
            if (!spa) continue;
            paddr_t pa = ALIGN_DOWN(spa, CONFIG_PAGE_SIZE);

            uint64_t f = PTE_USER | PTE_READ | ((sv->flags & VM_EXEC) ? PTE_EXEC : 0);
            bool cow = (sv->flags & VM_WRITE) && !(sv->flags & VM_SHARED);
            if (cow)
                f |= PTE_COW;
            else
                f |= (sv->flags & VM_WRITE) ? PTE_WRITE : 0;

            if (arch_mmu_map(dst->pgdir, va, pa, f) < 0) goto fail;
            pmm_get_page(pa);

            if (cow) {
                uint64_t spte = arch_mmu_get_pte(src->pgdir, va);
                if (spte & PTE_WRITE) {
                    spte = (spte & ~PTE_WRITE) | PTE_COW;
                    arch_mmu_set_pte(src->pgdir, va, spte);
                    cow_updated = true;
                } else if (!(spte & PTE_COW)) {
                    spte |= PTE_COW;
                    arch_mmu_set_pte(src->pgdir, va, spte);
                    cow_updated = true;
                }
            }
        }
    }
    mutex_unlock(&src->lock);
    if (cow_updated)
        arch_mmu_flush_tlb_all();
    return dst;
fail:
    mutex_unlock(&src->lock);
    mm_destroy(dst);
    return NULL;
}

/* --- Fault & Syscall Hooks --- */

int mm_handle_fault(struct mm_struct *mm, vaddr_t addr, uint32_t flags) {
    mutex_lock(&mm->lock);
    struct vm_area *vma = mm_find_vma(mm, addr);
    if (!vma || ((flags & PTE_WRITE) && !(vma->flags & VM_WRITE))) { mutex_unlock(&mm->lock); return -EFAULT; }

    vaddr_t va = ALIGN_DOWN(addr, CONFIG_PAGE_SIZE);
    uint64_t pte = arch_mmu_get_pte(mm->pgdir, va);
    if (pte & PTE_VALID) {
        if ((flags & PTE_WRITE) && (pte & PTE_COW)) {
            paddr_t old_pa = ALIGN_DOWN(arch_mmu_translate(mm->pgdir, va), CONFIG_PAGE_SIZE);
            if (!old_pa) { mutex_unlock(&mm->lock); return -EFAULT; }

            int refs = pmm_page_refcount(old_pa);

            if (refs == 1) {
                pte = (pte & ~PTE_COW) | PTE_WRITE;
                arch_mmu_set_pte(mm->pgdir, va, pte);
                arch_mmu_flush_tlb_page(va);
                mutex_unlock(&mm->lock);
                return 0;
            }

            paddr_t new_pa = pmm_alloc_page();
            if (!new_pa) { mutex_unlock(&mm->lock); return -ENOMEM; }
            memcpy(phys_to_virt(new_pa), phys_to_virt(old_pa), CONFIG_PAGE_SIZE);

            uint64_t keep_flags = pte & ((1UL << 10) - 1);
            pte = ((new_pa / CONFIG_PAGE_SIZE) << 10) | keep_flags;
            pte = (pte & ~PTE_COW) | PTE_WRITE;
            arch_mmu_set_pte(mm->pgdir, va, pte);
            arch_mmu_flush_tlb_page(va);
            pmm_put_page(old_pa);
            mutex_unlock(&mm->lock);
            return 0;
        }
        mutex_unlock(&mm->lock);
        return 0;
    }

    paddr_t pa = pmm_alloc_page();
    if (!pa) { mutex_unlock(&mm->lock); return -ENOMEM; }
    void *kva = phys_to_virt(pa);
    memset(kva, 0, CONFIG_PAGE_SIZE);
    if (vma->vnode && vma->vnode->ops && vma->vnode->ops->read &&
        vma->file_end > vma->file_start) {
        vaddr_t page_start = va;
        vaddr_t page_end = va + CONFIG_PAGE_SIZE;
        vaddr_t read_start =
            (page_start > vma->file_start) ? page_start : vma->file_start;
        vaddr_t read_end =
            (page_end < vma->file_end) ? page_end : vma->file_end;
        if (read_start < read_end) {
            off_t file_off =
                vma->offset + (off_t)(read_start - vma->start);
            size_t to_read = (size_t)(read_end - read_start);
            ssize_t rd = vma->vnode->ops->read(
                vma->vnode,
                (uint8_t *)kva + (read_start - page_start),
                to_read,
                file_off);
            if (rd < 0) {
                pmm_free_page(pa);
                mutex_unlock(&mm->lock);
                return (int)rd;
            }
            if ((size_t)rd != to_read) {
                pmm_free_page(pa);
                mutex_unlock(&mm->lock);
                return -EIO;
            }
        }
    }

    uint64_t f = PTE_USER | PTE_READ | ((vma->flags & VM_WRITE) ? PTE_WRITE : 0) | ((vma->flags & VM_EXEC) ? PTE_EXEC : 0);
    int ret = arch_mmu_map(mm->pgdir, va, pa, f);
    if (ret < 0) pmm_free_page(pa);
    mutex_unlock(&mm->lock);
    return ret;
}

vaddr_t mm_brk(struct mm_struct *mm, vaddr_t newbrk) {
    vaddr_t old_brk;
    bool grow;

    mutex_lock(&mm->lock);
    old_brk = mm->brk;
    if (!newbrk || newbrk < USER_HEAP_START) {
        mutex_unlock(&mm->lock);
        return old_brk;
    }
    newbrk = ALIGN_UP(newbrk, CONFIG_PAGE_SIZE);
    if (newbrk >= mm->start_stack) {
        mutex_unlock(&mm->lock);
        return old_brk;
    }

    if (newbrk == old_brk) {
        mutex_unlock(&mm->lock);
        return newbrk;
    }

    grow = newbrk > old_brk;
    struct vm_area *heap_vma = mm_find_vma(mm, USER_HEAP_START);

    if (grow) {
        struct vm_area *vma;
        list_for_each_entry(vma, &mm->vma_list, list) {
            if (vma == heap_vma)
                continue;
            if (vma->end <= old_brk || vma->start >= newbrk)
                continue;
            /* Cannot grow the heap into another mapping. */
            mutex_unlock(&mm->lock);
            return old_brk;
        }
        mutex_unlock(&mm->lock);

        if (mm_add_vma(mm, USER_HEAP_START, newbrk, VM_READ | VM_WRITE, NULL,
                       0) < 0)
            return old_brk;

        mutex_lock(&mm->lock);
        mm->brk = newbrk;
        mutex_unlock(&mm->lock);
        return newbrk;
    }

    mm_unmap_range(mm->pgdir, newbrk, old_brk);
    if (heap_vma && heap_vma->end > newbrk)
        heap_vma->end = newbrk;
    mm->brk = newbrk;
    mutex_unlock(&mm->lock);
    return newbrk;
}
