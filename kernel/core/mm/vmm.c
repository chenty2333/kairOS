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

/* --- Internal Helpers --- */

static void unmap_range(paddr_t pgdir, vaddr_t start, vaddr_t end) {
    for (vaddr_t va = start; va < end; va += CONFIG_PAGE_SIZE) {
        paddr_t pa = arch_mmu_translate(pgdir, va);
        if (pa) {
            arch_mmu_unmap(pgdir, va);
            pmm_free_page(pa);
        }
    }
    arch_mmu_flush_tlb_all();
}

static struct vm_area *find_vma(struct mm_struct *mm, vaddr_t addr) {
    struct rb_node *n = mm->mm_rb.rb_node;
    while (n) {
        struct vm_area *vma = rb_entry(n, struct vm_area, rb_node);
        if (addr < vma->start) n = n->rb_left;
        else if (addr >= vma->end) n = n->rb_right;
        else return vma;
    }
    return NULL;
}

static struct vm_area *find_vma_intersection(struct mm_struct *mm, vaddr_t start, vaddr_t end) {
    struct rb_node *n = mm->mm_rb.rb_node;
    while (n) {
        struct vm_area *vma = rb_entry(n, struct vm_area, rb_node);
        if (end <= vma->start) n = n->rb_left;
        else if (start >= vma->end) n = n->rb_right;
        else return vma;
    }
    return NULL;
}

static void insert_vma(struct mm_struct *mm, struct vm_area *new_vma) {
    struct vm_area *pos;
    struct vm_area *at = NULL;
    list_for_each_entry(pos, &mm->vma_list, list) {
        if (new_vma->start < pos->start) { at = pos; break; }
    }
    if (at) list_add_tail(&new_vma->list, &at->list);
    else list_add_tail(&new_vma->list, &mm->vma_list);

    struct rb_node **p = &mm->mm_rb.rb_node, *parent = NULL;
    while (*p) {
        parent = *p;
        if (new_vma->start < rb_entry(parent, struct vm_area, rb_node)->start) p = &(*p)->rb_left;
        else p = &(*p)->rb_right;
    }
    rb_link_node(&new_vma->rb_node, parent, p);
    rb_insert_color(&new_vma->rb_node, &mm->mm_rb);
}

static void remove_vma(struct mm_struct *mm, struct vm_area *vma) {
    list_del(&vma->list);
    rb_erase(&vma->rb_node, &mm->mm_rb);
}

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

int mm_add_vma(struct mm_struct *mm, vaddr_t start, vaddr_t end,
               uint32_t flags, struct vnode *vn, off_t offset) {
    if (!mm) {
        return -EINVAL;
    }

    start = ALIGN_DOWN(start, CONFIG_PAGE_SIZE);
    end = ALIGN_UP(end, CONFIG_PAGE_SIZE);
    if (start >= end) {
        return -EINVAL;
    }

    mutex_lock(&mm->lock);

    struct vm_area *acc = NULL;
    for (;;) {
        struct vm_area *hit = find_vma_intersection(mm, start, end);
        if (!hit) {
            break;
        }

        start = (start < hit->start) ? start : hit->start;
        end = (end > hit->end) ? end : hit->end;
        flags |= hit->flags;

        if (!acc) {
            acc = hit;
            remove_vma(mm, hit);
        } else {
            remove_vma(mm, hit);
            if (hit->vnode)
                vnode_put(hit->vnode);
            kfree(hit);
        }
    }

    if (!acc) {
        acc = kzalloc(sizeof(*acc));
        if (!acc) {
            mutex_unlock(&mm->lock);
            return -ENOMEM;
        }
        INIT_LIST_HEAD(&acc->list);
    }

    acc->start = start;
    acc->end = end;
    acc->flags = flags;
    struct vnode *old_vn = acc->vnode;
    if (old_vn && old_vn != vn)
        vnode_put(old_vn);
    if (vn && vn != old_vn)
        vnode_get(vn);
    acc->vnode = vn;
    acc->offset = offset;

    insert_vma(mm, acc);
    mutex_unlock(&mm->lock);
    return 0;
}

void mm_destroy(struct mm_struct *mm) {
    if (!mm) return;
    mutex_lock(&mm->lock);
    if (--mm->refcount > 0) { mutex_unlock(&mm->lock); return; }
    struct vm_area *vma, *tmp;
    list_for_each_entry_safe(vma, tmp, &mm->vma_list, list) {
        unmap_range(mm->pgdir, vma->start, vma->end);
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
        struct vm_area *dv = kzalloc(sizeof(*dv));
        if (!dv) goto fail;
        *dv = *sv;
        INIT_LIST_HEAD(&dv->list);
        if (dv->vnode)
            vnode_get(dv->vnode);
        insert_vma(dst, dv);

        for (vaddr_t va = sv->start; va < sv->end; va += CONFIG_PAGE_SIZE) {
            paddr_t spa = arch_mmu_translate(src->pgdir, va);
            if (!spa) continue;
            paddr_t pa = ALIGN_DOWN(spa, CONFIG_PAGE_SIZE);

            uint64_t f = PTE_USER | PTE_READ | ((dv->flags & VM_EXEC) ? PTE_EXEC : 0);
            bool cow = (dv->flags & VM_WRITE) && !(dv->flags & VM_SHARED);
            if (cow)
                f |= PTE_COW;
            else
                f |= (dv->flags & VM_WRITE) ? PTE_WRITE : 0;

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
    struct vm_area *vma = find_vma(mm, addr);
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
    if (vma->vnode && vma->vnode->ops && vma->vnode->ops->read) {
        off_t file_off = vma->offset + (off_t)(va - vma->start);
        size_t to_read = CONFIG_PAGE_SIZE;
        if (file_off < (off_t)vma->vnode->size) {
            size_t avail = (size_t)vma->vnode->size - (size_t)file_off;
            if (avail < to_read)
                to_read = avail;
            ssize_t rd = vma->vnode->ops->read(vma->vnode, kva, to_read,
                                               file_off);
            if (rd < 0) {
                pmm_free_page(pa);
                mutex_unlock(&mm->lock);
                return (int)rd;
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
    struct vm_area *heap_vma = find_vma(mm, USER_HEAP_START);

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

    unmap_range(mm->pgdir, newbrk, old_brk);
    if (heap_vma && heap_vma->end > newbrk)
        heap_vma->end = newbrk;
    mm->brk = newbrk;
    mutex_unlock(&mm->lock);
    return newbrk;
}

vaddr_t mm_mmap(struct mm_struct *mm, vaddr_t addr, size_t len, uint32_t prot, uint32_t flags, struct vnode *vn, off_t offset) {
    if (!len) return 0;
    len = ALIGN_UP(len, CONFIG_PAGE_SIZE);

    mutex_lock(&mm->lock);
    if (!addr) {
        addr = ALIGN_UP(mm->brk, CONFIG_PAGE_SIZE);
        while (addr + len < mm->start_stack) {
            struct vm_area *c = find_vma_intersection(mm, addr, addr + len);
            if (!c) break;
            addr = ALIGN_UP(c->end, CONFIG_PAGE_SIZE);
        }
    } else {
        addr = ALIGN_DOWN(addr, CONFIG_PAGE_SIZE);
        if (find_vma_intersection(mm, addr, addr + len)) {
            mutex_unlock(&mm->lock); return 0;
        }
    }

    if (addr + len >= mm->start_stack) { mutex_unlock(&mm->lock); return 0; }
    mutex_unlock(&mm->lock);

    if (mm_add_vma(mm, addr, addr + len, prot | flags, vn, offset) < 0)
        return 0;
    return addr;
}

int mm_munmap(struct mm_struct *mm, vaddr_t addr, size_t len) {

    if (!len) return -EINVAL;

    addr = ALIGN_DOWN(addr, CONFIG_PAGE_SIZE);

    len = ALIGN_UP(len, CONFIG_PAGE_SIZE);

    vaddr_t end = addr + len;



    mutex_lock(&mm->lock);

    struct vm_area *vma, *tmp;

    list_for_each_entry_safe(vma, tmp, &mm->vma_list, list) {

        if (vma->start >= end || vma->end <= addr) continue;



        if (vma->start >= addr && vma->end <= end) {

            unmap_range(mm->pgdir, vma->start, vma->end);

            remove_vma(mm, vma);
            if (vma->vnode)
                vnode_put(vma->vnode);
            kfree(vma);

        } else if (vma->start < addr && vma->end > end) {

            struct vm_area *nv = kzalloc(sizeof(*nv));

            if (!nv) { mutex_unlock(&mm->lock); return -ENOMEM; }

            unmap_range(mm->pgdir, addr, end);

            *nv = *vma; nv->start = end; nv->offset += (end - vma->start);
            if (nv->vnode)
                vnode_get(nv->vnode);

            vma->end = addr;

            INIT_LIST_HEAD(&nv->list);

            insert_vma(mm, nv);

        } else if (vma->start < addr) {

            unmap_range(mm->pgdir, addr, vma->end);

            vma->end = addr;

        } else {

            unmap_range(mm->pgdir, vma->start, end);

            vma->offset += (end - vma->start);

            vma->start = end;

        }

    }

    mutex_unlock(&mm->lock);

    return 0;

}

int mm_mprotect(struct mm_struct *mm, vaddr_t addr, size_t len,
                uint32_t prot) {
    if (!mm || !len)
        return -EINVAL;

    addr = ALIGN_DOWN(addr, CONFIG_PAGE_SIZE);
    len = ALIGN_UP(len, CONFIG_PAGE_SIZE);
    vaddr_t end = addr + len;
    uint32_t prot_mask = VM_READ | VM_WRITE | VM_EXEC;
    uint32_t new_prot = prot & prot_mask;

    /* Ensure the range is fully covered by existing mappings. */
    mutex_lock(&mm->lock);
    for (vaddr_t cur = addr; cur < end;) {
        struct vm_area *vma = find_vma(mm, cur);
        if (!vma || vma->start > cur) {
            mutex_unlock(&mm->lock);
            return -ENOMEM;
        }
        cur = MIN(vma->end, end);
    }

    struct vm_area *vma, *tmp;
    list_for_each_entry_safe(vma, tmp, &mm->vma_list, list) {
        if (vma->end <= addr || vma->start >= end)
            continue;

        uint32_t base_flags = vma->flags & ~prot_mask;
        uint32_t mid_flags = base_flags | new_prot;

        if (addr <= vma->start && end >= vma->end) {
            vma->flags = mid_flags;
            continue;
        }

        if (vma->start < addr && vma->end > end) {
            struct vm_area *mid = kzalloc(sizeof(*mid));
            struct vm_area *tail = kzalloc(sizeof(*tail));
            if (!mid || !tail) {
                kfree(mid);
                kfree(tail);
                mutex_unlock(&mm->lock);
                return -ENOMEM;
            }

            *mid = *vma;
            mid->start = addr;
            mid->end = end;
            mid->flags = mid_flags;
            mid->offset += (addr - vma->start);
            INIT_LIST_HEAD(&mid->list);
            memset(&mid->rb_node, 0, sizeof(mid->rb_node));

            *tail = *vma;
            tail->start = end;
            tail->offset += (end - vma->start);
            INIT_LIST_HEAD(&tail->list);
            memset(&tail->rb_node, 0, sizeof(tail->rb_node));

            vma->end = addr;

            insert_vma(mm, mid);
            insert_vma(mm, tail);
            continue;
        }

        if (vma->start < addr) {
            struct vm_area *mid = kzalloc(sizeof(*mid));
            if (!mid) {
                mutex_unlock(&mm->lock);
                return -ENOMEM;
            }

            *mid = *vma;
            mid->start = addr;
            mid->flags = mid_flags;
            mid->offset += (addr - vma->start);
            INIT_LIST_HEAD(&mid->list);
            memset(&mid->rb_node, 0, sizeof(mid->rb_node));

            vma->end = addr;
            insert_vma(mm, mid);
            continue;
        }

        /* vma->start >= addr and vma->end > end */
        struct vm_area *mid = kzalloc(sizeof(*mid));
        if (!mid) {
            mutex_unlock(&mm->lock);
            return -ENOMEM;
        }

        *mid = *vma;
        mid->end = end;
        mid->flags = mid_flags;
        INIT_LIST_HEAD(&mid->list);
        memset(&mid->rb_node, 0, sizeof(mid->rb_node));

        remove_vma(mm, vma);
        vma->offset += (end - vma->start);
        vma->start = end;
        insert_vma(mm, vma);
        insert_vma(mm, mid);
    }

    uint64_t flag_mask = PTE_READ | PTE_WRITE | PTE_EXEC | PTE_USER | PTE_COW;
    uint64_t low_mask = (1UL << 10) - 1;
    for (vaddr_t va = addr; va < end; va += CONFIG_PAGE_SIZE) {
        struct vm_area *cur = find_vma(mm, va);
        if (!cur)
            break;
        uint64_t pte = arch_mmu_get_pte(mm->pgdir, va);
        if (!(pte & PTE_VALID))
            continue;

        uint64_t low = pte & low_mask;
        uint64_t high = pte & ~low_mask;
        uint64_t new_low = (low & ~flag_mask) | PTE_USER;

        if (cur->flags & VM_READ)
            new_low |= PTE_READ;
        if (cur->flags & VM_EXEC)
            new_low |= PTE_EXEC;
        if (cur->flags & VM_WRITE) {
            if (low & PTE_COW)
                new_low |= PTE_COW;
            else
                new_low |= PTE_WRITE;
        }

        uint64_t new_pte = high | new_low;
        if (new_pte != pte) {
            arch_mmu_set_pte(mm->pgdir, va, new_pte);
            arch_mmu_flush_tlb_page(va);
        }
    }

    mutex_unlock(&mm->lock);
    return 0;
}
