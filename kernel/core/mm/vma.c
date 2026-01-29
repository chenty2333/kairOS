/**
 * vma.c - Virtual memory area management
 */

#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/string.h>
#include <kairos/vfs.h>

void mm_unmap_range_noflush(paddr_t pgdir, vaddr_t start, vaddr_t end) {
    for (vaddr_t va = start; va < end; va += CONFIG_PAGE_SIZE) {
        paddr_t pa = arch_mmu_translate(pgdir, va);
        if (pa) {
            arch_mmu_unmap(pgdir, va);
            pmm_free_page(pa);
        }
    }
}

void mm_unmap_range(paddr_t pgdir, vaddr_t start, vaddr_t end) {
    mm_unmap_range_noflush(pgdir, start, end);
    arch_mmu_flush_tlb_all();
}

struct vm_area *mm_find_vma(struct mm_struct *mm, vaddr_t addr) {
    struct rb_node *n = mm->mm_rb.rb_node;
    while (n) {
        struct vm_area *vma = rb_entry(n, struct vm_area, rb_node);
        if (addr < vma->start) n = n->rb_left;
        else if (addr >= vma->end) n = n->rb_right;
        else return vma;
    }
    return NULL;
}

static struct vm_area *find_vma_intersection(struct mm_struct *mm, vaddr_t start,
                                             vaddr_t end) {
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
    if (!vn) {
        for (;;) {
            struct vm_area *hit = find_vma_intersection(mm, start, end);
            if (!hit) {
                break;
            }
            if (hit->vnode) {
                mutex_unlock(&mm->lock);
                return -EEXIST;
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
    } else if (find_vma_intersection(mm, start, end)) {
        mutex_unlock(&mm->lock);
        return -EEXIST;
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
    if (vn) {
        vaddr_t vend = end;
        if (vn->size > (size_t)offset) {
            size_t avail = vn->size - (size_t)offset;
            if (avail < (size_t)(end - start))
                vend = start + avail;
        } else {
            vend = start;
        }
        acc->file_start = start;
        acc->file_end = vend;
    } else {
        acc->file_start = 0;
        acc->file_end = 0;
    }

    insert_vma(mm, acc);
    mutex_unlock(&mm->lock);
    return 0;
}

int mm_add_vma_file(struct mm_struct *mm, vaddr_t start, vaddr_t end,
                    uint32_t flags, struct vnode *vn, off_t offset,
                    vaddr_t file_start, vaddr_t file_end) {
    if (!mm || !vn) {
        return -EINVAL;
    }

    start = ALIGN_DOWN(start, CONFIG_PAGE_SIZE);
    end = ALIGN_UP(end, CONFIG_PAGE_SIZE);
    if (start >= end) {
        return -EINVAL;
    }

    if (file_start < start) {
        file_start = start;
    }
    if (file_end > end) {
        file_end = end;
    }

    mutex_lock(&mm->lock);
    if (find_vma_intersection(mm, start, end)) {
        mutex_unlock(&mm->lock);
        return -EEXIST;
    }

    struct vm_area *vma = kzalloc(sizeof(*vma));
    if (!vma) {
        mutex_unlock(&mm->lock);
        return -ENOMEM;
    }
    INIT_LIST_HEAD(&vma->list);
    vma->start = start;
    vma->end = end;
    vma->flags = flags;
    vma->vnode = vn;
    vma->offset = offset;
    vma->file_start = file_start;
    vma->file_end = file_end;
    vnode_get(vn);

    insert_vma(mm, vma);
    mutex_unlock(&mm->lock);
    return 0;
}

int mm_mmap(struct mm_struct *mm, vaddr_t addr, size_t len, uint32_t prot,
            uint32_t flags, struct vnode *vn, off_t offset, bool fixed,
            vaddr_t *out) {
    if (!mm || !out || !len)
        return -EINVAL;
    len = ALIGN_UP(len, CONFIG_PAGE_SIZE);

    mutex_lock(&mm->lock);
    vaddr_t start;
    if (fixed) {
        start = addr;
        if (find_vma_intersection(mm, start, start + len)) {
            mutex_unlock(&mm->lock);
            return -EEXIST;
        }
    } else {
        start = addr ? ALIGN_DOWN(addr, CONFIG_PAGE_SIZE)
                     : ALIGN_UP(mm->brk, CONFIG_PAGE_SIZE);
        while (start + len < mm->start_stack) {
            struct vm_area *c = find_vma_intersection(mm, start, start + len);
            if (!c)
                break;
            start = ALIGN_UP(c->end, CONFIG_PAGE_SIZE);
        }
    }

    if (start + len >= mm->start_stack) {
        mutex_unlock(&mm->lock);
        return -ENOMEM;
    }
    mutex_unlock(&mm->lock);

    if (vn) {
        vaddr_t file_end = start;
        if (vn->size > (size_t)offset) {
            size_t avail = vn->size - (size_t)offset;
            if (avail > len)
                avail = len;
            file_end = start + avail;
        }
        if (mm_add_vma_file(mm, start, start + len, prot | flags, vn, offset,
                            start, file_end) < 0) {
            return -ENOMEM;
        }
    } else if (mm_add_vma(mm, start, start + len, prot | flags, NULL, 0) < 0) {
        return -ENOMEM;
    }
    *out = start;
    return 0;
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

            mm_unmap_range_noflush(mm->pgdir, vma->start, vma->end);

            remove_vma(mm, vma);
            if (vma->vnode)
                vnode_put(vma->vnode);
            kfree(vma);

        } else if (vma->start < addr && vma->end > end) {

            struct vm_area *nv = kzalloc(sizeof(*nv));

            if (!nv) { mutex_unlock(&mm->lock); return -ENOMEM; }

            mm_unmap_range_noflush(mm->pgdir, addr, end);

            *nv = *vma; nv->start = end; nv->offset += (end - vma->start);
            if (nv->vnode)
                vnode_get(nv->vnode);

            vma->end = addr;

            INIT_LIST_HEAD(&nv->list);

            insert_vma(mm, nv);

        } else if (vma->start < addr) {

            mm_unmap_range_noflush(mm->pgdir, addr, vma->end);

            vma->end = addr;

        } else {

            mm_unmap_range_noflush(mm->pgdir, vma->start, end);

            vma->offset += (end - vma->start);

            vma->start = end;

        }

    }

    mutex_unlock(&mm->lock);
    arch_mmu_flush_tlb_all();

    return 0;

}

int mm_mremap(struct mm_struct *mm, vaddr_t old_addr, size_t old_len,
              size_t new_len, uint32_t flags, vaddr_t new_addr, vaddr_t *out)
{
    if (!mm || !out || !old_len || !new_len) {
        return -EINVAL;
    }

    old_len = ALIGN_UP(old_len, CONFIG_PAGE_SIZE);
    new_len = ALIGN_UP(new_len, CONFIG_PAGE_SIZE);

    /* Shrink case */
    if (new_len <= old_len) {
        if (new_len < old_len) {
            mm_munmap(mm, old_addr + new_len, old_len - new_len);
        }
        *out = old_addr;
        return 0;
    }

    /* Try to grow in place */
    mutex_lock(&mm->lock);
    struct vm_area *vma = mm_find_vma(mm, old_addr);
    if (!vma || vma->start != old_addr) {
        mutex_unlock(&mm->lock);
        return -EFAULT;
    }

    vaddr_t old_end = old_addr + old_len;
    vaddr_t new_end = old_addr + new_len;

    if (!find_vma_intersection(mm, old_end, new_end)) {
        /* Space is free — grow in place */
        remove_vma(mm, vma);
        vma->end = new_end;
        INIT_LIST_HEAD(&vma->list);
        memset(&vma->rb_node, 0, sizeof(vma->rb_node));
        insert_vma(mm, vma);
        mutex_unlock(&mm->lock);
        *out = old_addr;
        return 0;
    }
    mutex_unlock(&mm->lock);

    /* Cannot grow in place — need to move */
    if (!(flags & 1)) { /* MREMAP_MAYMOVE */
        return -ENOMEM;
    }

    /* Capture source VMA properties */
    mutex_lock(&mm->lock);
    vma = mm_find_vma(mm, old_addr);
    if (!vma || vma->start != old_addr) {
        mutex_unlock(&mm->lock);
        return -EFAULT;
    }
    uint32_t vm_flags = vma->flags;
    struct vnode *vn = vma->vnode;
    off_t offset = vma->offset;
    if (vn) {
        vnode_get(vn);
    }
    mutex_unlock(&mm->lock);

    /* Allocate new region */
    bool fixed = (flags & 2) != 0; /* MREMAP_FIXED */
    vaddr_t target = fixed ? new_addr : 0;
    vaddr_t res = 0;
    int ret = mm_mmap(mm, target, new_len, vm_flags, 0, vn, offset, fixed,
                      &res);
    if (vn) {
        vnode_put(vn);
    }
    if (ret < 0) {
        return ret;
    }

    /* Transfer PTEs: remap physical pages from old VA to new VA */
    for (vaddr_t va = old_addr; va < old_end; va += CONFIG_PAGE_SIZE) {
        paddr_t pa = arch_mmu_translate(mm->pgdir, va);
        if (!pa) {
            continue;
        }
        uint64_t pte = arch_mmu_get_pte(mm->pgdir, va);
        uint64_t pte_flags = pte & ((1UL << 10) - 1);
        arch_mmu_unmap(mm->pgdir, va);
        vaddr_t dest = res + (va - old_addr);
        arch_mmu_map(mm->pgdir, dest, pa, pte_flags);
    }
    arch_mmu_flush_tlb_all();

    /* Remove old VMA without freeing physical pages */
    mutex_lock(&mm->lock);
    vma = mm_find_vma(mm, old_addr);
    if (vma && vma->start == old_addr) {
        remove_vma(mm, vma);
        if (vma->vnode) {
            vnode_put(vma->vnode);
        }
        kfree(vma);
    }
    mutex_unlock(&mm->lock);

    *out = res;
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
        struct vm_area *vma = mm_find_vma(mm, cur);
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
        struct vm_area *cur = mm_find_vma(mm, va);
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
