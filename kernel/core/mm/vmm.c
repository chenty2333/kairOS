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

#define USER_SPACE_START    0x00000000UL
#define USER_SPACE_END      0x0000003FFFFFFFFFULL
#define USER_HEAP_START     0x00000001000000UL
#define USER_STACK_TOP      0x0000003FF0000000ULL

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
        unmap_range(mm->pgdir, vma->start, vma->end);
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

    struct vm_area *sv;
    list_for_each_entry(sv, &src->vma_list, list) {
        struct vm_area *dv = kzalloc(sizeof(*dv));
        if (!dv) goto fail;
        *dv = *sv;
        INIT_LIST_HEAD(&dv->list);
        insert_vma(dst, dv);

        for (vaddr_t va = sv->start; va < sv->end; va += CONFIG_PAGE_SIZE) {
            paddr_t spa = arch_mmu_translate(src->pgdir, va);
            if (!spa) continue;
            paddr_t dpa = pmm_alloc_page();
            if (!dpa) goto fail;
            memcpy(phys_to_virt(dpa), phys_to_virt(spa), CONFIG_PAGE_SIZE);
            uint64_t f = PTE_USER | PTE_READ | ((dv->flags & VM_WRITE) ? PTE_WRITE : 0) | ((dv->flags & VM_EXEC) ? PTE_EXEC : 0);
            if (arch_mmu_map(dst->pgdir, va, dpa, f) < 0) { pmm_free_page(dpa); goto fail; }
        }
    }
    mutex_unlock(&src->lock);
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
    if (arch_mmu_translate(mm->pgdir, va)) { mutex_unlock(&mm->lock); return -EEXIST; }

    paddr_t pa = pmm_alloc_page();
    if (!pa) { mutex_unlock(&mm->lock); return -ENOMEM; }
    memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);

    uint64_t f = PTE_USER | PTE_READ | ((vma->flags & VM_WRITE) ? PTE_WRITE : 0) | ((vma->flags & VM_EXEC) ? PTE_EXEC : 0);
    int ret = arch_mmu_map(mm->pgdir, va, pa, f);
    if (ret < 0) pmm_free_page(pa);
    mutex_unlock(&mm->lock);
    return ret;
}

vaddr_t mm_brk(struct mm_struct *mm, vaddr_t newbrk) {
    mutex_lock(&mm->lock);
    if (!newbrk || newbrk < USER_HEAP_START) { mutex_unlock(&mm->lock); return mm->brk; }
    newbrk = ALIGN_UP(newbrk, CONFIG_PAGE_SIZE);
    if (newbrk >= mm->start_stack) { mutex_unlock(&mm->lock); return mm->brk; }

    if (newbrk < mm->brk) unmap_range(mm->pgdir, newbrk, mm->brk);
    mm->brk = newbrk;

    struct vm_area *vma = find_vma(mm, USER_HEAP_START);
    if (!vma) {
        if (!(vma = kzalloc(sizeof(*vma)))) { mutex_unlock(&mm->lock); return mm->brk; }
        vma->start = USER_HEAP_START; vma->end = newbrk;
        vma->flags = VM_READ | VM_WRITE;
        INIT_LIST_HEAD(&vma->list);
        insert_vma(mm, vma);
    } else vma->end = newbrk;

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

    struct vm_area *vma = kzalloc(sizeof(*vma));
    if (!vma) { mutex_unlock(&mm->lock); return 0; }
    vma->start = addr; vma->end = addr + len;
    vma->flags = prot | flags; vma->vnode = vn; vma->offset = offset;
    INIT_LIST_HEAD(&vma->list);
    insert_vma(mm, vma);

    mutex_unlock(&mm->lock);
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

            rb_erase(&vma->rb_node, &mm->mm_rb);

            list_del(&vma->list);

            kfree(vma);

        } else if (vma->start < addr && vma->end > end) {

            struct vm_area *nv = kzalloc(sizeof(*nv));

            if (!nv) { mutex_unlock(&mm->lock); return -ENOMEM; }

            unmap_range(mm->pgdir, addr, end);

            *nv = *vma; nv->start = end; nv->offset += (end - vma->start);

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
