/**
 * kernel/core/tests/mm_tests.c - Memory subsystem regression tests
 */

#include <kairos/arch.h>
#include <kairos/atomic.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/vfs.h>

#if CONFIG_KERNEL_TESTS

#define MM_TEST_BASE1 0x20000000UL
#define MM_TEST_BASE2 0x21000000UL
#define MM_TEST_BASE3 0x22000000UL
#define MM_TEST_BASE4 0x23000000UL
#define MM_TEST_PROBE_MAX 1024

static int tests_failed;
static paddr_t reserve_probe_pages[MM_TEST_PROBE_MAX];

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("mm_tests: %s failed\n", name);
        tests_failed++;
    }
}

static int dummy_vnode_close(struct vnode *vn) {
    (void)vn;
    return 0;
}

static struct file_ops dummy_vnode_ops = {
    .close = dummy_vnode_close,
};

static void test_mmu_pte_roundtrip(void) {
    struct mm_struct *mm = mm_create();
    test_check(mm != NULL, "pte_roundtrip mm_create");
    if (!mm)
        return;

    vaddr_t va = MM_TEST_BASE1;
    int ret = mm_add_vma(mm, va, va + CONFIG_PAGE_SIZE, VM_READ | VM_WRITE,
                         NULL, 0);
    test_check(ret == 0, "pte_roundtrip add_vma");
    if (ret < 0) {
        mm_destroy(mm);
        return;
    }

    paddr_t pa = pmm_alloc_page();
    test_check(pa != 0, "pte_roundtrip alloc_page");
    if (!pa) {
        mm_destroy(mm);
        return;
    }

    ret = arch_mmu_map(mm->pgdir, va, pa, PTE_USER | PTE_READ | PTE_COW);
    test_check(ret == 0, "pte_roundtrip map");
    if (ret < 0) {
        pmm_free_page(pa);
        mm_destroy(mm);
        return;
    }

    uint64_t pte = arch_mmu_get_pte(mm->pgdir, va);
    uint64_t flags = pte & ((1ULL << 10) - 1);
    test_check((flags & PTE_VALID) != 0, "pte_roundtrip valid");
    test_check((flags & PTE_USER) != 0, "pte_roundtrip user");
    test_check((flags & PTE_COW) != 0, "pte_roundtrip cow");

    flags &= ~PTE_COW;
    flags |= PTE_WRITE;
    pte = (pte & ~((1ULL << 10) - 1)) | flags;
    ret = arch_mmu_set_pte(mm->pgdir, va, pte);
    test_check(ret == 0, "pte_roundtrip set_pte");

    paddr_t pa2 = ALIGN_DOWN(arch_mmu_translate(mm->pgdir, va), CONFIG_PAGE_SIZE);
    uint64_t pte2 = arch_mmu_get_pte(mm->pgdir, va);
    uint64_t flags2 = pte2 & ((1ULL << 10) - 1);
    test_check(pa2 == pa, "pte_roundtrip pa_stable");
    test_check((flags2 & PTE_COW) == 0, "pte_roundtrip clear_cow");
    test_check((flags2 & PTE_WRITE) != 0, "pte_roundtrip set_write");

    mm_destroy(mm);
}

static void test_cow_clone_fault(void) {
    struct mm_struct *src = mm_create();
    test_check(src != NULL, "cow mm_create src");
    if (!src)
        return;

    vaddr_t va = MM_TEST_BASE2;
    int ret = mm_add_vma(src, va, va + CONFIG_PAGE_SIZE, VM_READ | VM_WRITE,
                         NULL, 0);
    test_check(ret == 0, "cow add_vma src");
    if (ret < 0) {
        mm_destroy(src);
        return;
    }

    paddr_t pa = pmm_alloc_page();
    test_check(pa != 0, "cow alloc_page");
    if (!pa) {
        mm_destroy(src);
        return;
    }

    memset(phys_to_virt(pa), 0x5A, CONFIG_PAGE_SIZE);
    ret = arch_mmu_map(src->pgdir, va, pa, PTE_USER | PTE_READ | PTE_WRITE);
    test_check(ret == 0, "cow map src");
    if (ret < 0) {
        pmm_free_page(pa);
        mm_destroy(src);
        return;
    }

    struct mm_struct *dst = mm_clone(src);
    test_check(dst != NULL, "cow mm_clone");
    if (!dst) {
        mm_destroy(src);
        return;
    }

    uint64_t spte = arch_mmu_get_pte(src->pgdir, va);
    uint64_t dpte = arch_mmu_get_pte(dst->pgdir, va);
    uint64_t sflags = spte & ((1ULL << 10) - 1);
    uint64_t dflags = dpte & ((1ULL << 10) - 1);
    test_check((sflags & PTE_COW) != 0, "cow src_marked_cow");
    test_check((dflags & PTE_COW) != 0, "cow dst_marked_cow");
    test_check((sflags & PTE_WRITE) == 0, "cow src_not_writeable");
    test_check((dflags & PTE_WRITE) == 0, "cow dst_not_writeable");

    ret = mm_handle_fault(dst, va, PTE_WRITE);
    test_check(ret == 0, "cow handle_fault");
    if (ret == 0) {
        paddr_t src_pa = ALIGN_DOWN(arch_mmu_translate(src->pgdir, va),
                                    CONFIG_PAGE_SIZE);
        paddr_t dst_pa = ALIGN_DOWN(arch_mmu_translate(dst->pgdir, va),
                                    CONFIG_PAGE_SIZE);
        test_check(src_pa != 0 && dst_pa != 0, "cow pa_nonzero");
        test_check(src_pa != dst_pa, "cow split_private_page");
        if (src_pa && dst_pa) {
            test_check(memcmp(phys_to_virt(src_pa), phys_to_virt(dst_pa),
                              CONFIG_PAGE_SIZE) == 0,
                       "cow content_copied");
        }
    }

    mm_destroy(dst);
    mm_destroy(src);
}

static void test_mprotect_file_vma_refcount(void) {
    struct mm_struct *mm = mm_create();
    test_check(mm != NULL, "mprotect_ref mm_create");
    if (!mm)
        return;

    struct vnode vn;
    memset(&vn, 0, sizeof(vn));
    vn.type = VNODE_FILE;
    vn.ops = &dummy_vnode_ops;
    atomic_init(&vn.refcount, 1);
    vn.kobj = NULL;
    atomic_init(&vn.kobj_state, 0);

    vaddr_t start = MM_TEST_BASE3;
    vaddr_t end = start + 3 * CONFIG_PAGE_SIZE;
    int ret = mm_add_vma_file(mm, start, end, VM_READ | VM_WRITE, &vn, 0,
                              start, end);
    test_check(ret == 0, "mprotect_ref add_vma_file");
    if (ret < 0) {
        mm_destroy(mm);
        return;
    }

    uint32_t before = atomic_read(&vn.refcount);
    ret = mm_mprotect(mm, start + CONFIG_PAGE_SIZE, CONFIG_PAGE_SIZE, VM_READ);
    test_check(ret == 0, "mprotect_ref mprotect");
    uint32_t after = atomic_read(&vn.refcount);
    test_check(after == before + 2, "mprotect_ref split_ref_gain");

    mm_destroy(mm);
    uint32_t final = atomic_read(&vn.refcount);
    test_check(final == 1, "mprotect_ref balanced_put");
}

static void test_mremap_move_integrity(void) {
    struct mm_struct *mm = mm_create();
    test_check(mm != NULL, "mremap mm_create");
    if (!mm)
        return;

    vaddr_t old = MM_TEST_BASE4;
    size_t old_len = 2 * CONFIG_PAGE_SIZE;
    size_t new_len = 3 * CONFIG_PAGE_SIZE;
    int ret = mm_add_vma(mm, old, old + old_len, VM_READ | VM_WRITE, NULL, 0);
    test_check(ret == 0, "mremap add_vma old");
    if (ret < 0) {
        mm_destroy(mm);
        return;
    }

    for (size_t off = 0; off < old_len; off += CONFIG_PAGE_SIZE) {
        paddr_t pa = pmm_alloc_page();
        test_check(pa != 0, "mremap alloc_page");
        if (!pa) {
            mm_destroy(mm);
            return;
        }
        memset(phys_to_virt(pa), (int)(0x30 + (off / CONFIG_PAGE_SIZE)),
               CONFIG_PAGE_SIZE);
        ret = arch_mmu_map(mm->pgdir, old + off, pa,
                           PTE_USER | PTE_READ | PTE_WRITE);
        test_check(ret == 0, "mremap map old");
        if (ret < 0) {
            pmm_free_page(pa);
            mm_destroy(mm);
            return;
        }
    }

    /* Occupy immediate gap to force move path instead of in-place growth. */
    ret = mm_add_vma(mm, old + old_len, old + old_len + CONFIG_PAGE_SIZE,
                     VM_READ, NULL, 0);
    test_check(ret == 0, "mremap add blocker");

    vaddr_t out = 0;
    ret = mm_mremap(mm, old, old_len, new_len, 1, 0, &out);
    test_check(ret == 0, "mremap move");
    if (ret == 0) {
        test_check(out != old, "mremap moved_addr_changed");
        for (size_t off = 0; off < old_len; off += CONFIG_PAGE_SIZE) {
            paddr_t new_pa = arch_mmu_translate(mm->pgdir, out + off);
            test_check(new_pa != 0, "mremap new_pa_present");
            if (new_pa) {
                uint8_t *buf = (uint8_t *)phys_to_virt(
                    ALIGN_DOWN(new_pa, CONFIG_PAGE_SIZE));
                test_check(buf[0] == (uint8_t)(0x30 + (off / CONFIG_PAGE_SIZE)),
                           "mremap content_preserved");
            }
            paddr_t old_pa = arch_mmu_translate(mm->pgdir, old + off);
            test_check(old_pa == 0, "mremap old_unmapped");
        }
    }

    mm_destroy(mm);
}

static void test_pmm_reserve_range_nonallocatable(void) {
    paddr_t target = pmm_alloc_page();
    test_check(target != 0, "reserve alloc_target");
    if (!target)
        return;

    pmm_free_page(target);
    size_t before = pmm_num_free_pages();
    pmm_reserve_range(target, target + CONFIG_PAGE_SIZE);
    size_t after = pmm_num_free_pages();
    test_check(before == after + 1, "reserve free_count_drop");

    size_t n = 0;
    bool seen = false;
    while (n < MM_TEST_PROBE_MAX) {
        paddr_t pa = pmm_alloc_page();
        if (!pa)
            break;
        reserve_probe_pages[n++] = pa;
        if (pa == target)
            seen = true;
    }
    test_check(!seen, "reserve target_not_reallocated");
    for (size_t i = 0; i < n; i++)
        pmm_free_page(reserve_probe_pages[i]);
}

static void test_kmalloc_aligned_basic(void) {
    void *p64 = kmalloc_aligned(100, 64);
    test_check(p64 != NULL, "kmalloc_aligned alloc64");
    if (p64)
        test_check((((uintptr_t)p64) & 63UL) == 0, "kmalloc_aligned align64");
    kfree_aligned(p64);

    void *pbad = kmalloc_aligned(64, 24);
    test_check(pbad == NULL, "kmalloc_aligned reject_non_pow2");

    void *p8 = kmalloc_aligned(32, 8);
    test_check(p8 != NULL, "kmalloc_aligned alloc8");
    if (p8)
        test_check((((uintptr_t)p8) & 7UL) == 0, "kmalloc_aligned align8");
    kfree_aligned(p8);
}

int run_mm_tests(void) {
    tests_failed = 0;
    pr_info("\n=== MM Tests ===\n");

    test_mmu_pte_roundtrip();
    test_cow_clone_fault();
    test_mprotect_file_vma_refcount();
    test_mremap_move_integrity();
    test_pmm_reserve_range_nonallocatable();
    test_kmalloc_aligned_basic();

    if (tests_failed == 0)
        pr_info("mm tests: all passed\n");
    else
        pr_err("mm tests: %d failures\n", tests_failed);
    return tests_failed;
}

#else

int run_mm_tests(void) { return 0; }

#endif
