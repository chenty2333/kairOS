/**
 * kernel/core/tests/syscall_trap_tests.c - Syscall/trap boundary tests
 */

#include <kairos/arch.h>
#include <kairos/futex.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/time.h>
#include <kairos/trap_core.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

#if CONFIG_KERNEL_TESTS

static int tests_failed;

static void test_check(bool cond, const char *name) {
    if (!cond) {
        pr_err("syscall_trap_tests: %s failed\n", name);
        tests_failed++;
    }
}

static int trap_handle_calls;
static int trap_should_deliver_calls;
static bool trap_handler_saw_current_tf;
static struct trap_frame *trap_handler_tf;

#define TEST_NS_PER_SEC 1000000000ULL
#define SYSCALL_USER_TEST_CODE_ADDR 0x12000

struct user_map_ctx {
    struct process *proc;
    struct mm_struct *saved_mm;
    struct mm_struct *active_mm;
    struct mm_struct *temp_mm;
    paddr_t saved_pgdir;
    vaddr_t base;
    size_t len;
    bool switched_pgdir;
};

struct futex_waker_ctx {
    vaddr_t uaddr;
    volatile int started;
    int wake_ret;
};

static int user_map_begin(struct user_map_ctx *ctx, size_t len) {
    if (!ctx || len == 0)
        return -EINVAL;

    memset(ctx, 0, sizeof(*ctx));
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    ctx->proc = p;
    ctx->saved_mm = p->mm;
    ctx->active_mm = p->mm;
    ctx->saved_pgdir = arch_mmu_current();

    if (!ctx->active_mm) {
        ctx->temp_mm = mm_create();
        if (!ctx->temp_mm)
            return -ENOMEM;
        p->mm = ctx->temp_mm;
        ctx->active_mm = ctx->temp_mm;
    }

    if (ctx->saved_pgdir != ctx->active_mm->pgdir) {
        arch_mmu_switch(ctx->active_mm->pgdir);
        ctx->switched_pgdir = true;
    }

    int rc = mm_mmap(ctx->active_mm, 0, len, VM_READ | VM_WRITE, 0, NULL, 0,
                     false, &ctx->base);
    if (rc < 0) {
        if (ctx->switched_pgdir)
            arch_mmu_switch(ctx->saved_pgdir);
        if (ctx->temp_mm) {
            p->mm = ctx->saved_mm;
            mm_destroy(ctx->temp_mm);
        }
        memset(ctx, 0, sizeof(*ctx));
        return rc;
    }
    ctx->len = len;
    return 0;
}

static void user_map_end(struct user_map_ctx *ctx) {
    if (!ctx || !ctx->proc)
        return;
    if (ctx->active_mm && ctx->base && ctx->len)
        (void)mm_munmap(ctx->active_mm, ctx->base, ctx->len);
    if (ctx->switched_pgdir)
        arch_mmu_switch(ctx->saved_pgdir);
    if (ctx->temp_mm) {
        ctx->proc->mm = ctx->saved_mm;
        mm_destroy(ctx->temp_mm);
    }
    memset(ctx, 0, sizeof(*ctx));
}

static void *user_map_ptr(const struct user_map_ctx *ctx, size_t off) {
    if (!ctx || off >= ctx->len)
        return NULL;
    return (void *)(ctx->base + off);
}

static struct timespec ns_to_timespec(uint64_t ns) {
    struct timespec ts = {
        .tv_sec = (time_t)(ns / TEST_NS_PER_SEC),
        .tv_nsec = (int64_t)(ns % TEST_NS_PER_SEC),
    };
    return ts;
}

static int futex_waitv_waker_worker(void *arg) {
    struct futex_waker_ctx *ctx = (struct futex_waker_ctx *)arg;
    if (!ctx)
        proc_exit(0);

    ctx->started = 1;
    ctx->wake_ret = 0;
    uint64_t wake_deadline = arch_timer_get_ticks() +
                             arch_timer_ns_to_ticks(2ULL * TEST_NS_PER_SEC);
    if (wake_deadline == 0)
        wake_deadline = 1;
    while (arch_timer_get_ticks() < wake_deadline) {
        int64_t ret = sys_futex((uint64_t)ctx->uaddr, FUTEX_WAKE, 1, 0, 0, 0);
        if (ret > 0) {
            ctx->wake_ret = (int)ret;
            proc_exit(0);
        }
        proc_yield();
    }
    proc_exit(0);
}

static struct process *create_legacy_user_process(const char *name,
                                                  const uint8_t *code,
                                                  size_t code_size,
                                                  struct process *parent) {
    struct process *p = proc_alloc_internal();
    if (!p)
        return NULL;

    bool linked_parent = false;
    strncpy(p->name, name, sizeof(p->name) - 1);
    p->uid = p->gid = 1000;
    p->syscall_abi = SYSCALL_ABI_LEGACY;

    if (parent) {
        p->parent = parent;
        p->ppid = parent->pid;
        list_add(&p->sibling, &parent->children);
        linked_parent = true;
    }

    p->mm = mm_create();
    if (!p->mm)
        goto fail;

    if (mm_add_vma(p->mm, SYSCALL_USER_TEST_CODE_ADDR,
                   SYSCALL_USER_TEST_CODE_ADDR + code_size, VM_READ | VM_EXEC,
                   NULL, 0) < 0) {
        goto fail;
    }

    for (size_t off = 0; off < code_size; off += CONFIG_PAGE_SIZE) {
        paddr_t pa = pmm_alloc_page();
        if (!pa)
            goto fail;
        memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);
        size_t remaining = code_size - off;
        size_t len = remaining < CONFIG_PAGE_SIZE ? remaining : CONFIG_PAGE_SIZE;
        memcpy(phys_to_virt(pa), code + off, len);
        if (arch_mmu_map(p->mm->pgdir, SYSCALL_USER_TEST_CODE_ADDR + off, pa,
                         PTE_USER | PTE_READ | PTE_EXEC) < 0) {
            pmm_free_page(pa);
            goto fail;
        }
    }

    vaddr_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    if (mm_add_vma(p->mm, stack_bottom, USER_STACK_TOP,
                   VM_READ | VM_WRITE | VM_STACK, NULL, 0) < 0) {
        goto fail;
    }

    for (vaddr_t va = stack_bottom; va < USER_STACK_TOP; va += CONFIG_PAGE_SIZE) {
        paddr_t pa = pmm_alloc_page();
        if (!pa)
            goto fail;
        memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);
        if (arch_mmu_map(p->mm->pgdir, va, pa, PTE_USER | PTE_READ | PTE_WRITE) <
            0) {
            pmm_free_page(pa);
            goto fail;
        }
    }

    arch_context_init(p->context, SYSCALL_USER_TEST_CODE_ADDR,
                      USER_STACK_TOP - 16, false);
    return p;

fail:
    if (linked_parent && !list_empty(&p->sibling))
        list_del(&p->sibling);
    if (p->mm)
        mm_destroy(p->mm);
    proc_free_internal(p);
    return NULL;
}

#if defined(ARCH_riscv64)
/*
 * User-mode ecall sequence:
 * 1) SYS_uname with bad pointer: expect -EFAULT
 * 2) SYS_getpid: expect > 0
 * 3) SYS_uname with stack pointer: expect 0
 * 4) SYS_exit(0)
 * failure exits with non-zero code.
 */
static const uint8_t user_syscall_e2e_prog[] = {
    0x13, 0x05, 0xf0, 0xff, 0x93, 0x08, 0x40, 0x06, 0x73, 0x00, 0x00, 0x00,
    0x93, 0x02, 0x20, 0xff, 0x63, 0x16, 0x55, 0x02, 0x93, 0x08, 0x50, 0x00,
    0x73, 0x00, 0x00, 0x00, 0x63, 0x56, 0xa0, 0x02, 0x13, 0x05, 0x01, 0xc0,
    0x93, 0x08, 0x40, 0x06, 0x73, 0x00, 0x00, 0x00, 0x63, 0x14, 0x05, 0x02,
    0x13, 0x05, 0x00, 0x00, 0x93, 0x08, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x13, 0x05, 0xb0, 0x00, 0x93, 0x08, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x13, 0x05, 0xc0, 0x00, 0x93, 0x08, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x13, 0x05, 0xd0, 0x00, 0x93, 0x08, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x6f, 0x00, 0x00, 0x00,
};
#elif defined(ARCH_x86_64)
/*
 * User-mode int 0x80 sequence:
 * 1) SYS_uname((void *)-1): expect -EFAULT
 * 2) SYS_getpid(): expect > 0
 * 3) SYS_uname(sp-0x400): expect 0
 * 4) SYS_exit(0)
 * failure exits with non-zero code.
 */
static const uint8_t user_syscall_e2e_prog[] = {
    0x48, 0xc7, 0xc7, 0xff, 0xff, 0xff, 0xff, 0x48, 0xc7, 0xc0, 0x64, 0x00,
    0x00, 0x00, 0xcd, 0x80, 0x48, 0x83, 0xf8, 0xf2, 0x75, 0x30, 0x48, 0xc7,
    0xc0, 0x05, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x48, 0x85, 0xc0, 0x7e, 0x32,
    0x48, 0x8d, 0xbc, 0x24, 0x00, 0xfc, 0xff, 0xff, 0x48, 0xc7, 0xc0, 0x64,
    0x00, 0x00, 0x00, 0xcd, 0x80, 0x48, 0x85, 0xc0, 0x75, 0x2c, 0x48, 0x31,
    0xff, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x48, 0xc7,
    0xc7, 0xb0, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
    0xcd, 0x80, 0x48, 0xc7, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0,
    0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x48, 0xc7, 0xc7, 0xd0, 0x00, 0x00,
    0x00, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80,
};
#elif defined(ARCH_aarch64)
/*
 * User-mode svc sequence:
 * 1) SYS_uname((void *)-1): expect -EFAULT
 * 2) SYS_getpid(): expect > 0
 * 3) SYS_uname(sp-0x400): expect 0
 * 4) SYS_exit(0)
 * failure exits with non-zero code.
 */
static const uint8_t user_syscall_e2e_prog[] = {
    0x00, 0x00, 0x80, 0x92, 0x88, 0x0c, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
    0xa1, 0x01, 0x80, 0x92, 0x1f, 0x00, 0x01, 0xeb, 0x81, 0x01, 0x00, 0x54,
    0xa8, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x1f, 0x00, 0x00, 0xf1,
    0x6d, 0x01, 0x00, 0x54, 0xe0, 0x03, 0x10, 0xd1, 0x88, 0x0c, 0x80, 0xd2,
    0x01, 0x00, 0x00, 0xd4, 0x40, 0x01, 0x00, 0xb5, 0x00, 0x00, 0x80, 0xd2,
    0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x16, 0x80, 0xd2,
    0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x18, 0x80, 0xd2,
    0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x1a, 0x80, 0xd2,
    0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
};
#endif

static void test_syscall_user_e2e(void) {
#if defined(ARCH_riscv64) || defined(ARCH_x86_64) || defined(ARCH_aarch64)
    struct process *parent = proc_current();
    test_check(parent != NULL, "user_e2e parent exists");
    if (!parent)
        return;

    struct process *child =
        create_legacy_user_process("sys_e2e", user_syscall_e2e_prog,
                                   sizeof(user_syscall_e2e_prog), parent);
    test_check(child != NULL, "user_e2e create child");
    if (!child)
        return;

    pid_t expected = child->pid;
    sched_enqueue(child);

    int status = 0;
    pid_t wp = 0;
    for (int i = 0; i < 4000; i++) {
        wp = proc_wait(expected, &status, WNOHANG);
        if (wp == expected || wp < 0)
            break;
        proc_yield();
    }
    if (wp == 0)
        wp = proc_wait(expected, &status, 0);

    test_check(wp == expected, "user_e2e child reaped");
    if (wp == expected)
        test_check(status == 0, "user_e2e child exit zero");
#else
    pr_info("syscall_trap_tests: user e2e skipped on unsupported arch\n");
#endif
}

static int64_t dispatch_legacy(uint64_t num, uint64_t a0, uint64_t a1,
                               uint64_t a2, uint64_t a3, uint64_t a4,
                               uint64_t a5) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;

    enum syscall_abi old_abi = p->syscall_abi;
    p->syscall_abi = SYSCALL_ABI_LEGACY;
    int64_t ret = syscall_dispatch(num, a0, a1, a2, a3, a4, a5);
    p->syscall_abi = old_abi;
    return ret;
}

static int trap_handle_probe(const struct trap_core_event *ev) {
    trap_handle_calls++;
    trap_handler_tf = ev ? ev->tf : NULL;
    trap_handler_saw_current_tf =
        ev && (arch_get_percpu()->current_tf == ev->tf);
    return 0;
}

static bool trap_should_deliver_false(const struct trap_core_event *ev) {
    (void)ev;
    trap_should_deliver_calls++;
    return false;
}

static void test_syscall_table_slot_coverage(void) {
    test_check(syscall_table[SYS_exit] != NULL, "table SYS_exit present");
    test_check(syscall_table[SYS_fork] != NULL, "table SYS_fork present");
    test_check(syscall_table[SYS_getpid] != NULL, "table SYS_getpid present");
    test_check(syscall_table[SYS_getppid] != NULL, "table SYS_getppid present");
    test_check(syscall_table[SYS_getuid] != NULL, "table SYS_getuid present");
    test_check(syscall_table[SYS_getgid] != NULL, "table SYS_getgid present");
    test_check(syscall_table[SYS_open] != NULL, "table SYS_open present");
    test_check(syscall_table[SYS_read] != NULL, "table SYS_read present");
    test_check(syscall_table[SYS_write] != NULL, "table SYS_write present");
    test_check(syscall_table[SYS_close] != NULL, "table SYS_close present");
    test_check(syscall_table[SYS_pipe2] != NULL, "table SYS_pipe2 present");
    test_check(syscall_table[SYS_poll] != NULL, "table SYS_poll present");
    test_check(syscall_table[SYS_clock_gettime] != NULL,
               "table SYS_clock_gettime present");
    test_check(syscall_table[SYS_uname] != NULL, "table SYS_uname present");

    test_check(syscall_table[SYS_yield] == NULL, "table SYS_yield absent");
    test_check(syscall_table[SYS_clone] == NULL, "table SYS_clone absent");
    test_check(syscall_table[SYS_mmap] == NULL, "table SYS_mmap absent");
    test_check(syscall_table[SYS_munmap] == NULL, "table SYS_munmap absent");
    test_check(syscall_table[SYS_mprotect] == NULL,
               "table SYS_mprotect absent");
}

static void test_syscall_invalid_num_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_invalid_num proc_current");
    if (!p)
        return;

    int64_t ret = dispatch_legacy(SYS_MAX, 0, 0, 0, 0, 0, 0);

    test_check(ret == -ENOSYS, "legacy_invalid_num enosys");
}

static void test_syscall_unimplemented_slot_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_unimplemented proc_current");
    if (!p)
        return;

    const uint64_t missing[] = {
        SYS_yield,
        SYS_clone,
        SYS_mmap,
        SYS_munmap,
        SYS_mprotect,
    };

    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); i++) {
        int64_t ret = dispatch_legacy(missing[i], 0, 0, 0, 0, 0, 0);
        test_check(ret == -ENOSYS, "legacy_unimplemented enosys");
    }
}

static void test_syscall_identity_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_identity proc_current");
    if (!p)
        return;

    int64_t pid = dispatch_legacy(SYS_getpid, 0, 0, 0, 0, 0, 0);
    int64_t ppid = dispatch_legacy(SYS_getppid, 0, 0, 0, 0, 0, 0);
    int64_t uid = dispatch_legacy(SYS_getuid, 0, 0, 0, 0, 0, 0);
    int64_t gid = dispatch_legacy(SYS_getgid, 0, 0, 0, 0, 0, 0);

    test_check(pid == (int64_t)p->tgid, "legacy_getpid matches_current");
    test_check(ppid == (int64_t)p->ppid, "legacy_getppid matches_current");
    test_check(uid == (int64_t)p->uid, "legacy_getuid matches_current");
    test_check(gid == (int64_t)p->gid, "legacy_getgid matches_current");
}

static void test_syscall_error_paths_legacy(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "legacy_errors proc_current");
    if (!p)
        return;

    int64_t uname_ret = dispatch_legacy(SYS_uname, 0, 0, 0, 0, 0, 0);
    test_check(uname_ret == -EFAULT, "legacy_uname null_efault");
}

static void test_uaccess_cross_page_regression(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "uaccess_cross_page proc_current");
    if (!p)
        return;

    struct mm_struct *saved_mm = p->mm;
    struct mm_struct *active_mm = saved_mm;
    struct mm_struct *temp_mm = NULL;
    paddr_t saved_pgdir = arch_mmu_current();
    bool switched_pgdir = false;

    if (!active_mm) {
        temp_mm = mm_create();
        test_check(temp_mm != NULL, "uaccess_cross_page mm_create");
        if (!temp_mm)
            return;
        p->mm = temp_mm;
        active_mm = temp_mm;
    }

    if (saved_pgdir != active_mm->pgdir) {
        arch_mmu_switch(active_mm->pgdir);
        switched_pgdir = true;
    }

    const size_t map_len = 3 * CONFIG_PAGE_SIZE;
    const size_t span = CONFIG_PAGE_SIZE + 64;
    vaddr_t map_start = 0;
    vaddr_t user_ptr = 0;

    int ret = mm_mmap(active_mm, 0, map_len, VM_READ | VM_WRITE, 0, NULL, 0,
                      false, &map_start);
    test_check(ret == 0, "uaccess_cross_page mmap");
    if (ret < 0)
        goto out_restore_mm;

    uint8_t *src = kmalloc(span);
    uint8_t *dst = kmalloc(span);
    test_check(src != NULL, "uaccess_cross_page kmalloc_src");
    test_check(dst != NULL, "uaccess_cross_page kmalloc_dst");
    if (!src || !dst)
        goto out_unmap;

    for (size_t i = 0; i < span; i++)
        src[i] = (uint8_t)((i * 131U + 7U) & 0xffU);

    user_ptr = map_start + CONFIG_PAGE_SIZE - 16;
    ret = copy_to_user((void *)user_ptr, src, span);
    test_check(ret == 0, "uaccess_cross_page copy_to_user");
    if (ret == 0) {
        vaddr_t page1 = ALIGN_DOWN(user_ptr, CONFIG_PAGE_SIZE);
        vaddr_t page2 = page1 + CONFIG_PAGE_SIZE;
        vaddr_t page3 = page2 + CONFIG_PAGE_SIZE;
        test_check(arch_mmu_translate(active_mm->pgdir, page1) != 0,
                   "uaccess_cross_page page1_faulted");
        test_check(arch_mmu_translate(active_mm->pgdir, page2) != 0,
                   "uaccess_cross_page page2_faulted");
        test_check(arch_mmu_translate(active_mm->pgdir, page3) != 0,
                   "uaccess_cross_page page3_faulted");
    }

    memset(dst, 0, span);
    ret = copy_from_user(dst, (const void *)user_ptr, span);
    test_check(ret == 0, "uaccess_cross_page copy_from_user");
    if (ret == 0)
        test_check(memcmp(src, dst, span) == 0, "uaccess_cross_page data_match");

out_unmap:
    ret = mm_munmap(active_mm, map_start, map_len);
    test_check(ret == 0, "uaccess_cross_page munmap");

    if (user_ptr && dst) {
        ret = copy_from_user(dst, (const void *)user_ptr, span);
        test_check(ret == -EFAULT, "uaccess_cross_page post_unmap_efault");
    }

    if (src)
        kfree(src);
    if (dst)
        kfree(dst);

out_restore_mm:
    if (switched_pgdir)
        arch_mmu_switch(saved_pgdir);
    if (temp_mm) {
        p->mm = saved_mm;
        mm_destroy(temp_mm);
    }
}

static void test_uaccess_large_range_regression(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "uaccess_large_range proc_current");
    if (!p)
        return;

    struct mm_struct *saved_mm = p->mm;
    struct mm_struct *active_mm = saved_mm;
    struct mm_struct *temp_mm = NULL;
    paddr_t saved_pgdir = arch_mmu_current();
    bool switched_pgdir = false;

    if (!active_mm) {
        temp_mm = mm_create();
        test_check(temp_mm != NULL, "uaccess_large_range mm_create");
        if (!temp_mm)
            return;
        p->mm = temp_mm;
        active_mm = temp_mm;
    }

    if (saved_pgdir != active_mm->pgdir) {
        arch_mmu_switch(active_mm->pgdir);
        switched_pgdir = true;
    }

    const size_t map_len = 12 * CONFIG_PAGE_SIZE;
    const size_t span = 7 * CONFIG_PAGE_SIZE + 257;
    vaddr_t map_start = 0;
    vaddr_t user_ptr = 0;

    int ret = mm_mmap(active_mm, 0, map_len, VM_READ | VM_WRITE, 0, NULL, 0,
                      false, &map_start);
    test_check(ret == 0, "uaccess_large_range mmap");
    if (ret < 0)
        goto out_restore_mm;

    uint8_t *src = kmalloc(span);
    uint8_t *dst = kmalloc(span);
    test_check(src != NULL, "uaccess_large_range kmalloc_src");
    test_check(dst != NULL, "uaccess_large_range kmalloc_dst");
    if (!src || !dst)
        goto out_unmap;

    for (size_t i = 0; i < span; i++)
        src[i] = (uint8_t)((i * 97U + 23U) & 0xffU);

    user_ptr = map_start + CONFIG_PAGE_SIZE / 2;
    ret = copy_to_user((void *)user_ptr, src, span);
    test_check(ret == 0, "uaccess_large_range copy_to_user");
    if (ret == 0) {
        vaddr_t first = ALIGN_DOWN(user_ptr, CONFIG_PAGE_SIZE);
        vaddr_t mid = first + 4 * CONFIG_PAGE_SIZE;
        vaddr_t last = ALIGN_DOWN(user_ptr + span - 1, CONFIG_PAGE_SIZE);
        test_check(arch_mmu_translate(active_mm->pgdir, first) != 0,
                   "uaccess_large_range first_faulted");
        test_check(arch_mmu_translate(active_mm->pgdir, mid) != 0,
                   "uaccess_large_range mid_faulted");
        test_check(arch_mmu_translate(active_mm->pgdir, last) != 0,
                   "uaccess_large_range last_faulted");
    }

    memset(dst, 0, span);
    ret = copy_from_user(dst, (const void *)user_ptr, span);
    test_check(ret == 0, "uaccess_large_range copy_from_user");
    if (ret == 0)
        test_check(memcmp(src, dst, span) == 0, "uaccess_large_range data_match");

    ret = mm_munmap(active_mm, map_start + 4 * CONFIG_PAGE_SIZE, CONFIG_PAGE_SIZE);
    test_check(ret == 0, "uaccess_large_range munmap_hole");
    if (ret == 0) {
        ret = copy_from_user(dst, (const void *)user_ptr, span);
        test_check(ret == -EFAULT, "uaccess_large_range hole_copy_from_efault");

        ret = copy_to_user((void *)user_ptr, src, span);
        test_check(ret == -EFAULT, "uaccess_large_range hole_copy_to_efault");
    }

out_unmap:
    ret = mm_munmap(active_mm, map_start, map_len);
    test_check(ret == 0, "uaccess_large_range munmap_all");

    if (src)
        kfree(src);
    if (dst)
        kfree(dst);

out_restore_mm:
    if (switched_pgdir)
        arch_mmu_switch(saved_pgdir);
    if (temp_mm) {
        p->mm = saved_mm;
        mm_destroy(temp_mm);
    }
}

static void test_strncpy_from_user_len_regression(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc = user_map_begin(&um, 2 * CONFIG_PAGE_SIZE);
    test_check(rc == 0, "uaccess_strncpy user_map");
    if (rc < 0)
        return;
    mapped = true;

    char *u_cross = (char *)user_map_ptr(&um, CONFIG_PAGE_SIZE - 2);
    char *u_plain = (char *)user_map_ptr(&um, 128);
    test_check(u_cross != NULL, "uaccess_strncpy u_cross");
    test_check(u_plain != NULL, "uaccess_strncpy u_plain");
    if (!u_cross || !u_plain)
        goto out;

    static const char cross_src[] = {'A', 'B', '\0', 'X'};
    rc = copy_to_user(u_cross, cross_src, sizeof(cross_src));
    test_check(rc == 0, "uaccess_strncpy copy_cross");
    if (rc == 0) {
        char out[16];
        memset(out, 0xcc, sizeof(out));
        long len = strncpy_from_user(out, u_cross, sizeof(out));
        test_check(len == 2, "uaccess_strncpy cross_len_excludes_nul");
        test_check(out[0] == 'A' && out[1] == 'B' && out[2] == '\0',
                   "uaccess_strncpy cross_content");
    }

    static const char plain_src[] = {'1', '2', '3', '4', '\0'};
    rc = copy_to_user(u_plain, plain_src, sizeof(plain_src));
    test_check(rc == 0, "uaccess_strncpy copy_plain");
    if (rc == 0) {
        char out[8];
        memset(out, 0xcc, sizeof(out));
        long len = strncpy_from_user(out, u_plain, sizeof(plain_src));
        test_check(len == 4, "uaccess_strncpy exact_len_excludes_nul");
        test_check(out[4] == '\0', "uaccess_strncpy exact_nul_copied");
    }

    static const char nonul_src[] = {'x', 'y', 'z'};
    rc = copy_to_user(u_plain, nonul_src, sizeof(nonul_src));
    test_check(rc == 0, "uaccess_strncpy copy_nonul");
    if (rc == 0) {
        char out[8];
        memset(out, 0, sizeof(out));
        long len = strncpy_from_user(out, u_plain, sizeof(nonul_src));
        test_check(len == 3, "uaccess_strncpy nonul_len_matches_count");
        test_check(out[0] == 'x' && out[1] == 'y' && out[2] == 'z',
                   "uaccess_strncpy nonul_content");
    }

out:
    if (mapped)
        user_map_end(&um);
}

static void test_strncpy_from_user_unmapped_tail_regression(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc = user_map_begin(&um, 2 * CONFIG_PAGE_SIZE);
    test_check(rc == 0, "uaccess_strncpy_tail user_map");
    if (rc < 0)
        return;
    mapped = true;

    char *u_tail = (char *)user_map_ptr(&um, CONFIG_PAGE_SIZE - 1);
    test_check(u_tail != NULL, "uaccess_strncpy_tail u_tail");
    if (!u_tail)
        goto out;

    static const char c = 'Q';
    rc = copy_to_user(u_tail, &c, 1);
    test_check(rc == 0, "uaccess_strncpy_tail copy_char");
    if (rc == 0) {
        rc = mm_munmap(um.active_mm, um.base + CONFIG_PAGE_SIZE, CONFIG_PAGE_SIZE);
        test_check(rc == 0, "uaccess_strncpy_tail munmap_next_page");
        if (rc == 0) {
            char out[8];
            memset(out, 0, sizeof(out));
            long len = strncpy_from_user(out, u_tail, 4);
            test_check(len == -EFAULT,
                       "uaccess_strncpy_tail unmapped_tail_efault");
        }
    }

out:
    if (mapped)
        user_map_end(&um);
}

static void test_uaccess_arg_validation_regression(void) {
    uint8_t src = 0x5a;
    uint8_t dst = 0;
    void *bad = (void *)(~(uintptr_t)0);

    int ret = copy_from_user(&dst, bad, 1);
    test_check(ret == -EFAULT, "uaccess_arg bad_from_efault");

    ret = copy_to_user(bad, &src, 1);
    test_check(ret == -EFAULT, "uaccess_arg bad_to_efault");

    ret = copy_from_user(&dst, NULL, 0);
    test_check(ret == 0, "uaccess_arg zero_from_ok");

    ret = copy_to_user(NULL, &src, 0);
    test_check(ret == 0, "uaccess_arg zero_to_ok");
}

static void test_sched_affinity_syscalls_regression(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "affinity proc_current");
    if (!p)
        return;

    struct user_map_ctx um = {0};
    bool mapped = false;
    unsigned long saved_mask = 0;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "affinity user_map");
    if (rc < 0)
        goto out;
    mapped = true;

    unsigned long *u_mask = (unsigned long *)user_map_ptr(&um, 0);
    test_check(u_mask != NULL, "affinity user_ptr");
    if (!u_mask)
        goto out;

    int64_t ret64 = sys_sched_getaffinity(0, sizeof(unsigned long) - 1,
                                          (uint64_t)u_mask, 0, 0, 0);
    test_check(ret64 == -EINVAL, "affinity get len_einval");

    ret64 = sys_sched_getaffinity(0, sizeof(unsigned long), 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "affinity get null_efault");

    ret64 = sys_sched_getaffinity(0, sizeof(unsigned long), (uint64_t)u_mask, 0,
                                  0, 0);
    test_check(ret64 == (int64_t)sizeof(unsigned long), "affinity get ok");
    if (ret64 == (int64_t)sizeof(unsigned long)) {
        rc = copy_from_user(&saved_mask, u_mask, sizeof(saved_mask));
        test_check(rc == 0, "affinity get copy_mask");
        if (rc == 0)
            test_check(saved_mask != 0, "affinity get nonzero_mask");
    }

    ret64 = sys_sched_getaffinity(0x7fffffffU, sizeof(unsigned long),
                                  (uint64_t)u_mask, 0, 0, 0);
    test_check(ret64 == -ESRCH, "affinity get bad_pid_esrch");

    ret64 = sys_sched_setaffinity(0, sizeof(unsigned long) - 1, (uint64_t)u_mask,
                                  0, 0, 0);
    test_check(ret64 == -EINVAL, "affinity set len_einval");

    ret64 = sys_sched_setaffinity(0, sizeof(unsigned long), 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "affinity set null_efault");

    unsigned long req_mask = 0;
    rc = copy_to_user(u_mask, &req_mask, sizeof(req_mask));
    test_check(rc == 0, "affinity set copy_zero");
    if (rc == 0) {
        ret64 = sys_sched_setaffinity(0, sizeof(unsigned long), (uint64_t)u_mask,
                                      0, 0, 0);
        test_check(ret64 == -EINVAL, "affinity set zero_einval");
    }

    if (saved_mask) {
        rc = copy_to_user(u_mask, &saved_mask, sizeof(saved_mask));
        test_check(rc == 0, "affinity set copy_saved");
        if (rc == 0) {
            ret64 = sys_sched_setaffinity(0, sizeof(unsigned long),
                                          (uint64_t)u_mask, 0, 0, 0);
            test_check(ret64 == 0, "affinity set restore_ok");
        }
    }

    int cpus = sched_cpu_count();
    int bits = (int)(sizeof(unsigned long) * 8);
    int current_cpu = p->se.cpu;
    if (saved_mask && cpus > 1 && current_cpu >= 0 && current_cpu < bits) {
        unsigned long alt_mask = saved_mask & ~(1UL << current_cpu);
        if (alt_mask != 0) {
            rc = copy_to_user(u_mask, &alt_mask, sizeof(alt_mask));
            test_check(rc == 0, "affinity set copy_alt");
            if (rc == 0) {
                ret64 = sys_sched_setaffinity(0, sizeof(unsigned long),
                                              (uint64_t)u_mask, 0, 0, 0);
                test_check(ret64 == 0, "affinity set running_exclude_ok");
                if (ret64 == 0) {
                    proc_yield();
                    struct process *cur = proc_current();
                    int cur_cpu = cur ? cur->se.cpu : -1;
                    bool allowed =
                        cur_cpu >= 0 && cur_cpu < bits &&
                        ((alt_mask & (1UL << cur_cpu)) != 0);
                    test_check(allowed, "affinity set migrated_to_allowed_cpu");
                }
            }
            rc = copy_to_user(u_mask, &saved_mask, sizeof(saved_mask));
            if (rc == 0)
                (void)sys_sched_setaffinity(0, sizeof(unsigned long),
                                            (uint64_t)u_mask, 0, 0, 0);
        }
    }

out:
    if (mapped)
        user_map_end(&um);
}

#define SYSCALL_MOUNT_FLAG_TEST_PATH "/tmp/.kairos_syscall_mount_flags"
#define SYSCALL_ACCT_TEST_FILE "/tmp/.kairos_syscall_acct"

static void test_mount_umount_flag_semantics(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;
    int rc;

    (void)vfs_umount(SYSCALL_MOUNT_FLAG_TEST_PATH);
    (void)vfs_rmdir(SYSCALL_MOUNT_FLAG_TEST_PATH);

    rc = vfs_mkdir(SYSCALL_MOUNT_FLAG_TEST_PATH, 0755);
    test_check(rc == 0 || rc == -EEXIST, "mountflags mkdir");
    if (rc < 0 && rc != -EEXIST)
        goto out;

    rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "mountflags user_map");
    if (rc < 0)
        goto out;
    mapped = true;

    char *u_tgt = (char *)user_map_ptr(&um, 0x000);
    char *u_fstype = (char *)user_map_ptr(&um, 0x100);
    test_check(u_tgt != NULL, "mountflags u_tgt");
    test_check(u_fstype != NULL, "mountflags u_fstype");
    if (!u_tgt || !u_fstype)
        goto out;

    rc = copy_to_user(u_tgt, SYSCALL_MOUNT_FLAG_TEST_PATH,
                      strlen(SYSCALL_MOUNT_FLAG_TEST_PATH) + 1);
    test_check(rc == 0, "mountflags copy tgt");
    rc = copy_to_user(u_fstype, "tmpfs", 6);
    test_check(rc == 0, "mountflags copy fstype");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_mount(0, (uint64_t)u_tgt, (uint64_t)u_fstype,
                              MS_RDONLY | MS_NODEV | MS_NOEXEC, 0, 0);
    test_check(ret64 == 0, "mountflags mount semantic");

    ret64 = sys_mount(0, (uint64_t)u_tgt, 0,
                      MS_REMOUNT | MS_RDONLY | MS_NOEXEC, 0, 0);
    test_check(ret64 == 0, "mountflags remount semantic");

    ret64 = sys_umount2((uint64_t)u_tgt, MNT_DETACH | UMOUNT_NOFOLLOW, 0, 0, 0, 0);
    test_check(ret64 == 0, "mountflags umount2 detach_nofollow");

    ret64 = sys_umount2((uint64_t)u_tgt, MNT_EXPIRE, 0, 0, 0, 0);
    test_check(ret64 == -EINVAL, "mountflags umount2 unsupported");

out:
    if (mapped)
        user_map_end(&um);
    (void)vfs_umount(SYSCALL_MOUNT_FLAG_TEST_PATH);
    (void)vfs_rmdir(SYSCALL_MOUNT_FLAG_TEST_PATH);
}

static void test_acct_syscall_semantics(void) {
    struct process *p = proc_current();
    test_check(p != NULL, "acct proc_current");
    if (!p)
        return;

    uid_t saved_uid = p->uid;
    struct user_map_ctx um = {0};
    bool mapped = false;
    struct file *f = NULL;

    int rc = vfs_open(SYSCALL_ACCT_TEST_FILE, O_CREAT | O_TRUNC | O_RDWR, 0644, &f);
    test_check(rc == 0, "acct create file");
    if (rc == 0 && f)
        vfs_close(f);

    rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "acct user_map");
    if (rc < 0)
        goto out_restore_uid;
    mapped = true;

    char *u_path = (char *)user_map_ptr(&um, 0x000);
    char *u_dir = (char *)user_map_ptr(&um, 0x100);
    test_check(u_path != NULL, "acct u_path");
    test_check(u_dir != NULL, "acct u_dir");
    if (!u_path || !u_dir)
        goto out;

    rc = copy_to_user(u_path, SYSCALL_ACCT_TEST_FILE, strlen(SYSCALL_ACCT_TEST_FILE) + 1);
    test_check(rc == 0, "acct copy file");
    rc = copy_to_user(u_dir, "/tmp", 5);
    test_check(rc == 0, "acct copy dir");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_acct((uint64_t)u_path, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "acct enable root");

    ret64 = sys_acct(0, 0, 0, 0, 0, 0);
    test_check(ret64 == 0, "acct disable root");

    ret64 = sys_acct((uint64_t)u_dir, 0, 0, 0, 0, 0);
    test_check(ret64 == -EISDIR, "acct dir eisdir");

    ret64 = sys_acct(0x1000, 0, 0, 0, 0, 0);
    test_check(ret64 == -EFAULT, "acct badptr efault");

    p->uid = 1000;
    ret64 = sys_acct((uint64_t)u_path, 0, 0, 0, 0, 0);
    test_check(ret64 == -EPERM, "acct nonroot eperm");
    p->uid = saved_uid;

out:
    if (mapped)
        user_map_end(&um);
out_restore_uid:
    p->uid = saved_uid;
    (void)vfs_unlink(SYSCALL_ACCT_TEST_FILE);
}

static void test_futex_waitv_syscalls_regression(void) {
    struct user_map_ctx um = {0};
    bool mapped = false;

    int rc = user_map_begin(&um, CONFIG_PAGE_SIZE);
    test_check(rc == 0, "futex_waitv user_map");
    if (rc < 0)
        goto out;
    mapped = true;

    uint32_t *u_word = (uint32_t *)user_map_ptr(&um, 0);
    struct futex_waitv *u_waiter =
        (struct futex_waitv *)user_map_ptr(&um, 64);
    struct timespec *u_timeout =
        (struct timespec *)user_map_ptr(&um, 128);
    test_check(u_word != NULL, "futex_waitv u_word");
    test_check(u_waiter != NULL, "futex_waitv u_waiter");
    test_check(u_timeout != NULL, "futex_waitv u_timeout");
    if (!u_word || !u_waiter || !u_timeout)
        goto out;

    uint32_t word = 0;
    rc = copy_to_user(u_word, &word, sizeof(word));
    test_check(rc == 0, "futex_waitv init_word");
    if (rc < 0)
        goto out;

    struct futex_waitv waiter = {
        .val = 0,
        .uaddr = (uint64_t)(uintptr_t)u_word,
        .flags = FUTEX_32,
        .__reserved = 0,
    };
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv init_waiter");
    if (rc < 0)
        goto out;

    int64_t ret64 = sys_futex_waitv(0, 1, 0, 0, CLOCK_MONOTONIC, 0);
    test_check(ret64 == -EFAULT, "futex_waitv null_waiters_efault");

    ret64 = sys_futex_waitv((uint64_t)u_waiter, 0, 0, 0, CLOCK_MONOTONIC, 0);
    test_check(ret64 == -EINVAL, "futex_waitv nr_zero_einval");

    ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 1, 0, CLOCK_MONOTONIC, 0);
    test_check(ret64 == -EINVAL, "futex_waitv flags_einval");

    waiter.flags = 0;
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv copy_bad_flags");
    if (rc == 0) {
        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, 0, CLOCK_MONOTONIC, 0);
        test_check(ret64 == -EINVAL, "futex_waitv waiter_flags_einval");
    }

    waiter.flags = FUTEX_32;
    waiter.__reserved = 1;
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv copy_reserved");
    if (rc == 0) {
        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, 0, CLOCK_MONOTONIC, 0);
        test_check(ret64 == -EINVAL, "futex_waitv reserved_einval");
    }

    waiter.__reserved = 0;
    waiter.val = 1;
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv copy_eagain_waiter");
    if (rc == 0) {
        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, 0, CLOCK_MONOTONIC, 0);
        test_check(ret64 == -EAGAIN, "futex_waitv value_mismatch_eagain");
    }

    waiter.val = 0;
    rc = copy_to_user(u_waiter, &waiter, sizeof(waiter));
    test_check(rc == 0, "futex_waitv copy_timeout_waiter");
    if (rc == 0) {
        uint64_t now_ns = time_now_ns();
        struct timespec abs = ns_to_timespec(now_ns);
        rc = copy_to_user(u_timeout, &abs, sizeof(abs));
        test_check(rc == 0, "futex_waitv copy_timeout_now");
        if (rc == 0) {
            ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, (uint64_t)u_timeout,
                                    CLOCK_MONOTONIC, 0);
            test_check(ret64 == -ETIMEDOUT, "futex_waitv timeout_etimedout");
        }

        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, (uint64_t)u_timeout,
                                12345, 0);
        test_check(ret64 == -EINVAL, "futex_waitv bad_clock_einval");
    }

    struct futex_waker_ctx wctx = {
        .uaddr = (vaddr_t)u_word,
        .started = 0,
        .wake_ret = 0,
    };
    struct process *waker =
        kthread_create_joinable(futex_waitv_waker_worker, &wctx, "fwaitv");
    test_check(waker != NULL, "futex_waitv create_waker");
    if (!waker)
        goto out;
    pid_t wpid = waker->pid;
    sched_enqueue(waker);
    for (int i = 0; i < 2000 && !wctx.started; i++)
        proc_yield();
    test_check(wctx.started != 0, "futex_waitv waker_started");

    uint64_t wake_deadline_ns = time_now_ns() + 1000ULL * 1000ULL * 1000ULL;
    struct timespec wake_abs = ns_to_timespec(wake_deadline_ns);
    rc = copy_to_user(u_timeout, &wake_abs, sizeof(wake_abs));
    test_check(rc == 0, "futex_waitv copy_wake_timeout");
    if (rc == 0) {
        ret64 = sys_futex_waitv((uint64_t)u_waiter, 1, 0, (uint64_t)u_timeout,
                                CLOCK_MONOTONIC, 0);
        test_check(ret64 == 0, "futex_waitv wake_index_zero");
    }

    int status = 0;
    pid_t wp = proc_wait(wpid, &status, 0);
    test_check(wp == wpid, "futex_waitv waker_reaped");
    test_check(wctx.wake_ret > 0, "futex_waitv wake_positive");

out:
    if (mapped)
        user_map_end(&um);
}

static void test_trap_dispatch_guard_clauses(void) {
    struct trap_frame tf;
    memset(&tf, 0, sizeof(tf));

    struct trap_core_event ev = {
        .type = TRAP_CORE_EVENT_SYSCALL,
        .tf = &tf,
        .from_user = false,
        .code = 0,
        .fault_addr = 0,
    };
    struct trap_core_ops ops = {
        .handle_event = trap_handle_probe,
        .should_deliver_signals = trap_should_deliver_false,
    };
    struct trap_core_ops ops_no_handler = {
        .handle_event = NULL,
        .should_deliver_signals = trap_should_deliver_false,
    };

    trap_handle_calls = 0;
    trap_should_deliver_calls = 0;

    trap_core_dispatch(NULL, &ops);
    trap_core_dispatch(&ev, NULL);
    trap_core_dispatch(&ev, &ops_no_handler);
    ev.tf = NULL;
    trap_core_dispatch(&ev, &ops);

    test_check(trap_handle_calls == 0, "trap_guard no_handle_calls");
    test_check(trap_should_deliver_calls == 0, "trap_guard no_deliver_calls");
}

static void test_trap_dispatch_sets_and_restores_tf(void) {
    struct trap_frame tf;
    memset(&tf, 0, sizeof(tf));

    struct trap_core_event ev = {
        .type = TRAP_CORE_EVENT_SYSCALL,
        .tf = &tf,
        .from_user = false,
        .code = 0,
        .fault_addr = 0,
    };
    struct trap_core_ops ops = {
        .handle_event = trap_handle_probe,
        .should_deliver_signals = trap_should_deliver_false,
    };

    struct percpu_data *cpu = arch_get_percpu();
    struct trap_frame *old_tf = cpu->current_tf;

    trap_handle_calls = 0;
    trap_should_deliver_calls = 0;
    trap_handler_saw_current_tf = false;
    trap_handler_tf = NULL;

    trap_core_dispatch(&ev, &ops);

    test_check(trap_handle_calls == 1, "trap_dispatch handle_called");
    test_check(trap_should_deliver_calls == 1, "trap_dispatch deliver_called");
    test_check(trap_handler_tf == &tf, "trap_dispatch handler_tf");
    test_check(trap_handler_saw_current_tf, "trap_dispatch saw_current_tf");
    test_check(cpu->current_tf == old_tf, "trap_dispatch restored_tf");
}

static void test_trap_dispatch_restores_preexisting_tf(void) {
    struct trap_frame tf;
    struct trap_frame injected_old;
    memset(&tf, 0, sizeof(tf));
    memset(&injected_old, 0, sizeof(injected_old));

    struct trap_core_event ev = {
        .type = TRAP_CORE_EVENT_PAGE_FAULT,
        .tf = &tf,
        .from_user = true,
        .code = 1,
        .fault_addr = 0x1000,
    };
    struct trap_core_ops ops = {
        .handle_event = trap_handle_probe,
        .should_deliver_signals = trap_should_deliver_false,
    };

    struct percpu_data *cpu = arch_get_percpu();
    struct trap_frame *saved = cpu->current_tf;
    cpu->current_tf = &injected_old;

    trap_handle_calls = 0;
    trap_should_deliver_calls = 0;
    trap_handler_saw_current_tf = false;
    trap_handler_tf = NULL;

    trap_core_dispatch(&ev, &ops);

    test_check(trap_handle_calls == 1, "trap_restore_nonnull handle_called");
    test_check(trap_should_deliver_calls == 1,
               "trap_restore_nonnull deliver_called");
    test_check(trap_handler_tf == &tf, "trap_restore_nonnull handler_tf");
    test_check(trap_handler_saw_current_tf, "trap_restore_nonnull saw_current");
    test_check(cpu->current_tf == &injected_old,
               "trap_restore_nonnull restored_previous");

    cpu->current_tf = saved;
}

int run_syscall_trap_tests(void) {
    tests_failed = 0;
    pr_info("Running syscall/trap tests...\n");

    test_syscall_table_slot_coverage();
    test_syscall_invalid_num_legacy();
    test_syscall_unimplemented_slot_legacy();
    test_syscall_identity_legacy();
    test_syscall_error_paths_legacy();
    test_uaccess_cross_page_regression();
    test_uaccess_large_range_regression();
    test_strncpy_from_user_len_regression();
    test_strncpy_from_user_unmapped_tail_regression();
    test_uaccess_arg_validation_regression();
    test_sched_affinity_syscalls_regression();
    test_mount_umount_flag_semantics();
    test_acct_syscall_semantics();
    test_futex_waitv_syscalls_regression();
    test_trap_dispatch_guard_clauses();
    test_trap_dispatch_sets_and_restores_tf();
    test_trap_dispatch_restores_preexisting_tf();
    test_syscall_user_e2e();

    if (tests_failed == 0)
        pr_info("syscall/trap tests: all passed\n");
    else
        pr_err("syscall/trap tests: %d failures\n", tests_failed);

    return tests_failed;
}

#else

int run_syscall_trap_tests(void) { return 0; }

#endif /* CONFIG_KERNEL_TESTS */
