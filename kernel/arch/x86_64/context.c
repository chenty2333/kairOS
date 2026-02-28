/**
 * kernel/arch/x86_64/context.c - x86_64 context management
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/types.h>

struct arch_context {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rsp;
    uint64_t rflags;
    uint64_t kernel_stack;
    uint64_t user_stack;
    uint64_t cr3;
    uint64_t kthread_fn;
    uint64_t kthread_arg;
    uint64_t fs_base;
};

extern void kthread_entry(void);
extern void fork_ret(void);

static inline bool stack_addr_in_range(uint64_t addr, uint64_t bottom,
                                       uint64_t top) {
    return addr >= bottom && addr <= top;
}

static inline uint64_t stack_rebase_addr(uint64_t addr, uint64_t src_top,
                                         uint64_t dst_top) {
    return dst_top - (src_top - addr);
}

static void rebase_saved_rbp_chain(struct arch_context *dst, uint64_t src_bottom,
                                   uint64_t src_top, uint64_t dst_bottom,
                                   uint64_t dst_top, uint64_t stack_bytes) {
    if (!stack_addr_in_range(dst->rbp, dst_bottom, dst_top))
        return;

    uint64_t fp = dst->rbp;
    uint64_t max_steps = stack_bytes / sizeof(uint64_t);
    for (uint64_t i = 0; i < max_steps; i++) {
        if (fp < dst_bottom || fp > (dst_top - sizeof(uint64_t)))
            break;
        uint64_t next = *(uint64_t *)fp;
        if (!stack_addr_in_range(next, src_bottom, src_top))
            break;
        uint64_t rebased = stack_rebase_addr(next, src_top, dst_top);
        *(uint64_t *)fp = rebased;
        if (rebased <= fp)
            break;
        fp = rebased;
    }
}

struct arch_context *arch_context_alloc(void) {
    struct arch_context *ctx = kmalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    struct page *pg = alloc_pages(CONFIG_KERNEL_STACK_ORDER);
    if (!pg) {
        kfree(ctx);
        return NULL;
    }

    void *stack_addr = phys_to_virt(page_to_phys(pg));
    memset(stack_addr, 0, CONFIG_KERNEL_STACK_SIZE);

    memset(ctx, 0, sizeof(*ctx));
    ctx->kernel_stack = (uint64_t)stack_addr + CONFIG_KERNEL_STACK_SIZE - 8;
    ctx->rsp = ctx->kernel_stack;
    return ctx;
}

void arch_context_free(struct arch_context *ctx) {
    if (!ctx)
        return;
    if (ctx->kernel_stack) {
        void *stack_bottom =
            (void *)(ctx->kernel_stack + 8 - CONFIG_KERNEL_STACK_SIZE);
        struct page *pg = phys_to_page(virt_to_phys(stack_bottom));
        if (pg)
            free_pages(pg, CONFIG_KERNEL_STACK_ORDER);
    }
    kfree(ctx);
}

void arch_context_set_cpu(struct arch_context *ctx, int cpu) {
    if (!ctx)
        return;
    if (ctx->kernel_stack)
        *(uint64_t *)ctx->kernel_stack = (uint64_t)cpu;
    __asm__ __volatile__("wrmsr" :: "c"(0xC0000100),
                         "a"((uint32_t)ctx->fs_base),
                         "d"((uint32_t)(ctx->fs_base >> 32)));
}

void arch_context_init(struct arch_context *ctx, vaddr_t entry, vaddr_t arg,
                       bool kernel) {
    ctx->rsp = ctx->kernel_stack;
    if (kernel) {
        ctx->rip = (uint64_t)kthread_entry;
        ctx->r12 = entry;
        ctx->r13 = arg;
        ctx->kthread_fn = entry;
        ctx->kthread_arg = arg;
    } else {
        struct trap_frame *tf =
            (struct trap_frame *)(ctx->kernel_stack - sizeof(struct trap_frame));
        memset(tf, 0, sizeof(*tf));
        tf->rip = entry;
        tf->rsp = arg;
        tf->cs = 0x1B;
        tf->ss = 0x23;
        tf->rflags = 0x202;
        ctx->rip = (uint64_t)fork_ret;
        ctx->rsp = (uint64_t)tf;
        ctx->user_stack = arg;
    }
}

void arch_context_clone(struct arch_context *dst, struct arch_context *src) {
    if (!dst || !src)
        return;

    uint64_t dst_top = dst->kernel_stack;
    uint64_t src_top = src->kernel_stack;
    uint64_t stack_bytes = CONFIG_KERNEL_STACK_SIZE;

    *dst = *src;
    dst->kernel_stack = dst_top;

    if (!dst_top || !src_top)
        return;

    uint64_t src_bottom = src_top + sizeof(uint64_t) - stack_bytes;
    uint64_t dst_bottom = dst_top + sizeof(uint64_t) - stack_bytes;
    memcpy((void *)dst_bottom, (const void *)src_bottom, (size_t)stack_bytes);

    if (stack_addr_in_range(src->rsp, src_bottom, src_top))
        dst->rsp = stack_rebase_addr(src->rsp, src_top, dst_top);
    if (stack_addr_in_range(src->rbp, src_bottom, src_top))
        dst->rbp = stack_rebase_addr(src->rbp, src_top, dst_top);

    /* Rebase saved frame links so leave/ret cannot pivot back to src stack. */
    rebase_saved_rbp_chain(dst, src_bottom, src_top, dst_bottom, dst_top,
                           stack_bytes);
}

void arch_setup_fork_child(struct arch_context *ctx, struct trap_frame *tf) {
    struct trap_frame *child_tf =
        (struct trap_frame *)(ctx->kernel_stack - sizeof(*tf));
    memcpy(child_tf, tf, sizeof(*tf));
    child_tf->rax = 0;
    ctx->rip = (uint64_t)fork_ret;
    ctx->rsp = (uint64_t)child_tf;
}

void arch_context_set_retval(struct arch_context *ctx, uint64_t val) {
    ((struct trap_frame *)ctx->rsp)->rax = val;
}

void arch_context_set_args(struct arch_context *ctx, uint64_t a0, uint64_t a1,
                           uint64_t a2) {
    struct trap_frame *tf = (struct trap_frame *)ctx->rsp;
    tf->rdi = a0;
    tf->rsi = a1;
    tf->rdx = a2;
}

void arch_set_tls(struct arch_context *ctx, uint64_t tls) {
    if (!ctx)
        return;
    ctx->fs_base = tls;
    struct process *cur = proc_current();
    if (!cur || cur->context != ctx)
        return;
    __asm__ __volatile__("wrmsr" :: "c"(0xC0000100), "a"((uint32_t)tls),
                         "d"((uint32_t)(tls >> 32)));
}

uint64_t arch_get_tls(const struct arch_context *ctx) {
    return ctx ? ctx->fs_base : 0;
}

void arch_context_set_user_sp(struct arch_context *ctx, vaddr_t sp) {
    if (!ctx)
        return;
    struct trap_frame *tf = (struct trap_frame *)ctx->rsp;
    tf->rsp = sp;
    ctx->user_stack = sp;
}

uint64_t arch_context_kernel_stack(const struct arch_context *ctx) {
    return ctx ? ctx->kernel_stack : 0;
}
