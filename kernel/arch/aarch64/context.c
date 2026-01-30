/**
 * kernel/arch/aarch64/context.c - AArch64 context management
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/string.h>
#include <kairos/types.h>

struct arch_context {
    uint64_t x19;
    uint64_t x20;
    uint64_t x21;
    uint64_t x22;
    uint64_t x23;
    uint64_t x24;
    uint64_t x25;
    uint64_t x26;
    uint64_t x27;
    uint64_t x28;
    uint64_t x29;
    uint64_t sp;
    uint64_t lr;
    uint64_t kernel_stack;
    uint64_t user_stack;
    uint64_t ttbr0;
    uint64_t kthread_fn;
    uint64_t kthread_arg;
};

extern void kthread_entry(void);
extern void fork_ret(void);

struct arch_context *arch_context_alloc(void) {
    struct arch_context *ctx = kmalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    struct page *pg = alloc_pages(1);
    if (!pg) {
        kfree(ctx);
        return NULL;
    }
    void *stack_addr = phys_to_virt(page_to_phys(pg));
    memset(stack_addr, 0, 2 * CONFIG_PAGE_SIZE);

    memset(ctx, 0, sizeof(*ctx));
    ctx->kernel_stack = (uint64_t)stack_addr + (2 * CONFIG_PAGE_SIZE) - 8;
    ctx->sp = ctx->kernel_stack;
    return ctx;
}

void arch_context_free(struct arch_context *ctx) {
    if (!ctx)
        return;
    if (ctx->kernel_stack) {
        void *stack_bottom =
            (void *)(ctx->kernel_stack + 8 - (2 * CONFIG_PAGE_SIZE));
        struct page *pg = phys_to_page(virt_to_phys(stack_bottom));
        if (pg)
            free_pages(pg, 1);
    }
    kfree(ctx);
}

void arch_context_set_cpu(struct arch_context *ctx, int cpu) {
    if (ctx && ctx->kernel_stack) {
        *(uint64_t *)ctx->kernel_stack = (uint64_t)cpu;
    }
}

void arch_context_init(struct arch_context *ctx, vaddr_t entry, vaddr_t arg,
                       bool kernel) {
    ctx->sp = ctx->kernel_stack;
    if (kernel) {
        ctx->lr = (uint64_t)kthread_entry;
        ctx->x19 = entry;
        ctx->x20 = arg;
        ctx->kthread_fn = entry;
        ctx->kthread_arg = arg;
    } else {
        struct trap_frame *tf =
            (struct trap_frame *)(ctx->kernel_stack - sizeof(struct trap_frame));
        memset(tf, 0, sizeof(*tf));
        tf->elr = entry;
        tf->sp = arg;
        tf->spsr = 0;
        ctx->lr = (uint64_t)fork_ret;
        ctx->sp = (uint64_t)tf;
        ctx->user_stack = arg;
    }
}

void arch_context_clone(struct arch_context *dst, struct arch_context *src) {
    *dst = *src;
}

void arch_setup_fork_child(struct arch_context *ctx, struct trap_frame *tf) {
    struct trap_frame *child_tf =
        (struct trap_frame *)(ctx->kernel_stack - sizeof(*tf));
    memcpy(child_tf, tf, sizeof(*tf));
    child_tf->tf_a0 = 0;
    ctx->lr = (uint64_t)fork_ret;
    ctx->sp = (uint64_t)child_tf;
}

void arch_context_set_retval(struct arch_context *ctx, uint64_t val) {
    ((struct trap_frame *)ctx->sp)->tf_a0 = val;
}

void arch_context_set_args(struct arch_context *ctx, uint64_t a0, uint64_t a1,
                           uint64_t a2) {
    struct trap_frame *tf = (struct trap_frame *)ctx->sp;
    tf->tf_a0 = a0;
    tf->tf_a1 = a1;
    tf->tf_a2 = a2;
}

void arch_set_tls(struct arch_context *ctx, uint64_t tls) {
    (void)ctx;
    /* Set tpidr_el0 directly; restored on context switch */
    __asm__ __volatile__("msr tpidr_el0, %0" :: "r"(tls));
}

void arch_context_set_user_sp(struct arch_context *ctx, vaddr_t sp) {
    if (!ctx)
        return;
    struct trap_frame *tf = (struct trap_frame *)ctx->sp;
    tf->sp = sp;
    ctx->user_stack = sp;
}
