/**
 * kernel/arch/x86_64/context.c - x86_64 context management
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
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
    ctx->rsp = ctx->kernel_stack;
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
    *dst = *src;
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

void arch_context_set_user_sp(struct arch_context *ctx, vaddr_t sp) {
    if (!ctx)
        return;
    struct trap_frame *tf = (struct trap_frame *)ctx->rsp;
    tf->rsp = sp;
    ctx->user_stack = sp;
}
