/**
 * kernel/arch/riscv64/context.c - RISC-V 64 Context Management
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>

/**
 * Architecture context structure
 * Must match the layout expected by switch.S and trapasm.S
 */
struct arch_context {
    uint64_t ra;           /* 0x00: Return address */
    uint64_t sp;           /* 0x08: Stack pointer */
    uint64_t s[12];        /* 0x10 - 0x68: s0-s11 */
    uint64_t kernel_stack; /* 0x70: Kernel stack base (top) */
    uint64_t user_stack;   /* 0x78: User stack pointer */
    uint64_t satp;         /* 0x80: Page table */
    uint64_t kthread_fn;   /* For kernel threads */
    uint64_t kthread_arg;
};

/* External entry points */
extern void kthread_entry(void);
extern void trap_return(void);

struct arch_context *arch_context_alloc(void) {
    struct arch_context *ctx = kmalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    /* Allocate 8KB kernel stack (order 1 = 2 pages) */
    struct page *pg = alloc_pages(1);
    if (!pg) {
        kfree(ctx);
        return NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->kernel_stack =
        (uint64_t)phys_to_virt(page_to_phys(pg)) + (2 * CONFIG_PAGE_SIZE);
    ctx->sp = ctx->kernel_stack;

    return ctx;
}

void arch_context_free(struct arch_context *ctx) {
    if (!ctx)
        return;
    if (ctx->kernel_stack) {
        void *stack_bottom =
            (void *)(ctx->kernel_stack - (2 * CONFIG_PAGE_SIZE));
        struct page *pg = phys_to_page(virt_to_phys(stack_bottom));
        if (pg)
            free_pages(pg, 1);
    }
    kfree(ctx);
}

void arch_context_init(struct arch_context *ctx, vaddr_t entry, vaddr_t arg,
                       bool kernel) {
    ctx->sp = ctx->kernel_stack;
    if (kernel) {
        ctx->ra = (uint64_t)kthread_entry;
        ctx->s[0] = entry; /* s0 = fn */
        ctx->s[1] = arg;   /* s1 = arg */
        ctx->kthread_fn = entry;
        ctx->kthread_arg = arg;
    } else {
        /* User process: Create a fake trap frame to return to U-mode */
        struct trap_frame *tf = (struct trap_frame *)(ctx->kernel_stack - sizeof(struct trap_frame));
        memset(tf, 0, sizeof(*tf));
        
        tf->sepc = entry;
        tf->tf_sp = arg;
        /* sstatus: SPIE=1 (enable interrupts after sret), SPP=0 (return to U-mode) */
        tf->sstatus = (1UL << 5); 
        
        ctx->ra = (uint64_t)trap_return;
        ctx->sp = (uint64_t)tf;
        ctx->user_stack = arg;
    }
}

void arch_context_clone(struct arch_context *dst, struct arch_context *src) {
    uint64_t saved_kstack = dst->kernel_stack;
    uint64_t saved_sp = dst->sp;
    memcpy(dst, src, sizeof(*dst));
    dst->kernel_stack = saved_kstack;
    dst->sp = saved_sp;
}

void arch_setup_fork_child(struct arch_context *ctx, struct trap_frame *tf) {
    /* Place trap frame at the top of the child's kernel stack */
    struct trap_frame *child_tf =
        (struct trap_frame *)(ctx->kernel_stack - sizeof(*tf));
    memcpy(child_tf, tf, sizeof(*tf));

    child_tf->tf_a0 = 0; /* a0 = 0 for child */
    child_tf->sepc += 4; /* skip ecall */

    ctx->ra = (uint64_t)trap_return;
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