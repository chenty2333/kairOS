/**
 * context.c - RISC-V 64 Context Management
 *
 * Implements architecture context allocation and initialization.
 */

#include <kairos/types.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/config.h>

/**
 * Architecture context structure
 *
 * Contains saved registers and stack information.
 * Must match the layout expected by context.S
 */
struct arch_context {
    /* Callee-saved registers */
    uint64_t ra;        /* 0x00: Return address */
    uint64_t sp;        /* 0x08: Stack pointer */
    uint64_t s0;        /* 0x10: Frame pointer */
    uint64_t s1;        /* 0x18 */
    uint64_t s2;        /* 0x20 */
    uint64_t s3;        /* 0x28 */
    uint64_t s4;        /* 0x30 */
    uint64_t s5;        /* 0x38 */
    uint64_t s6;        /* 0x40 */
    uint64_t s7;        /* 0x48 */
    uint64_t s8;        /* 0x50 */
    uint64_t s9;        /* 0x58 */
    uint64_t s10;       /* 0x60 */
    uint64_t s11;       /* 0x68 */

    /* Stack and page table info */
    uint64_t kernel_stack;  /* 0x70: Kernel stack base */
    uint64_t user_stack;    /* 0x78: User stack pointer */
    uint64_t satp;          /* 0x80: Page table (satp register value) */

    /* For kernel threads: function and argument */
    uint64_t kthread_fn;    /* Function pointer */
    uint64_t kthread_arg;   /* Function argument */
};

/* External entry point for new kernel threads */
extern void kthread_entry(void);

/**
 * arch_context_alloc - Allocate architecture context
 *
 * Allocates a context structure and kernel stack.
 */
struct arch_context *arch_context_alloc(void)
{
    /* Allocate context structure */
    struct arch_context *ctx = kmalloc(sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }

    /* Allocate kernel stack (2 pages = 8KB) */
    struct page *stack_page = alloc_pages(1);  /* 2^1 = 2 pages */
    if (!stack_page) {
        kfree(ctx);
        return NULL;
    }

    /* Initialize context */
    ctx->ra = 0;
    ctx->sp = 0;
    ctx->s0 = 0;
    ctx->s1 = 0;
    ctx->s2 = 0;
    ctx->s3 = 0;
    ctx->s4 = 0;
    ctx->s5 = 0;
    ctx->s6 = 0;
    ctx->s7 = 0;
    ctx->s8 = 0;
    ctx->s9 = 0;
    ctx->s10 = 0;
    ctx->s11 = 0;

    /* Kernel stack grows down, so base is at top of allocated region */
    paddr_t stack_base = page_to_phys(stack_page);
    ctx->kernel_stack = (uint64_t)phys_to_virt(stack_base) + (2 * CONFIG_PAGE_SIZE);
    
    pr_debug("arch_context_alloc: stack_page=%p, phys=%p, virt=%p, top=%p\n",
             stack_page, (void *)stack_base, phys_to_virt(stack_base), (void *)ctx->kernel_stack);

    ctx->sp = ctx->kernel_stack;  /* Initial SP at top of stack */

    ctx->user_stack = 0;
    ctx->satp = 0;
    ctx->kthread_fn = 0;
    ctx->kthread_arg = 0;

    return ctx;
}

/**
 * arch_context_free - Free architecture context
 */
void arch_context_free(struct arch_context *ctx)
{
    if (!ctx) {
        return;
    }

    /* Free kernel stack */
    if (ctx->kernel_stack) {
        /* kernel_stack is a virtual address pointing to top of stack */
        vaddr_t stack_top = ctx->kernel_stack;
        vaddr_t stack_bottom = stack_top - (2 * CONFIG_PAGE_SIZE);
        paddr_t stack_phys = virt_to_phys((void *)stack_bottom);
        struct page *stack_page = phys_to_page(stack_phys);
        if (stack_page) {
            free_pages(stack_page, 1);
        }
    }

    kfree(ctx);
}

/**
 * arch_context_init - Initialize context for a new process/thread
 *
 * @ctx: Context to initialize
 * @entry: Entry point (function address)
 * @stack: Stack pointer (user stack for user mode, ignored for kernel)
 * @kernel: True for kernel thread, false for user process
 */
void arch_context_init(struct arch_context *ctx,
                       vaddr_t entry,
                       vaddr_t stack,
                       bool kernel)
{
    if (kernel) {
        /* Kernel thread setup */
        ctx->ra = (uint64_t)kthread_entry;
        ctx->sp = ctx->kernel_stack;
        ctx->s0 = entry;    /* Function to call */
        ctx->s1 = stack;    /* Argument (repurposed) */
        ctx->kthread_fn = entry;
        ctx->kthread_arg = stack;
    } else {
        /* User process setup */
        ctx->ra = entry;            /* Entry point stored in ra for arch_enter_user */
        ctx->sp = ctx->kernel_stack;
        ctx->user_stack = stack;
        ctx->s0 = 0;
        ctx->s1 = 0;
    }
}

/**
 * arch_context_clone - Clone context (for fork)
 */
void arch_context_clone(struct arch_context *dst, struct arch_context *src)
{
    /* Copy register state */
    dst->ra = src->ra;
    /* Don't copy sp - it points to different stack */
    dst->s0 = src->s0;
    dst->s1 = src->s1;
    dst->s2 = src->s2;
    dst->s3 = src->s3;
    dst->s4 = src->s4;
    dst->s5 = src->s5;
    dst->s6 = src->s6;
    dst->s7 = src->s7;
    dst->s8 = src->s8;
    dst->s9 = src->s9;
    dst->s10 = src->s10;
    dst->s11 = src->s11;

    dst->user_stack = src->user_stack;
    /* satp will be set separately when page table is cloned */
}

/**
 * arch_context_get_sp - Get stack pointer from context
 */
uint64_t arch_context_get_sp(struct arch_context *ctx)
{
    return ctx->sp;
}

/**
 * arch_context_set_sp - Set stack pointer in context
 */
void arch_context_set_sp(struct arch_context *ctx, uint64_t sp)
{
    ctx->sp = sp;
}

/**
 * arch_context_get_kernel_stack - Get kernel stack base
 */
uint64_t arch_context_get_kernel_stack(struct arch_context *ctx)
{
    return ctx->kernel_stack;
}

/*
 * Trap frame layout (must match trapasm.S)
 */
struct trap_frame {
    uint64_t ra;        /* x1 */
    uint64_t sp;        /* x2 */
    uint64_t gp;        /* x3 */
    uint64_t tp;        /* x4 */
    uint64_t t0;        /* x5 */
    uint64_t t1;        /* x6 */
    uint64_t t2;        /* x7 */
    uint64_t s0;        /* x8 */
    uint64_t s1;        /* x9 */
    uint64_t a0;        /* x10 - syscall return value */
    uint64_t a1;        /* x11 */
    uint64_t a2;        /* x12 */
    uint64_t a3;        /* x13 */
    uint64_t a4;        /* x14 */
    uint64_t a5;        /* x15 */
    uint64_t a6;        /* x16 */
    uint64_t a7;        /* x17 */
    uint64_t s2;        /* x18 */
    uint64_t s3;        /* x19 */
    uint64_t s4;        /* x20 */
    uint64_t s5;        /* x21 */
    uint64_t s6;        /* x22 */
    uint64_t s7;        /* x23 */
    uint64_t s8;        /* x24 */
    uint64_t s9;        /* x25 */
    uint64_t s10;       /* x26 */
    uint64_t s11;       /* x27 */
    uint64_t t3;        /* x28 */
    uint64_t t4;        /* x29 */
    uint64_t t5;        /* x30 */
    uint64_t t6;        /* x31 */
    uint64_t sepc;
    uint64_t sstatus;
    uint64_t scause;
    uint64_t stval;
};

/* External: trap_return in trapasm.S */
extern void trap_return(void);

/**
 * arch_setup_fork_child - Set up child context for fork
 *
 * @child_ctx: Child's context (must already have kernel stack allocated)
 * @parent_tf: Parent's trap frame
 *
 * This function:
 * 1. Copies the parent's trap frame to child's kernel stack
 * 2. Sets a0 = 0 in the child's trap frame (fork returns 0 to child)
 * 3. Sets up the child's context to "return" from trap_return
 */
void arch_setup_fork_child(struct arch_context *child_ctx, struct trap_frame *parent_tf)
{
    /* Calculate position for trap frame on child's kernel stack */
    /* Stack grows down, so subtract trap frame size from top */
    struct trap_frame *child_tf = (struct trap_frame *)
        (child_ctx->kernel_stack - sizeof(struct trap_frame));

    /* Copy parent's trap frame (manual copy to avoid memcpy) */
    uint64_t *dst = (uint64_t *)child_tf;
    uint64_t *src = (uint64_t *)parent_tf;
    for (size_t i = 0; i < sizeof(struct trap_frame) / sizeof(uint64_t); i++) {
        dst[i] = src[i];
    }

    /* Child returns 0 from fork */
    child_tf->a0 = 0;

    /* Advance sepc past the ecall instruction.
     * The parent's sepc is advanced in handle_exception AFTER syscall returns,
     * but we copy the trap frame during the syscall, so we need to advance it here. */
    child_tf->sepc += 4;
    
    pr_debug("arch_setup_fork_child: parent_sepc=%p, child_sepc=%p\n", 
             (void *)parent_tf->sepc, (void *)child_tf->sepc);

    /* Set up child's context to resume at trap_return */
    child_ctx->ra = (uint64_t)trap_return;
    child_ctx->sp = (uint64_t)child_tf;

    /* Clear callee-saved registers (they will be restored from trap frame) */
    child_ctx->s0 = 0;
    child_ctx->s1 = 0;
    child_ctx->s2 = 0;
    child_ctx->s3 = 0;
    child_ctx->s4 = 0;
    child_ctx->s5 = 0;
    child_ctx->s6 = 0;
    child_ctx->s7 = 0;
    child_ctx->s8 = 0;
    child_ctx->s9 = 0;
    child_ctx->s10 = 0;
    child_ctx->s11 = 0;
}

/**
 * arch_context_set_retval - Set return value in context
 *
 * Sets a0 in the trap frame so it will be restored when returning
 * to user space. Used for fork child return value and signal returns.
 *
 * Note: The trap frame must be at sp (context was set up by arch_setup_fork_child).
 */
void arch_context_set_retval(struct arch_context *ctx, uint64_t val)
{
    struct trap_frame *tf = (struct trap_frame *)ctx->sp;
    tf->a0 = val;
}

/**
 * arch_context_set_args - Set argument registers
 *
 * Sets a0-a2 in the trap frame for signal delivery. The signal handler
 * will receive these as arguments when it starts executing.
 */
void arch_context_set_args(struct arch_context *ctx,
                           uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    struct trap_frame *tf = (struct trap_frame *)ctx->sp;
    tf->a0 = arg0;
    tf->a1 = arg1;
    tf->a2 = arg2;
}
