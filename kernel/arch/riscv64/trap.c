/**
 * trap.c - RISC-V 64 Trap Handling
 *
 * Implements the C portion of trap handling:
 * - Trap dispatch based on scause
 * - Exception handling
 * - Interrupt handling
 * - Syscall entry
 */

#include <kairos/types.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/syscall.h>

/* RISC-V scause values */
#define SCAUSE_INTERRUPT        (1UL << 63)

/* Exception codes (scause without interrupt bit) */
#define EXC_INST_MISALIGNED     0
#define EXC_INST_ACCESS         1
#define EXC_ILLEGAL_INST        2
#define EXC_BREAKPOINT          3
#define EXC_LOAD_MISALIGNED     4
#define EXC_LOAD_ACCESS         5
#define EXC_STORE_MISALIGNED    6
#define EXC_STORE_ACCESS        7
#define EXC_ECALL_U             8
#define EXC_ECALL_S             9
#define EXC_INST_PAGE_FAULT     12
#define EXC_LOAD_PAGE_FAULT     13
#define EXC_STORE_PAGE_FAULT    15

/* Interrupt codes */
#define IRQ_S_SOFT              1
#define IRQ_S_TIMER             5
#define IRQ_S_EXT               9

/* sstatus bits */
#define SSTATUS_SPP             (1UL << 8)
#define SSTATUS_SPIE            (1UL << 5)
#define SSTATUS_SIE             (1UL << 1)
#define SSTATUS_SUM             (1UL << 18)  /* Supervisor User Memory access */

/**
 * Trap frame structure (must match trap.S)
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
    uint64_t a0;        /* x10 */
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

/* External trap entry point */
extern void trap_entry(void);

/* Timer handler (implemented in timer.c) */
void timer_interrupt_handler(void);

/* Global tick counter */
volatile uint64_t system_ticks = 0;

/* Current trap frame (for fork) */
static struct trap_frame *current_tf = NULL;

/**
 * get_current_trapframe - Get the current trap frame
 *
 * Used by fork to copy parent's trap frame to child.
 */
struct trap_frame *get_current_trapframe(void)
{
    return current_tf;
}

/**
 * Exception names for debugging
 */
static const char *exception_names[] = {
    [EXC_INST_MISALIGNED]   = "Instruction address misaligned",
    [EXC_INST_ACCESS]       = "Instruction access fault",
    [EXC_ILLEGAL_INST]      = "Illegal instruction",
    [EXC_BREAKPOINT]        = "Breakpoint",
    [EXC_LOAD_MISALIGNED]   = "Load address misaligned",
    [EXC_LOAD_ACCESS]       = "Load access fault",
    [EXC_STORE_MISALIGNED]  = "Store/AMO address misaligned",
    [EXC_STORE_ACCESS]      = "Store/AMO access fault",
    [EXC_ECALL_U]           = "Environment call from U-mode",
    [EXC_ECALL_S]           = "Environment call from S-mode",
    [10]                    = "Reserved",
    [11]                    = "Reserved",
    [EXC_INST_PAGE_FAULT]   = "Instruction page fault",
    [EXC_LOAD_PAGE_FAULT]   = "Load page fault",
    [14]                    = "Reserved",
    [EXC_STORE_PAGE_FAULT]  = "Store/AMO page fault",
};

/**
 * handle_exception - Handle synchronous exception
 */
static void handle_exception(struct trap_frame *tf)
{
    uint64_t cause = tf->scause & ~SCAUSE_INTERRUPT;
    bool from_user = (tf->sstatus & SSTATUS_SPP) == 0;

    switch (cause) {
    case EXC_ECALL_U:
    case EXC_ECALL_S:
        /* System call */
        tf->a0 = syscall_dispatch(tf->a7,
                                  tf->a0, tf->a1, tf->a2,
                                  tf->a3, tf->a4, tf->a5);
        /* Advance PC past ecall instruction */
        tf->sepc += 4;
        break;

    case EXC_BREAKPOINT:
        pr_info("Breakpoint at %p\n", (void *)tf->sepc);
        /* Check if it's a compressed instruction (2 bytes) or regular (4 bytes) */
        /* Compressed instructions have bits [1:0] != 0b11 */
        {
            uint16_t inst = *(uint16_t *)tf->sepc;
            if ((inst & 0x3) == 0x3) {
                tf->sepc += 4;  /* 32-bit instruction */
            } else {
                tf->sepc += 2;  /* 16-bit compressed instruction */
            }
        }
        break;

    case EXC_INST_PAGE_FAULT:
    case EXC_LOAD_PAGE_FAULT:
    case EXC_STORE_PAGE_FAULT:
        /* Page fault - will be handled by MM in later phases */
        pr_err("Page fault at %p, accessing %p\n",
               (void *)tf->sepc, (void *)tf->stval);
        if (!from_user) {
            panic("Kernel page fault!");
        }
        /* TODO: Send SIGSEGV to user process */
        panic("User page fault (no signal handling yet)");
        break;

    case EXC_ILLEGAL_INST:
        pr_err("Illegal instruction at %p\n", (void *)tf->sepc);
        if (!from_user) {
            panic("Illegal instruction in kernel!");
        }
        /* TODO: Send SIGILL to user process */
        panic("User illegal instruction (no signal handling yet)");
        break;

    default:
        pr_err("Unhandled exception: %s (cause=%lu)\n",
               cause < 16 ? exception_names[cause] : "Unknown",
               cause);
        pr_err("  sepc:    %p\n", (void *)tf->sepc);
        pr_err("  stval:   %p\n", (void *)tf->stval);
        pr_err("  sstatus: 0x%lx\n", tf->sstatus);
        panic("Unhandled exception");
    }
}

/**
 * handle_interrupt - Handle asynchronous interrupt
 */
static void handle_interrupt(struct trap_frame *tf)
{
    uint64_t cause = tf->scause & ~SCAUSE_INTERRUPT;

    switch (cause) {
    case IRQ_S_TIMER:
        timer_interrupt_handler();
        break;

    case IRQ_S_SOFT:
        /* Software interrupt (IPI) - clear it */
        /* Will be used for SMP in later phases */
        pr_debug("Software interrupt\n");
        break;

    case IRQ_S_EXT:
        /* External interrupt - will be handled by device drivers */
        pr_debug("External interrupt\n");
        break;

    default:
        pr_warn("Unknown interrupt: %lu\n", cause);
        break;
    }
}

/**
 * trap_dispatch - Main trap dispatcher (called from trap.S)
 */
void trap_dispatch(struct trap_frame *tf)
{
    /*
     * Enable SUM (Supervisor User Memory access) so we can access
     * user memory in syscall handlers. This is cleared on trap entry
     * for security, so we enable it explicitly here.
     */
    __asm__ __volatile__("csrs sstatus, %0" :: "r"(SSTATUS_SUM));

    /* Save trap frame pointer for fork */
    current_tf = tf;

    if (tf->scause & SCAUSE_INTERRUPT) {
        handle_interrupt(tf);
    } else {
        handle_exception(tf);
    }

    current_tf = NULL;
}

/**
 * arch_trap_init - Initialize trap handling
 */
void arch_trap_init(void)
{
    /* Set trap vector */
    __asm__ __volatile__(
        "csrw stvec, %0"
        :: "r"(trap_entry)
    );

    /* Clear sscratch (indicates we're in kernel mode) */
    __asm__ __volatile__("csrw sscratch, zero");

    /* Enable supervisor interrupts in sie */
    uint64_t sie = (1UL << IRQ_S_SOFT) |
                   (1UL << IRQ_S_TIMER) |
                   (1UL << IRQ_S_EXT);
    __asm__ __volatile__(
        "csrw sie, %0"
        :: "r"(sie)
    );

    pr_info("Trap: initialized, stvec=%p\n", (void *)trap_entry);
}

/**
 * arch_dump_regs - Dump register state for debugging
 */
void arch_dump_regs(struct arch_context *ctx)
{
    /* TODO: Implement when arch_context is defined */
    (void)ctx;
    pr_info("Register dump not yet implemented\n");
}

/**
 * arch_backtrace - Print stack backtrace
 */
void arch_backtrace(void)
{
    uint64_t fp;
    __asm__ __volatile__("mv %0, s0" : "=r"(fp));

    pr_info("Backtrace:\n");

    for (int i = 0; i < 16 && fp != 0; i++) {
        uint64_t ra = *(uint64_t *)(fp - 8);
        uint64_t prev_fp = *(uint64_t *)(fp - 16);

        pr_info("  [%d] %p\n", i, (void *)ra);

        if (prev_fp <= fp) {
            break;  /* Stack grows down, so prev_fp should be > fp */
        }
        fp = prev_fp;
    }
}
