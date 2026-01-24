/**
 * kairos/arch.h - Hardware Abstraction Layer
 *
 * This file defines the interface between architecture-independent
 * kernel code and architecture-specific implementations.
 *
 * Each architecture (riscv64, aarch64, x86_64) must implement all
 * functions declared here.
 */

#ifndef _KAIROS_ARCH_H
#define _KAIROS_ARCH_H

#include <kairos/types.h>

struct process;
struct arch_context;
struct percpu_data;

/*
 * ============================================================
 *                     CPU Control
 * ============================================================
 */

/* Initialize CPU (called once per CPU) */
void arch_cpu_init(int cpu_id);

/* Get number of CPUs */
int arch_cpu_count(void);

#include <asm/arch.h>

/* Get current CPU ID */
#ifndef ARCH_HAS_CPU_ID
int arch_cpu_id(void);
#endif

/* Halt CPU until interrupt (idle loop) */
void arch_cpu_halt(void);

/* Hint: spinning in a loop */
void arch_cpu_relax(void);

/* Reboot system */
noreturn void arch_cpu_reset(void);

/* Shutdown system */
noreturn void arch_cpu_shutdown(void);

/*
 * ============================================================
 *                   Interrupt Control
 * ============================================================
 */

/* Enable interrupts */
void arch_irq_enable(void);

/* Disable interrupts */
void arch_irq_disable(void);

/* Save interrupt state and disable */
bool arch_irq_save(void);

/* Restore interrupt state */
void arch_irq_restore(bool state);

/* Check if interrupts are enabled */
bool arch_irq_enabled(void);

/*
 * ============================================================
 *                   Context Switching
 * ============================================================
 */

/* Allocate architecture context (registers, kernel stack) */
struct arch_context *arch_context_alloc(void);

/* Free architecture context */
void arch_context_free(struct arch_context *ctx);

/* Initialize context for new process */
void arch_context_init(struct arch_context *ctx,
                       vaddr_t entry,      /* Entry point */
                       vaddr_t stack,      /* User stack pointer */
                       bool kernel);       /* Kernel thread? */

/* Switch context: save old, restore new */
void arch_context_switch(struct arch_context *old, struct arch_context *new);

/* Enter user mode (does not return) */
noreturn void arch_enter_user(struct arch_context *ctx);

/* Clone context (for fork) */
void arch_context_clone(struct arch_context *dst, struct arch_context *src);

/* Set return value in context (for syscall/fork return) */
void arch_context_set_retval(struct arch_context *ctx, uint64_t val);

/* Set argument registers (for signal delivery) */
void arch_context_set_args(struct arch_context *ctx,
                           uint64_t arg0, uint64_t arg1, uint64_t arg2);

/*
 * ============================================================
 *                  Memory Management
 * ============================================================
 */

/* Initialize MMU */
void arch_mmu_init(void);

/* Create new page table, returns physical address */
paddr_t arch_mmu_create_table(void);

/* Destroy page table */
void arch_mmu_destroy_table(paddr_t table);

/* Map virtual address to physical */
int arch_mmu_map(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags);

/* Unmap virtual address */
int arch_mmu_unmap(paddr_t table, vaddr_t va);

/* Query mapping */
paddr_t arch_mmu_translate(paddr_t table, vaddr_t va);

/* Switch to address space */
void arch_mmu_switch(paddr_t table);

/* Get current page table */
paddr_t arch_mmu_current(void);

/* Flush TLB */
void arch_mmu_flush_tlb(void);

/* Flush single TLB entry */
void arch_mmu_flush_tlb_page(vaddr_t va);

/*
 * ============================================================
 *                       Timer
 * ============================================================
 */

/* Initialize timer with given frequency (Hz) */
void arch_timer_init(uint64_t hz);

/* Get current tick count */
uint64_t arch_timer_ticks(void);

/* Get timer frequency */
uint64_t arch_timer_freq(void);

/* Convert ticks to nanoseconds */
uint64_t arch_timer_ticks_to_ns(uint64_t ticks);

/* Convert nanoseconds to ticks */
uint64_t arch_timer_ns_to_ticks(uint64_t ns);

/* Set next timer interrupt (in ticks from now) */
void arch_timer_set_next(uint64_t ticks);

/* Acknowledge timer interrupt */
void arch_timer_ack(void);

/*
 * ============================================================
 *             Inter-Processor Interrupt (IPI)
 * ============================================================
 */

/* IPI types */
#define IPI_RESCHEDULE  0       /* Reschedule on target CPU */
#define IPI_CALL        1       /* Function call */
#define IPI_STOP        2       /* Stop CPU */

/* Send IPI to specific CPU */
void arch_send_ipi(int cpu, int type);

/* Send IPI to all other CPUs */
void arch_send_ipi_all(int type);



/*
 * ============================================================
 *                   Console I/O
 * ============================================================
 */

/* Early console output (before full driver init) */
void arch_early_putchar(char c);

/* Early console input (blocking) */
int arch_early_getchar(void);

/*
 * ============================================================
 *                   Trap Handling
 * ============================================================
 */

/* Trap types */
enum trap_type {
    TRAP_SYSCALL,       /* System call */
    TRAP_PAGE_FAULT,    /* Page fault */
    TRAP_ILLEGAL_INST,  /* Illegal instruction */
    TRAP_BREAKPOINT,    /* Breakpoint */
    TRAP_TIMER,         /* Timer interrupt */
    TRAP_IRQ,           /* External interrupt */
    TRAP_UNKNOWN,       /* Unknown */
};

/* Trap information passed to generic handler */
struct trap_info {
    enum trap_type type;
    uint64_t fault_addr;        /* For page faults */
    uint64_t error_code;        /* Architecture-specific */
    bool is_write;              /* For page faults */
    bool is_user;               /* Trapped from user mode? */
};

/* Initialize trap handling */
void arch_trap_init(void);

/* Generic trap handler (implemented in core/trap.c) */
void trap_handler(struct trap_info *info);

/*
 * ============================================================
 *                   Fork Support
 * ============================================================
 */

/* Trap frame structure (opaque, defined per-architecture) */
struct trap_frame;

/* Get the current trap frame (for fork) */
struct trap_frame *get_current_trapframe(void);

/* Copy trap frame to a child's kernel stack and set up context for fork return */
void arch_setup_fork_child(struct arch_context *child_ctx, struct trap_frame *parent_tf);

/*
 * ============================================================
 *                   Debug Support
 * ============================================================
 */

/* Trigger debugger breakpoint */
void arch_breakpoint(void);

/* Print registers (for debugging) */
void arch_dump_regs(struct arch_context *ctx);

/* Stack trace */
void arch_backtrace(void);

#endif /* _KAIROS_ARCH_H */
