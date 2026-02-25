/**
 * kernel/include/kairos/arch.h - Hardware Abstraction Layer
 */

#ifndef _KAIROS_ARCH_H
#define _KAIROS_ARCH_H

#include <kairos/types.h>

struct process;
struct arch_context;
struct percpu_data;
struct trap_info;
struct trap_frame;

/* CPU Control */
void arch_cpu_init(int cpu_id);
int arch_cpu_count(void);
#include <asm/arch.h>
#ifndef ARCH_HAS_CPU_ID
int arch_cpu_id(void);
#endif
#ifndef ARCH_HAS_CPU_ID_STABLE
static inline int arch_cpu_id_stable(void) {
    return arch_cpu_id();
}
#endif
void arch_cpu_halt(void);
void arch_cpu_relax(void);
noreturn void arch_cpu_reset(void);
noreturn void arch_cpu_shutdown(void);

/* Interrupts */
void arch_irq_enable(void);
void arch_irq_disable(void);
bool arch_irq_save(void);
void arch_irq_restore(bool state);
bool arch_irq_enabled(void);

/* Context Management */
struct arch_context *arch_context_alloc(void);
void arch_context_free(struct arch_context *ctx);
void arch_context_init(struct arch_context *ctx, vaddr_t entry, vaddr_t stack,
                       bool kernel);
void arch_context_switch(struct arch_context *old, struct arch_context *new);
noreturn void arch_enter_user(struct arch_context *ctx);
void arch_context_clone(struct arch_context *dst, struct arch_context *src);
void arch_context_set_retval(struct arch_context *ctx, uint64_t val);
void arch_context_set_args(struct arch_context *ctx, uint64_t a0, uint64_t a1,
                           uint64_t a2);
void arch_context_set_cpu(struct arch_context *ctx, int cpu);
void arch_set_tls(struct arch_context *ctx, uint64_t tls);
#ifdef ARCH_HAS_TSS
void arch_tss_set_rsp0(uint64_t rsp0);
#else
static inline void arch_tss_set_rsp0(uint64_t rsp0) { (void)rsp0; }
#endif
#if defined(ARCH_HAS_TSS) || defined(ARCH_HAS_CONTEXT_KERNEL_STACK)
uint64_t arch_context_kernel_stack(const struct arch_context *ctx);
#else
static inline uint64_t arch_context_kernel_stack(const struct arch_context *ctx) {
    (void)ctx;
    return 0;
}
#endif
#ifdef ARCH_HAS_CONTEXT_SET_USER_SP
void arch_context_set_user_sp(struct arch_context *ctx, vaddr_t sp);
#else
static inline void arch_context_set_user_sp(struct arch_context *ctx,
                                            vaddr_t sp) {
    (void)ctx;
    (void)sp;
}
#endif

/* Memory Management (MMU) */
struct boot_info;
void arch_mmu_init(const struct boot_info *bi);
paddr_t arch_mmu_create_table(void);
void arch_mmu_destroy_table(paddr_t table);
int arch_mmu_map(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags);
int arch_mmu_map_merge(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags);
int arch_mmu_unmap(paddr_t table, vaddr_t va);
paddr_t arch_mmu_translate(paddr_t table, vaddr_t va);
/*
 * Generic PTE encoding shared with core MM:
 * - low 10 bits: HAL PTE_* flags
 * - upper bits:  (phys_addr >> PAGE_SHIFT) << 10
 */
uint64_t arch_mmu_get_pte(paddr_t table, vaddr_t va);
int arch_mmu_set_pte(paddr_t table, vaddr_t va, uint64_t pte);
void arch_mmu_switch(paddr_t table);
paddr_t arch_mmu_current(void);
void arch_mmu_flush_tlb(void);
void arch_mmu_flush_tlb_page(vaddr_t va);
void arch_mmu_flush_tlb_all(void);
paddr_t arch_mmu_get_kernel_pgdir(void);

/* Timer & IPI */
void arch_timer_init(uint64_t hz);
uint64_t arch_timer_ticks(void);
uint64_t arch_timer_freq(void);
uint64_t arch_timer_ticks_to_ns(uint64_t ticks);
uint64_t arch_timer_ns_to_ticks(uint64_t ns);
uint64_t arch_timer_get_ticks(void);
void arch_timer_set_next(uint64_t ticks);
void arch_timer_ack(void);

#define IPI_RESCHEDULE 0
#define IPI_CALL 1
#define IPI_STOP 2
#define IPI_TLB_FLUSH 3
void arch_send_ipi(int cpu, int type);
void arch_send_ipi_all(int type);

/* I/O & Debug */
void arch_early_putchar(char c);
#ifdef ARCH_HAS_EARLY_GETCHAR
int arch_early_getchar(void);
int arch_early_getchar_nb(void);
#ifdef ARCH_HAS_CONSOLE_INPUT_IRQ
void arch_console_input_init(void);
#else
static inline void arch_console_input_init(void) {}
#endif
#else
static inline int arch_early_getchar(void) { return -1; }
static inline int arch_early_getchar_nb(void) { return -1; }
static inline void arch_console_input_init(void) {}
#endif
void arch_breakpoint(void);
void arch_dump_regs(struct arch_context *ctx);
void arch_backtrace(void);

/* Trap Handling */
enum trap_type {
    TRAP_SYSCALL,
    TRAP_PAGE_FAULT,
    TRAP_ILLEGAL_INST,
    TRAP_BREAKPOINT,
    TRAP_TIMER,
    TRAP_IRQ,
    TRAP_UNKNOWN
};

/* Interrupt Controller Interface */
void arch_irq_init(void);
void arch_irq_enable_nr(int irq);
void arch_irq_disable_nr(int irq);
void arch_irq_handler(struct trap_frame *tf);
void arch_irq_register(int irq, void (*handler)(void *), void *arg);

struct trap_info {
    enum trap_type type;
    uint64_t fault_addr, error_code;
    bool is_write, is_user;
};
void arch_trap_init(void);
struct trap_frame *get_current_trapframe(void);
void arch_setup_fork_child(struct arch_context *child_ctx,
                           struct trap_frame *parent_tf);

#endif
