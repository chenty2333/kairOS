/**
 * kernel/arch/aarch64/trap.c - AArch64 trap handling
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/syscall.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>

extern void gic_init(void);
extern uint32_t gic_ack_irq(void);
extern void gic_eoi(uint32_t irq);

volatile uint64_t system_ticks = 0;

struct trap_frame *get_current_trapframe(void) {
    return arch_get_percpu()->current_tf;
}

static void handle_exception(struct trap_frame *tf) {
    uint64_t esr = tf->esr;
    uint64_t ec = (esr >> 26) & 0x3f;
    bool from_user = (tf->spsr & (1 << 4)) == 0;

    if (ec == 0x15) {
        tf->tf_a0 = syscall_dispatch(tf->tf_a7, tf->tf_a0, tf->tf_a1, tf->tf_a2,
                                     tf->tf_a3, tf->tf_a4, tf->tf_a5);
        tf->elr += 4;
        return;
    }

    if (ec == 0x20 || ec == 0x24) {
        struct process *cur = proc_current();
        if (from_user && cur && cur->mm) {
            uint32_t f = (ec == 0x24) ? PTE_WRITE : 0;
            if (mm_handle_fault(cur->mm, tf->far, f) == 0)
                return;
        }
    }

    if (from_user) {
        signal_send(proc_current()->pid, SIGSEGV);
        signal_deliver_pending();
        return;
    }

    pr_err("AArch64 exception ec=%lu elr=%p far=%p\n", ec,
           (void *)tf->elr, (void *)tf->far);
    panic("AArch64 exception");
}

static void handle_irq(void) {
    uint32_t irq = gic_ack_irq();
    gic_eoi(irq);
    if (irq == 1) {
        struct percpu_data *cpu = arch_get_percpu();
        int pending = __sync_fetch_and_and(&cpu->ipi_pending_mask, 0);
        if (pending & (1 << IPI_RESCHEDULE))
            cpu->resched_needed = true;
        if (pending & (1 << IPI_TLB_FLUSH))
            arch_mmu_flush_tlb();
        if (pending & (1 << IPI_STOP)) {
            while (1)
                arch_cpu_halt();
        }
        return;
    }
    uint64_t tick = __atomic_add_fetch(&system_ticks, 1, __ATOMIC_RELAXED);
    sched_tick();
    if (tick && (tick % CONFIG_HZ == 0))
        pr_debug("tick: %lu sec\n", tick / CONFIG_HZ);
}

void aarch64_trap_dispatch(struct trap_frame *tf) {
    struct percpu_data *cpu = arch_get_percpu();
    struct trap_frame *old = cpu->current_tf;
    cpu->current_tf = tf;

    if (tf->esr == 0) {
        handle_irq();
    } else {
        handle_exception(tf);
    }

    if ((tf->spsr & (1 << 4)) == 0) {
        signal_deliver_pending();
    }

    cpu->current_tf = old;
}

void arch_trap_init(void) {
    extern void vector_table(void);
    __asm__ __volatile__("msr vbar_el1, %0" :: "r"(&vector_table));
    gic_init();
    pr_info("Trap: initialized\n");
}

void arch_irq_init(void) {}
void arch_irq_enable_nr(int irq) { (void)irq; }
void arch_irq_disable_nr(int irq) { (void)irq; }
void arch_irq_register(int irq, void (*handler)(void *), void *arg) {
    (void)irq; (void)handler; (void)arg;
}
void arch_irq_handler(struct trap_frame *tf) { (void)tf; }

void arch_backtrace(void) {}
void arch_dump_regs(struct arch_context *ctx __attribute__((unused))) {}
