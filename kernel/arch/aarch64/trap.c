/**
 * kernel/arch/aarch64/trap.c - AArch64 trap handling
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/syscall.h>
#include <kairos/trap_core.h>
#include <kairos/tick.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>

extern void gic_init(void);
extern uint32_t gic_ack_irq(void);
extern void gic_eoi(uint32_t irq);
extern void gic_enable_irq(uint32_t irq);
extern void gic_disable_irq(uint32_t irq);

#define TIMER_PPI_IRQ 30
#define IPI_SGI_IRQ   1
#define MAX_IRQ       1024

/* --- IRQ handler table --- */

struct irq_entry {
    void (*handler)(void *);
    void *arg;
};

static struct irq_entry irq_handlers[MAX_IRQ];

struct trap_frame *get_current_trapframe(void) {
    return arch_get_percpu()->current_tf;
}

static void handle_exception(struct trap_frame *tf) {
    uint64_t esr = tf->esr;
    uint64_t ec = (esr >> 26) & 0x3f;
    bool from_user = (tf->spsr & (1 << 4)) == 0;

    /* SVC (syscall) */
    if (ec == 0x15) {
        tf->tf_a0 = syscall_dispatch(tf->tf_a7, tf->tf_a0, tf->tf_a1, tf->tf_a2,
                                     tf->tf_a3, tf->tf_a4, tf->tf_a5);
        tf->elr += 4;
        return;
    }

    /* Data/Instruction abort */
    if (ec == 0x20 || ec == 0x21 || ec == 0x24 || ec == 0x25) {
        struct process *cur = proc_current();
        if (from_user && cur && cur->mm) {
            uint32_t f = (ec == 0x24 || ec == 0x25) ? PTE_WRITE : 0;
            if (mm_handle_fault(cur->mm, tf->far, f) == 0)
                return;
        }

        /* Check exception table for kernel faults */
        if (!from_user) {
            unsigned long fixup = search_exception_table(tf->elr);
            if (fixup) {
                tf->elr = fixup;
                return;
            }
        }
    }

    if (from_user) {
        signal_send(proc_current()->pid, SIGSEGV);
        signal_deliver_pending();
        return;
    }

    pr_err("AArch64 exception ec=%lu esr=%p elr=%p far=%p\n", ec,
           (void *)tf->esr, (void *)tf->elr, (void *)tf->far);
    arch_dump_regs(NULL);
    arch_backtrace();
    panic("AArch64 exception");
}

static void handle_irq(const struct trap_core_event *ev) {
    uint32_t irq = gic_ack_irq();

    if (irq >= 1020) {
        /* Spurious interrupt */
        return;
    }

    gic_eoi(irq);

    if (irq == IPI_SGI_IRQ) {
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

    if (irq == TIMER_PPI_IRQ) {
        arch_timer_ack();
        tick_policy_on_timer_irq(ev);
        return;
    }

    /* Dispatch registered handlers */
    if (irq < MAX_IRQ && irq_handlers[irq].handler) {
        irq_handlers[irq].handler(irq_handlers[irq].arg);
        return;
    }

    pr_warn("IRQ: unhandled irq %u\n", irq);
}
/* PLACEHOLDER_TRAP_REST */

static enum trap_core_event_type aarch64_event_type(const struct trap_frame *tf) {
    if (tf->esr == 0)
        return TRAP_CORE_EVENT_EXT_IRQ;

    uint64_t ec = (tf->esr >> 26) & 0x3f;
    if (ec == 0x15)
        return TRAP_CORE_EVENT_SYSCALL;
    if (ec == 0x20 || ec == 0x21 || ec == 0x24 || ec == 0x25)
        return TRAP_CORE_EVENT_PAGE_FAULT;
    return TRAP_CORE_EVENT_ARCH_OTHER;
}

static int aarch64_handle_event(const struct trap_core_event *ev) {
    struct trap_frame *tf = ev->tf;
    if (tf->esr == 0) {
        handle_irq(ev);
    } else {
        handle_exception(tf);
    }
    return 0;
}

static bool aarch64_should_deliver_signals(const struct trap_core_event *ev) {
    return (ev->tf->spsr & (1 << 4)) == 0;
}

static const struct trap_core_ops aarch64_trap_ops = {
    .handle_event = aarch64_handle_event,
    .should_deliver_signals = aarch64_should_deliver_signals,
};

void aarch64_trap_dispatch(struct trap_frame *tf) {
    struct trap_core_event ev = {
        .type = aarch64_event_type(tf),
        .tf = tf,
        .from_user = (tf->spsr & (1 << 4)) == 0,
        .code = tf->esr,
        .fault_addr = tf->far,
    };
    trap_core_dispatch(&ev, &aarch64_trap_ops);
}

void arch_trap_init(void) {
    extern void vector_table(void);
    __asm__ __volatile__("msr vbar_el1, %0" :: "r"(&vector_table));
    gic_init();
    pr_info("Trap: initialized\n");
}

void arch_irq_init(void) {}

void arch_irq_enable_nr(int irq) {
    gic_enable_irq((uint32_t)irq);
}

void arch_irq_disable_nr(int irq) {
    gic_disable_irq((uint32_t)irq);
}

void arch_irq_register(int irq, void (*handler)(void *), void *arg) {
    if (irq >= 0 && irq < MAX_IRQ) {
        irq_handlers[irq].handler = handler;
        irq_handlers[irq].arg = arg;
    }
}

void arch_irq_handler(struct trap_frame *tf) { (void)tf; }

void arch_dump_regs(struct arch_context *ctx __attribute__((unused))) {
    struct trap_frame *tf = get_current_trapframe();
    if (!tf)
        return;
    pr_err("  x0=%016lx  x1=%016lx  x2=%016lx  x3=%016lx\n",
           tf->regs[0], tf->regs[1], tf->regs[2], tf->regs[3]);
    pr_err("  x4=%016lx  x5=%016lx  x6=%016lx  x7=%016lx\n",
           tf->regs[4], tf->regs[5], tf->regs[6], tf->regs[7]);
    pr_err("  x8=%016lx  x9=%016lx x10=%016lx x11=%016lx\n",
           tf->regs[8], tf->regs[9], tf->regs[10], tf->regs[11]);
    pr_err(" x12=%016lx x13=%016lx x14=%016lx x15=%016lx\n",
           tf->regs[12], tf->regs[13], tf->regs[14], tf->regs[15]);
    pr_err(" x16=%016lx x17=%016lx x18=%016lx x19=%016lx\n",
           tf->regs[16], tf->regs[17], tf->regs[18], tf->regs[19]);
    pr_err(" x20=%016lx x21=%016lx x22=%016lx x23=%016lx\n",
           tf->regs[20], tf->regs[21], tf->regs[22], tf->regs[23]);
    pr_err(" x24=%016lx x25=%016lx x26=%016lx x27=%016lx\n",
           tf->regs[24], tf->regs[25], tf->regs[26], tf->regs[27]);
    pr_err(" x28=%016lx x29=%016lx x30=%016lx\n",
           tf->regs[28], tf->regs[29], tf->regs[30]);
    pr_err("  SP=%016lx ELR=%016lx SPSR=%016lx\n",
           tf->sp, tf->elr, tf->spsr);
    pr_err(" ESR=%016lx FAR=%016lx\n", tf->esr, tf->far);
}

void arch_backtrace(void) {
    uint64_t fp;
    __asm__ __volatile__("mov %0, x29" : "=r"(fp));

    pr_err("Backtrace:\n");
    for (int i = 0; i < 16 && fp; i++) {
        uint64_t *frame = (uint64_t *)fp;
        uint64_t lr = frame[1];
        if (!lr)
            break;
        pr_err("  [%d] %016lx\n", i, lr);
        fp = frame[0];
        if (!fp)
            break;
    }
}
