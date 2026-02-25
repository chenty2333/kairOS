/**
 * kernel/arch/aarch64/trap.c - AArch64 trap handling
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/syscall.h>
#include <kairos/trap_core.h>
#include <kairos/tick.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>

/* WARN: ARM architecture fixed INTIDs, not board-configurable */
#define TIMER_PPI_IRQ 30
#define IPI_SGI_IRQ   1

#define AARCH64_SPSR_MODE_MASK 0xf
#define AARCH64_SPSR_EL0T      0x0

static inline bool aarch64_from_user(const struct trap_frame *tf) {
    return tf && ((tf->spsr & AARCH64_SPSR_MODE_MASK) == AARCH64_SPSR_EL0T);
}

struct trap_frame *get_current_trapframe(void) {
    struct trap_frame *tf = arch_get_percpu()->current_tf;
    if (tf)
        return tf;
    struct process *p = proc_current();
    return p ? (struct trap_frame *)p->active_tf : NULL;
}

static void handle_exception(struct trap_frame *tf) {
    uint64_t esr = tf->esr;
    uint64_t ec = (esr >> 26) & 0x3f;
    bool from_user = aarch64_from_user(tf);
    bool user_fault = false;

    /* SVC (syscall) */
    if (ec == 0x15) {
        uint64_t nr = tf->tf_a7;
        int64_t ret = syscall_dispatch(nr, tf->tf_a0, tf->tf_a1, tf->tf_a2,
                                       tf->tf_a3, tf->tf_a4, tf->tf_a5);
        tf->tf_a0 = ret;
        /*
         * AArch64 SVC sets ELR_EL1 to the next instruction automatically.
         * Do not advance tf->elr here, or user mode will skip an instruction.
         */
        return;
    }

    /* Data/Instruction abort */
    if (ec == 0x20 || ec == 0x21 || ec == 0x24 || ec == 0x25) {
        struct process *cur = proc_current();
        if (cur && cur->mm && tf->far >= USER_SPACE_START &&
            tf->far < USER_SPACE_END) {
            uint32_t f = 0;
            if (ec == 0x24 || ec == 0x25) {
                /* Data abort: WnR (bit 6) distinguishes write vs read */
                f = (esr & (1U << 6)) ? PTE_WRITE : 0;
            } else {
                f = PTE_EXEC;
            }
            if (mm_handle_fault(cur->mm, tf->far, f) == 0)
                return;
            user_fault = true;
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

    if (from_user || user_fault) {
        struct process *curr = proc_current();
        if (curr) {
            signal_send(curr->pid, SIGSEGV);
            signal_deliver_pending();
            return;
        }
        panic("AArch64 user fault without current process");
    }

    uint64_t tpidr_el1 = 0, spsel = 0;
    __asm__ __volatile__("mrs %0, tpidr_el1" : "=r"(tpidr_el1));
    __asm__ __volatile__("mrs %0, spsel" : "=r"(spsel));
    pr_err("AArch64 exception ec=%lu esr=%p elr=%p far=%p\n", ec,
           (void *)tf->esr, (void *)tf->elr, (void *)tf->far);
    pr_err("  cpu=%d tpidr_el1=%016lx spsel=%lu\n",
           arch_cpu_id(), tpidr_el1, spsel & 1);
    arch_dump_regs(NULL);
    arch_backtrace();
    panic("AArch64 exception");
}

static void handle_irq(const struct trap_core_event *ev) {
    const struct platform_desc *plat = platform_get();
    if (!plat || !plat->irqchip)
        return;

    uint32_t irq = plat->irqchip->ack();

    if (irq >= 1020)
        return;

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
    } else if (irq == TIMER_PPI_IRQ) {
        arch_timer_ack();
        tick_policy_on_timer_irq(ev);
    } else if (irq < IRQCHIP_MAX_IRQS) {
        platform_irq_dispatch_nr(irq);
    }

    plat->irqchip->eoi(irq);
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
    return aarch64_from_user(ev->tf);
}

static const struct trap_core_ops aarch64_trap_ops = {
    .handle_event = aarch64_handle_event,
    .should_deliver_signals = aarch64_should_deliver_signals,
};

void aarch64_trap_dispatch(struct trap_frame *tf) {
    struct trap_core_event ev = {
        .type = aarch64_event_type(tf),
        .tf = tf,
        .from_user = aarch64_from_user(tf),
        .code = tf->esr,
        .fault_addr = tf->far,
    };
    trap_core_dispatch(&ev, &aarch64_trap_ops);
}

void arch_trap_init(void) {
    extern void vector_table(void);
    __asm__ __volatile__("msr vbar_el1, %0" :: "r"(&vector_table));
    arch_irq_init();
    if (arch_cpu_id() == 0)
        pr_info("Trap: initialized\n");
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
