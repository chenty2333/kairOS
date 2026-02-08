/**
 * kernel/arch/riscv64/trap.c - RISC-V 64 Trap Handling
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
#include <kairos/types.h>
#include <kairos/uaccess.h>

#define EXC_BREAKPOINT 3
#define EXC_ECALL_U 8
#define EXC_ECALL_S 9
#define EXC_INST_PAGE_FAULT 12
#define EXC_LOAD_PAGE_FAULT 13
#define EXC_STORE_PAGE_FAULT 15
#define EXC_ILLEGAL_INST 2

#define IRQ_S_SOFT 1
#define IRQ_S_TIMER 5
#define IRQ_S_EXT 9

extern void trap_entry(void);
void timer_interrupt_handler(struct trap_frame *tf);

struct trap_frame *get_current_trapframe(void) {
    return arch_get_percpu()->current_tf;
}

static const char *exc_names[] = {
    [0] = "Misaligned instruction", [1] = "Instruction access fault",
    [2] = "Illegal instruction",    [3] = "Breakpoint",
    [8] = "Ecall from U-mode",      [9] = "Ecall from S-mode",
    [12] = "Inst page fault",       [13] = "Load page fault",
    [15] = "Store page fault"};

static void dump_trap_frame(struct trap_frame *tf, bool from_user) {
    struct process *p = proc_current();
    pr_err("Trap dump: cpu=%d mode=%s pid=%d name=%s\n", arch_cpu_id(),
           from_user ? "user" : "kernel", p ? p->pid : -1,
           p ? p->name : "-");
    pr_err("  sepc=%p stval=%p scause=%p sstatus=%p\n",
           (void *)tf->sepc, (void *)tf->stval, (void *)tf->scause,
           (void *)tf->sstatus);
    pr_err("  ra=%p sp=%p a0=%p a1=%p a2=%p a3=%p a4=%p a5=%p a6=%p a7=%p\n",
           (void *)tf->tf_ra, (void *)tf->tf_sp, (void *)tf->tf_a0,
           (void *)tf->tf_a1, (void *)tf->tf_a2, (void *)tf->tf_a3,
           (void *)tf->tf_a4, (void *)tf->tf_a5, (void *)tf->tf_a6,
           (void *)tf->tf_a7);
}

static void handle_exception(struct trap_frame *tf) {
    uint64_t cause = tf->scause & ~SCAUSE_INTERRUPT;
    bool from_user = !(tf->sstatus & SSTATUS_SPP);

    if (cause == EXC_ECALL_U || cause == EXC_ECALL_S) {
        uint64_t nr = tf->tf_a7;
        int64_t ret = syscall_dispatch(nr, tf->tf_a0, tf->tf_a1, tf->tf_a2,
                                       tf->tf_a3, tf->tf_a4, tf->tf_a5);
        tf->tf_a0 = ret;
        if (ret >= 0) {
            struct process *cur = proc_current();
            if (!cur || cur->syscall_abi == SYSCALL_ABI_LINUX) {
                if (nr == LINUX_NR_execve || nr == LINUX_NR_execveat)
                    return;
            } else {
                if (nr == SYS_exec)
                    return;
            }
        }
        tf->sepc += 4;
        return;
    }

    if (cause == EXC_BREAKPOINT) {
        uint16_t inst;
        if (copy_from_user(&inst, (void *)tf->sepc, 2))
            panic("bp read fail");
        tf->sepc += ((inst & 0x3) == 0x3) ? 4 : 2;
        return;
    }

    if (cause >= EXC_INST_PAGE_FAULT && cause <= EXC_STORE_PAGE_FAULT) {
        struct process *cur = proc_current();
        bool user_addr = tf->stval <= USER_SPACE_END;
        if (cur && cur->mm && user_addr) {
            uint32_t f = (cause == EXC_STORE_PAGE_FAULT)  ? PTE_WRITE
                         : (cause == EXC_INST_PAGE_FAULT) ? PTE_EXEC
                                                          : 0;
            if (mm_handle_fault(cur->mm, tf->stval, f) == 0)
                return;
        }
        if (!from_user) {
            unsigned long fix = search_exception_table(tf->sepc);
            if (fix) {
                tf->sepc = fix;
                return;
            }
        }
        if (from_user) {
            signal_send(cur->pid, SIGSEGV);
            signal_deliver_pending();
            return;
        }
    }

    if (cause == EXC_ILLEGAL_INST && from_user) {
        signal_send(proc_current()->pid, SIGILL);
        signal_deliver_pending(); /* Deliver immediately, should not return */
        return;
    }

    dump_trap_frame(tf, from_user);
    pr_err("Exception: %s (cause=%lu, epc=%p, val=%p)\n",
           cause < 16 ? exc_names[cause] : "Unknown", cause, (void *)tf->sepc,
           (void *)tf->stval);
    panic(from_user ? "User exception" : "Kernel exception");
}

static void handle_interrupt(struct trap_frame *tf) {
    uint64_t cause = tf->scause & ~SCAUSE_INTERRUPT;
    if (cause == IRQ_S_TIMER) {
        timer_interrupt_handler(tf);
    } else if (cause == IRQ_S_EXT) {
        arch_irq_handler(tf);
    } else if (cause == IRQ_S_SOFT) {
        __asm__ __volatile__("csrc sip, %0" ::"r"(1UL << 1));
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
    }
}

static enum trap_core_event_type riscv_event_type(uint64_t scause) {
    uint64_t cause = scause & ~SCAUSE_INTERRUPT;

    if (scause & SCAUSE_INTERRUPT) {
        if (cause == IRQ_S_TIMER)
            return TRAP_CORE_EVENT_TIMER;
        if (cause == IRQ_S_EXT)
            return TRAP_CORE_EVENT_EXT_IRQ;
        if (cause == IRQ_S_SOFT)
            return TRAP_CORE_EVENT_IPI;
        return TRAP_CORE_EVENT_ARCH_OTHER;
    }

    if (cause == EXC_ECALL_U || cause == EXC_ECALL_S)
        return TRAP_CORE_EVENT_SYSCALL;
    if (cause >= EXC_INST_PAGE_FAULT && cause <= EXC_STORE_PAGE_FAULT)
        return TRAP_CORE_EVENT_PAGE_FAULT;
    if (cause == EXC_BREAKPOINT)
        return TRAP_CORE_EVENT_BREAKPOINT;
    if (cause == EXC_ILLEGAL_INST)
        return TRAP_CORE_EVENT_ILLEGAL_INST;
    return TRAP_CORE_EVENT_ARCH_OTHER;
}

static int riscv_handle_event(const struct trap_core_event *ev) {
    if (ev->code & SCAUSE_INTERRUPT)
        handle_interrupt(ev->tf);
    else
        handle_exception(ev->tf);
    return 0;
}

static bool riscv_should_deliver_signals(const struct trap_core_event *ev) {
    return !(ev->tf->sstatus & SSTATUS_SPP);
}

static const struct trap_core_ops riscv_trap_ops = {
    .handle_event = riscv_handle_event,
    .should_deliver_signals = riscv_should_deliver_signals,
};

void trap_dispatch(struct trap_frame *tf) {
    struct trap_core_event ev = {
        .type = riscv_event_type(tf->scause),
        .tf = tf,
        .from_user = !(tf->sstatus & SSTATUS_SPP),
        .code = tf->scause,
        .fault_addr = tf->stval,
    };

    trap_core_dispatch(&ev, &riscv_trap_ops);
}

void arch_trap_init(void) {
    __asm__ __volatile__(
        "csrw stvec, %0\ncsrw sscratch, zero" ::"r"(trap_entry));
    
    arch_irq_init();

    uint64_t sie =
        (1UL << IRQ_S_SOFT) | (1UL << IRQ_S_TIMER) | (1UL << IRQ_S_EXT);
    __asm__ __volatile__("csrw sie, %0" ::"r"(sie));
    pr_info("Trap: initialized\n");
}

void arch_backtrace(void) {
    uint64_t fp;
    __asm__ __volatile__("mv %0, s0" : "=r"(fp));
    pr_info("Backtrace:\n");
    for (int i = 0; i < 16 && fp; i++) {
        uint64_t ra = *(uint64_t *)(fp - 8), prev = *(uint64_t *)(fp - 16);
        pr_info("  [%d] %p\n", i, (void *)ra);
        if (prev <= fp)
            break;
        fp = prev;
    }
}

void arch_dump_regs(struct arch_context *ctx __attribute__((unused))) {}
