/**
 * kernel/arch/x86_64/trap.c - x86_64 trap handling
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/syscall.h>
#include <kairos/trap_core.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>

#define IRQ_BASE 32
#define SYSCALL_VEC 0x80

struct idt_entry {
    uint16_t off_low;
    uint16_t sel;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t off_mid;
    uint32_t off_high;
    uint32_t zero;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static struct idt_entry idt[256];

extern void isr0(void);
extern void isr1(void);
extern void isr2(void);
extern void isr3(void);
extern void isr4(void);
extern void isr5(void);
extern void isr6(void);
extern void isr7(void);
extern void isr8(void);
extern void isr9(void);
extern void isr10(void);
extern void isr11(void);
extern void isr12(void);
extern void isr13(void);
extern void isr14(void);
extern void isr15(void);
extern void isr16(void);
extern void isr17(void);
extern void isr18(void);
extern void isr19(void);
extern void isr20(void);
extern void isr21(void);
extern void isr22(void);
extern void isr23(void);
extern void isr24(void);
extern void isr25(void);
extern void isr26(void);
extern void isr27(void);
extern void isr28(void);
extern void isr29(void);
extern void isr30(void);
extern void isr31(void);
extern void isr32(void);
extern void isr33(void);
extern void isr34(void);
extern void isr35(void);
extern void isr36(void);
extern void isr37(void);
extern void isr38(void);
extern void isr39(void);
extern void isr40(void);
extern void isr41(void);
extern void isr42(void);
extern void isr43(void);
extern void isr44(void);
extern void isr45(void);
extern void isr46(void);
extern void isr47(void);
extern void isr128(void);
extern void isr240(void);

static void handle_irq(struct trap_frame *tf, const struct trap_core_event *ev);

static void idt_set_gate_dpl(int n, void (*handler)(void), uint8_t dpl) {
    uint64_t addr = (uint64_t)handler;
    uint16_t cs;
    __asm__ __volatile__("mov %%cs, %0" : "=r"(cs));
    idt[n].off_low = addr & 0xffff;
    idt[n].sel = cs;
    idt[n].ist = 0;
    idt[n].type_attr = (uint8_t)(0x8E | ((dpl & 0x3) << 5));
    idt[n].off_mid = (addr >> 16) & 0xffff;
    idt[n].off_high = (addr >> 32) & 0xffffffff;
    idt[n].zero = 0;
}

static inline void idt_set_gate(int n, void (*handler)(void)) {
    idt_set_gate_dpl(n, handler, 0);
}

static void idt_load(void) {
    struct idt_ptr idtr = {
        .limit = sizeof(idt) - 1,
        .base = (uint64_t)&idt,
    };
    __asm__ __volatile__("lidt %0" :: "m"(idtr));
}

struct trap_frame *get_current_trapframe(void) {
    struct trap_frame *tf = arch_get_percpu()->current_tf;
    if (tf)
        return tf;
    struct process *p = proc_current();
    return p ? (struct trap_frame *)p->active_tf : NULL;
}

void arch_irq_handler(struct trap_frame *tf) {
    handle_irq(tf, NULL);
}

static void handle_exception(struct trap_frame *tf) {
    uint64_t trapno = tf->trapno;
    bool from_user = (tf->cs & 3) != 0;
    uint64_t cr2 = 0;
    struct process *cur = proc_current();

    if (trapno == 14) {
        __asm__ __volatile__("mov %%cr2, %0" : "=r"(cr2));
        bool user_addr = cr2 <= USER_SPACE_END;
        if (cur && cur->mm && user_addr) {
            uint32_t f = 0;
            if (tf->err & (1U << 1))
                f |= PTE_WRITE;
            if (tf->err & (1U << 4))
                f |= PTE_EXEC;
            if (mm_handle_fault(cur->mm, cr2, f) == 0)
                return;
        }
        if (!from_user) {
            unsigned long fixup = search_exception_table(tf->rip);
            if (fixup) {
                tf->rip = fixup;
                return;
            }
        }
    }

    if (from_user) {
        if (cur) {
            signal_send(cur->pid, SIGSEGV);
            signal_deliver_pending();
            return;
        }
        panic("x86_64 user exception without current process");
    }

    if (trapno == 13) {
        void *ra = NULL;
        if (tf->rsp)
            ra = *(void **)(tf->rsp + sizeof(void *));
        pr_err("x86_64 #GP rip=%p err=%p rsp=%p ra=%p rdi=%p rsi=%p rcx=%p rdx=%p rax=%p\n",
               (void *)tf->rip, (void *)tf->err, (void *)tf->rsp, ra,
               (void *)tf->rdi, (void *)tf->rsi, (void *)tf->rcx,
               (void *)tf->rdx, (void *)tf->rax);
    } else if (trapno == 14) {
        pr_err("x86_64 #PF rip=%p err=%p cr2=%p\n",
               (void *)tf->rip, (void *)tf->err, (void *)cr2);
    } else {
        pr_err("x86_64 exception %lu rip=%p err=%p\n", trapno,
               (void *)tf->rip, (void *)tf->err);
    }
    panic("x86_64 exception");
}

static void handle_syscall(struct trap_frame *tf) {
    tf->rax = syscall_dispatch(tf->rax, tf->rdi, tf->rsi, tf->rdx, tf->r10,
                               tf->r8, tf->r9);
}

static void handle_irq(struct trap_frame *tf, const struct trap_core_event *ev) {
    const struct platform_desc *plat = platform_get();
    int vec = (int)tf->trapno;
    int irq = vec - IRQ_BASE;
    if (irq >= 0 && irq < IRQCHIP_MAX_IRQS)
        platform_irq_dispatch((uint32_t)irq, ev);
    if (plat && plat->irqchip)
        plat->irqchip->eoi((irq >= 0) ? (uint32_t)irq : 0);
}

static enum trap_core_event_type x86_event_type(const struct trap_frame *tf) {
    if (tf->trapno == SYSCALL_VEC)
        return TRAP_CORE_EVENT_SYSCALL;
    if (tf->trapno == 0xF0)
        return TRAP_CORE_EVENT_IPI;
    if (tf->trapno < IRQ_BASE) {
        if (tf->trapno == 14)
            return TRAP_CORE_EVENT_PAGE_FAULT;
        if (tf->trapno == 3)
            return TRAP_CORE_EVENT_BREAKPOINT;
        if (tf->trapno == 6)
            return TRAP_CORE_EVENT_ILLEGAL_INST;
        return TRAP_CORE_EVENT_ARCH_OTHER;
    }
    if ((int)tf->trapno - IRQ_BASE == 0)
        return TRAP_CORE_EVENT_TIMER;
    return TRAP_CORE_EVENT_EXT_IRQ;
}

static int x86_handle_event(const struct trap_core_event *ev) {
    struct trap_frame *tf = ev->tf;
    if (tf->trapno == SYSCALL_VEC) {
        handle_syscall(tf);
    } else if (tf->trapno == 0xF0) {
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
    } else if (tf->trapno < IRQ_BASE) {
        handle_exception(tf);
    } else {
        handle_irq(tf, ev);
    }
    return 0;
}

static bool x86_should_deliver_signals(const struct trap_core_event *ev) {
    return (ev->tf->cs & 3) != 0;
}

static const struct trap_core_ops x86_trap_ops = {
    .handle_event = x86_handle_event,
    .should_deliver_signals = x86_should_deliver_signals,
};

void x86_trap_dispatch(struct trap_frame *tf) {
    struct trap_core_event ev = {
        .type = x86_event_type(tf),
        .tf = tf,
        .from_user = (tf->cs & 3) != 0,
        .code = tf->trapno,
        .fault_addr = 0,
    };
    trap_core_dispatch(&ev, &x86_trap_ops);
}

void arch_trap_init(void) {
    idt_set_gate(0, isr0);
    idt_set_gate(1, isr1);
    idt_set_gate(2, isr2);
    idt_set_gate(3, isr3);
    idt_set_gate(4, isr4);
    idt_set_gate(5, isr5);
    idt_set_gate(6, isr6);
    idt_set_gate(7, isr7);
    idt_set_gate(8, isr8);
    idt_set_gate(9, isr9);
    idt_set_gate(10, isr10);
    idt_set_gate(11, isr11);
    idt_set_gate(12, isr12);
    idt_set_gate(13, isr13);
    idt_set_gate(14, isr14);
    idt_set_gate(15, isr15);
    idt_set_gate(16, isr16);
    idt_set_gate(17, isr17);
    idt_set_gate(18, isr18);
    idt_set_gate(19, isr19);
    idt_set_gate(20, isr20);
    idt_set_gate(21, isr21);
    idt_set_gate(22, isr22);
    idt_set_gate(23, isr23);
    idt_set_gate(24, isr24);
    idt_set_gate(25, isr25);
    idt_set_gate(26, isr26);
    idt_set_gate(27, isr27);
    idt_set_gate(28, isr28);
    idt_set_gate(29, isr29);
    idt_set_gate(30, isr30);
    idt_set_gate(31, isr31);

    idt_set_gate(32, isr32);
    idt_set_gate(33, isr33);
    idt_set_gate(34, isr34);
    idt_set_gate(35, isr35);
    idt_set_gate(36, isr36);
    idt_set_gate(37, isr37);
    idt_set_gate(38, isr38);
    idt_set_gate(39, isr39);
    idt_set_gate(40, isr40);
    idt_set_gate(41, isr41);
    idt_set_gate(42, isr42);
    idt_set_gate(43, isr43);
    idt_set_gate(44, isr44);
    idt_set_gate(45, isr45);
    idt_set_gate(46, isr46);
    idt_set_gate(47, isr47);
    idt_set_gate_dpl(SYSCALL_VEC, isr128, 3);
    idt_set_gate(0xF0, isr240);

    idt_load();
    arch_irq_init();
    pr_info("Trap: initialized\n");
}

void arch_backtrace(void) {}
void arch_dump_regs(struct arch_context *ctx __attribute__((unused))) {}
