/**
 * kernel/arch/riscv64/plic.c - RISC-V Platform-Level Interrupt Controller
 */

#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/types.h>

/* PLIC Base Address (Standard for QEMU virt machine) */
#define PLIC_BASE           0x0c000000UL
#define PLIC_PRIORITY       (PLIC_BASE + 0x0)
#define PLIC_PENDING        (PLIC_BASE + 0x1000)
#define PLIC_ENABLE(hart)   (PLIC_BASE + 0x2000 + (hart) * 0x80)
#define PLIC_THRESHOLD(hart) (PLIC_BASE + 0x200000 + (hart) * 0x1000)
#define PLIC_CLAIM(hart)     (PLIC_BASE + 0x200004 + (hart) * 0x1000)

#define MAX_IRQS 1024

struct irq_handler {
    void (*handler)(void *);
    void *arg;
};

static struct irq_handler irq_handlers[MAX_IRQS];

/* MMIO helper */
static inline uint32_t plic_read(uintptr_t addr) {
    return *(volatile uint32_t *)addr;
}

static inline void plic_write(uintptr_t addr, uint32_t val) {
    *(volatile uint32_t *)addr = val;
}

void arch_irq_init(void) {
    int hart = arch_cpu_id();

    /* Set threshold to 0 (accept all interrupts with priority > 0) */
    plic_write(PLIC_THRESHOLD(hart), 0);
    
    pr_info("PLIC: initialized for hart %d\n", hart);
}

void arch_irq_enable_nr(int irq) {
    if (irq <= 0 || irq >= MAX_IRQS) return;
    
    int hart = arch_cpu_id();
    
    /* Set priority to 1 (lowest active) */
    plic_write(PLIC_PRIORITY + irq * 4, 1);
    
    /* Enable the IRQ for this hart */
    uintptr_t enable_addr = PLIC_ENABLE(hart) + (irq / 32) * 4;
    uint32_t val = plic_read(enable_addr);
    val |= (1 << (irq % 32));
    plic_write(enable_addr, val);
}

void arch_irq_disable_nr(int irq) {
    if (irq <= 0 || irq >= MAX_IRQS) return;
    
    int hart = arch_cpu_id();
    uintptr_t enable_addr = PLIC_ENABLE(hart) + (irq / 32) * 4;
    uint32_t val = plic_read(enable_addr);
    val &= ~(1 << (irq % 32));
    plic_write(enable_addr, val);
}

void arch_irq_register(int irq, void (*handler)(void *), void *arg) {
    if (irq <= 0 || irq >= MAX_IRQS) return;
    irq_handlers[irq].handler = handler;
    irq_handlers[irq].arg = arg;
    arch_irq_enable_nr(irq);
}

/**
 * arch_irq_handler - Main dispatcher for external interrupts
 */
void arch_irq_handler(struct trap_frame *tf) {
    (void)tf;
    int hart = arch_cpu_id();
    uint32_t irq = plic_read(PLIC_CLAIM(hart));

    if (irq > 0 && irq < MAX_IRQS) {
        if (irq_handlers[irq].handler) {
            irq_handlers[irq].handler(irq_handlers[irq].arg);
        } else {
            pr_warn("PLIC: unhandled interrupt %u\n", irq);
        }
        
        /* Signal completion */
        plic_write(PLIC_CLAIM(hart), irq);
    }
}
