/**
 * kernel/arch/x86_64/apic.c - Local APIC + apic_ops
 */

#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/types.h>

#define LAPIC_ID       0x20
#define LAPIC_EOI      0xB0
#define LAPIC_SVR      0xF0
#define LAPIC_ESR      0x280
#define LAPIC_ICR_LOW  0x300
#define LAPIC_ICR_HIGH 0x310
#define LAPIC_LVT_TIMER 0x320
#define LAPIC_TIMER_INIT 0x380
#define LAPIC_TIMER_CURR 0x390
#define LAPIC_TIMER_DIV  0x3E0

#define IRQ_BASE 32

static volatile uint32_t *lapic_base;

static inline void lapic_write(uint32_t reg, uint32_t val)
{
    lapic_base[reg / 4] = val;
    lapic_base[reg / 4];
}

uint32_t lapic_read(uint32_t reg)
{
    return lapic_base[reg / 4];
}

void lapic_init(void)
{
    const struct platform_desc *plat = platform_get();
    paddr_t base = plat ? plat->early_mmio[1].base : 0xFEE00000UL;
    lapic_base = (volatile uint32_t *)ioremap(base, 4096);
    lapic_write(LAPIC_SVR, 0x100 | 0xFF);
    lapic_write(LAPIC_ESR, 0);
    lapic_write(LAPIC_TIMER_DIV, 0x3);
}

void lapic_eoi(void)
{
    if (lapic_base)
        lapic_write(LAPIC_EOI, 0);
}

void lapic_send_ipi(uint32_t apic_id, uint32_t vector)
{
    lapic_write(LAPIC_ICR_HIGH, apic_id << 24);
    lapic_write(LAPIC_ICR_LOW, vector | (0x0 << 8));
}

void lapic_timer_init(uint32_t hz)
{
    (void)hz;
    lapic_write(LAPIC_LVT_TIMER, 0x20000 | 0x20);
}

/* --- irqchip_ops --- */

extern void ioapic_init(void);
extern void ioapic_route_irq(int irq, int vector, int cpu, bool masked);

static void apic_init_ops(const struct platform_desc *plat)
{
    (void)plat;
    ioapic_init();
    lapic_init();
}

static void apic_enable(int irq)
{
    ioapic_route_irq(irq, IRQ_BASE + irq, 0, false);
}

static void apic_disable(int irq)
{
    ioapic_route_irq(irq, IRQ_BASE + irq, 0, true);
}

// WARN: x86 has no claim; IRQ number determined by IDT vector
static uint32_t apic_ack(void)
{
    return 0;
}

static void apic_eoi_ops(uint32_t irq)
{
    (void)irq;
    lapic_eoi();
}

const struct irqchip_ops apic_ops = {
    .init    = apic_init_ops,
    .enable  = apic_enable,
    .disable = apic_disable,
    .ack     = apic_ack,
    .eoi     = apic_eoi_ops,
};
