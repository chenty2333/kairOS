/**
 * kernel/arch/x86_64/apic.c - Local APIC + apic_ops
 */

#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/boot.h>
#include <kairos/config.h>
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
extern void ioapic_route_irq(int irq, int vector, int cpu, bool masked,
                             bool level);

static bool ioapic_inited;
static uint32_t apic_irq_type[IRQCHIP_MAX_IRQS];
static uint32_t apic_irq_affinity[IRQCHIP_MAX_IRQS];

static uint32_t apic_sanitize_affinity_mask(uint32_t cpu_mask)
{
#if CONFIG_MAX_CPUS >= 32
    uint32_t valid_mask = UINT32_MAX;
#else
    uint32_t valid_mask = (1U << CONFIG_MAX_CPUS) - 1U;
#endif
    return cpu_mask & valid_mask;
}

static int apic_pick_cpu(uint32_t cpu_mask)
{
    cpu_mask = apic_sanitize_affinity_mask(cpu_mask);
    if (!cpu_mask)
        return 0;
    return (int)__builtin_ctz(cpu_mask);
}

static int apic_dest_id(int cpu)
{
    if (cpu < 0)
        return 0;
    const struct boot_info *bi = boot_info_get();
    if (bi && cpu < (int)bi->cpu_count)
        return (int)((uint32_t)bi->cpus[cpu].hw_id & 0xffU);
    return cpu & 0xff;
}

static void apic_init_ops(const struct platform_desc *plat)
{
    (void)plat;
    const struct boot_info *bi = boot_info_get();
    int bsp = bi ? (int)bi->bsp_cpu_id : 0;
    if (!ioapic_inited && arch_cpu_id() == bsp) {
        ioapic_init();
        ioapic_inited = true;
    }
    lapic_init();
}

static void apic_enable(int irq)
{
    if (irq < 0 || irq >= IRQCHIP_MAX_IRQS)
        return;
    bool level = (apic_irq_type[irq] & IRQ_FLAG_TRIGGER_LEVEL) != 0;
    int cpu = apic_pick_cpu(apic_irq_affinity[irq]);
    ioapic_route_irq(irq, IRQ_BASE + irq, apic_dest_id(cpu), false, level);
}

static void apic_disable(int irq)
{
    if (irq < 0 || irq >= IRQCHIP_MAX_IRQS)
        return;
    bool level = (apic_irq_type[irq] & IRQ_FLAG_TRIGGER_LEVEL) != 0;
    int cpu = apic_pick_cpu(apic_irq_affinity[irq]);
    ioapic_route_irq(irq, IRQ_BASE + irq, apic_dest_id(cpu), true, level);
}

static int apic_set_type(int irq, uint32_t type)
{
    if (irq < 0 || irq >= IRQCHIP_MAX_IRQS)
        return -EINVAL;
    type &= IRQ_FLAG_TRIGGER_MASK;
    if (!type)
        return 0;
    if (type == IRQ_FLAG_TRIGGER_MASK)
        return -EINVAL;
    apic_irq_type[irq] = type;
    return 0;
}

static int apic_set_affinity(int irq, uint32_t cpu_mask)
{
    if (irq < 0 || irq >= IRQCHIP_MAX_IRQS)
        return -EINVAL;
    cpu_mask = apic_sanitize_affinity_mask(cpu_mask);
    if (!cpu_mask)
        return -EINVAL;
    apic_irq_affinity[irq] = cpu_mask;
    bool level = (apic_irq_type[irq] & IRQ_FLAG_TRIGGER_LEVEL) != 0;
    int cpu = apic_pick_cpu(cpu_mask);
    ioapic_route_irq(irq, IRQ_BASE + irq, apic_dest_id(cpu), false, level);
    return 0;
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
    .set_type = apic_set_type,
    .set_affinity = apic_set_affinity,
    .ack     = apic_ack,
    .eoi     = apic_eoi_ops,
};
