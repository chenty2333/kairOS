/**
 * kernel/arch/riscv64/plic.c - RISC-V PLIC irqchip_ops implementation
 */

#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/types.h>

#define PLIC_PRIORITY(base)       ((base) + 0x0)
#define PLIC_ENABLE(base, hart)   ((base) + 0x2000 + (hart) * 0x80)
#define PLIC_THRESHOLD(base, hart) ((base) + 0x200000 + (hart) * 0x1000)
#define PLIC_CLAIM(base, hart)     ((base) + 0x200004 + (hart) * 0x1000)

static paddr_t plic_base;

static inline uint32_t plic_read(uintptr_t addr)
{
    return *(volatile uint32_t *)addr;
}

static inline void plic_write(uintptr_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static void plic_init(const struct platform_desc *plat)
{
    plic_base = plat->early_mmio[0].base;
    int hart = arch_cpu_id();
    plic_write(PLIC_THRESHOLD(plic_base, hart), 0);
    pr_info("PLIC: initialized for hart %d\n", hart);
}

static void plic_enable(int irq)
{
    if (irq <= 0 || irq >= IRQCHIP_MAX_IRQS)
        return;
    int hart = arch_cpu_id();
    plic_write(PLIC_PRIORITY(plic_base) + irq * 4, 1);
    uintptr_t enable_addr = PLIC_ENABLE(plic_base, hart) + (irq / 32) * 4;
    uint32_t val = plic_read(enable_addr);
    val |= (1 << (irq % 32));
    plic_write(enable_addr, val);
}

static void plic_disable(int irq)
{
    if (irq <= 0 || irq >= IRQCHIP_MAX_IRQS)
        return;
    int hart = arch_cpu_id();
    uintptr_t enable_addr = PLIC_ENABLE(plic_base, hart) + (irq / 32) * 4;
    uint32_t val = plic_read(enable_addr);
    val &= ~(1 << (irq % 32));
    plic_write(enable_addr, val);
}

static int plic_set_type(int irq, uint32_t type)
{
    (void)irq;
    if (type & IRQ_FLAG_TRIGGER_EDGE)
        return -EOPNOTSUPP;
    return 0;
}

static int plic_set_affinity(int irq, uint32_t cpu_mask)
{
    (void)irq;
    if (!cpu_mask)
        return -EINVAL;
    return -EOPNOTSUPP;
}

static uint32_t plic_ack(void)
{
    int hart = arch_cpu_id();
    return plic_read(PLIC_CLAIM(plic_base, hart));
}

static void plic_eoi(uint32_t irq)
{
    int hart = arch_cpu_id();
    plic_write(PLIC_CLAIM(plic_base, hart), irq);
}

const struct irqchip_ops plic_ops = {
    .init    = plic_init,
    .enable  = plic_enable,
    .disable = plic_disable,
    .set_type = plic_set_type,
    .set_affinity = plic_set_affinity,
    .ack     = plic_ack,
    .eoi     = plic_eoi,
};
