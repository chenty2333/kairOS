/**
 * kernel/arch/riscv64/plic.c - RISC-V PLIC irqchip_ops implementation
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>

#define PLIC_PRIORITY(base)       ((base) + 0x0)
#define PLIC_ENABLE(base, hart)   ((base) + 0x2000 + (hart) * 0x80)
#define PLIC_THRESHOLD(base, hart) ((base) + 0x200000 + (hart) * 0x1000)
#define PLIC_CLAIM(base, hart)     ((base) + 0x200004 + (hart) * 0x1000)

static paddr_t plic_base;
static spinlock_t plic_lock;
/* 0: uninitialized, 1: initializing, 2: ready */
static volatile int plic_state_ready;
static uint32_t plic_irq_affinity[IRQCHIP_MAX_IRQS];
static bool plic_irq_enabled[IRQCHIP_MAX_IRQS];

static inline uint32_t plic_read(uintptr_t addr)
{
    return *(volatile uint32_t *)addr;
}

static inline void plic_write(uintptr_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static uint32_t plic_valid_cpu_mask(void)
{
    int cpu_count = arch_cpu_count();
    if (cpu_count <= 0)
        cpu_count = 1;
    if (cpu_count > CONFIG_MAX_CPUS)
        cpu_count = CONFIG_MAX_CPUS;
#if CONFIG_MAX_CPUS >= 32
    return (cpu_count >= 32) ? UINT32_MAX : ((1U << cpu_count) - 1U);
#else
    return (1U << cpu_count) - 1U;
#endif
}

static void plic_route_irq_locked(int irq)
{
    uint32_t mask = plic_irq_affinity[irq] & plic_valid_cpu_mask();
    if (!mask)
        mask = 1U;
    plic_irq_affinity[irq] = mask;

    int cpu_count = arch_cpu_count();
    if (cpu_count <= 0)
        cpu_count = 1;
    if (cpu_count > CONFIG_MAX_CPUS)
        cpu_count = CONFIG_MAX_CPUS;

    uint32_t bit = (1U << (irq % 32));
    for (int hart = 0; hart < cpu_count; hart++) {
        uintptr_t hart_enable =
            PLIC_ENABLE(plic_base, hart) + ((uintptr_t)(irq / 32) * 4);
        uint32_t val = plic_read(hart_enable);
        bool enabled = plic_irq_enabled[irq];
        if (hart < 32)
            enabled = enabled && ((mask & (1U << hart)) != 0);
        else
            enabled = false;
        if (enabled)
            val |= bit;
        else
            val &= ~bit;
        plic_write(hart_enable, val);
    }
}

static void plic_init(const struct platform_desc *plat)
{
    plic_base = plat->early_mmio[0].base;

    if (__sync_bool_compare_and_swap(&plic_state_ready, 0, 1)) {
        spin_init(&plic_lock);
        for (int i = 0; i < IRQCHIP_MAX_IRQS; i++) {
            plic_irq_affinity[i] = 1U;
            plic_irq_enabled[i] = false;
        }
        __sync_synchronize();
        plic_state_ready = 2;
    }
    while (plic_state_ready != 2)
        arch_cpu_relax();

    int hart = arch_cpu_id();
    plic_write(PLIC_THRESHOLD(plic_base, hart), 0);
    pr_info("PLIC: initialized for hart %d\n", hart);
}

static void plic_enable(int irq)
{
    if (irq <= 0 || irq >= IRQCHIP_MAX_IRQS)
        return;

    plic_write(PLIC_PRIORITY(plic_base) + irq * 4, 1);

    bool irq_state;
    spin_lock_irqsave(&plic_lock, &irq_state);
    plic_irq_enabled[irq] = true;
    plic_route_irq_locked(irq);
    spin_unlock_irqrestore(&plic_lock, irq_state);
}

static void plic_disable(int irq)
{
    if (irq <= 0 || irq >= IRQCHIP_MAX_IRQS)
        return;

    bool irq_state;
    spin_lock_irqsave(&plic_lock, &irq_state);
    plic_irq_enabled[irq] = false;
    plic_route_irq_locked(irq);
    spin_unlock_irqrestore(&plic_lock, irq_state);

    plic_write(PLIC_PRIORITY(plic_base) + irq * 4, 0);
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
    if (irq <= 0 || irq >= IRQCHIP_MAX_IRQS)
        return -EINVAL;

    cpu_mask &= plic_valid_cpu_mask();
    if (!cpu_mask)
        return -EINVAL;

    bool irq_state;
    spin_lock_irqsave(&plic_lock, &irq_state);
    plic_irq_affinity[irq] = cpu_mask;
    plic_route_irq_locked(irq);
    spin_unlock_irqrestore(&plic_lock, irq_state);
    return 0;
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
