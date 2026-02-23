/**
 * kernel/platform/core.c - Platform registration, selection, and IRQ dispatch
 */

#include <kairos/platform_core.h>
#include <kairos/arch.h>
#include <kairos/fdt.h>
#include <kairos/printk.h>
#include <kairos/string.h>

extern const struct platform_desc * const __platform_table_start[];
extern const struct platform_desc * const __platform_table_end[];

static const struct platform_desc *current_platform;

const struct platform_desc *platform_get(void)
{
    return current_platform;
}

void platform_select(const char *arch)
{
    const struct platform_desc * const *p;
    const struct platform_desc *fallback = NULL;
    const char *root_compat = fdt_root_compatible();

    for (p = __platform_table_start; p < __platform_table_end; p++) {
        if (!*p)
            continue;
        if (strcmp((*p)->arch, arch) != 0)
            continue;

        if (root_compat && (*p)->compatible[0] &&
            strcmp((*p)->compatible, root_compat) == 0) {
            current_platform = *p;
            goto done;
        }
        if (!fallback)
            fallback = *p;
    }
    current_platform = fallback;

done:
    if (current_platform)
        pr_info("platform: selected '%s'\n", current_platform->name);
    else
        pr_warn("platform: no match for arch=%s\n", arch);
}

/* --- Unified IRQ handler table --- */

struct irq_entry {
    void (*handler)(void *);
    void *arg;
};

static struct irq_entry irq_table[IRQCHIP_MAX_IRQS];

void platform_irq_register(int irq, void (*handler)(void *), void *arg)
{
    if (irq >= 0 && irq < IRQCHIP_MAX_IRQS) {
        irq_table[irq].handler = handler;
        irq_table[irq].arg = arg;
    }
}

void platform_irq_dispatch_nr(uint32_t irq)
{
    if (irq < IRQCHIP_MAX_IRQS && irq_table[irq].handler)
        irq_table[irq].handler(irq_table[irq].arg);
}

/* --- arch_irq_* unified dispatch --- */

void arch_irq_init(void)
{
    const struct platform_desc *plat = platform_get();
    if (plat && plat->irqchip && plat->irqchip->init)
        plat->irqchip->init(plat);
}

void arch_irq_enable_nr(int irq)
{
    const struct platform_desc *plat = platform_get();
    if (plat && plat->irqchip && plat->irqchip->enable)
        plat->irqchip->enable(irq);
}

void arch_irq_disable_nr(int irq)
{
    const struct platform_desc *plat = platform_get();
    if (plat && plat->irqchip && plat->irqchip->disable)
        plat->irqchip->disable(irq);
}

void arch_irq_register(int irq, void (*handler)(void *), void *arg)
{
    platform_irq_register(irq, handler, arg);
    arch_irq_enable_nr(irq);
}
