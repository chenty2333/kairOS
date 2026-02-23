/**
 * kernel/include/kairos/platform_core.h - Platform abstraction layer
 */

#ifndef _KAIROS_PLATFORM_CORE_H
#define _KAIROS_PLATFORM_CORE_H

#include <kairos/types.h>

#define PLATFORM_MAX_EARLY_MMIO 8
#define PLATFORM_COMPAT_MAX     64
#define PLATFORM_NAME_MAX       32

struct early_mmio_region {
    paddr_t base;
    size_t  size;
};

/* Forward declarations for Phase 3 ops */
struct platform_desc;
struct timer_ops;
struct earlycon_ops;

#define IRQCHIP_MAX_IRQS 1024

struct irqchip_ops {
    void (*init)(const struct platform_desc *plat);
    void (*enable)(int irq);
    void (*disable)(int irq);
    uint32_t (*ack)(void);
    void (*eoi)(uint32_t irq);
    void (*send_sgi)(uint32_t cpu, uint32_t intid);
};

struct platform_desc {
    const char name[PLATFORM_NAME_MAX];
    const char compatible[PLATFORM_COMPAT_MAX];
    const char arch[16];

    struct early_mmio_region early_mmio[PLATFORM_MAX_EARLY_MMIO];
    int num_early_mmio;

    const struct irqchip_ops  *irqchip;
    const struct timer_ops    *timer;
    const struct earlycon_ops *earlycon;
};

#define PLATFORM_REGISTER(desc) \
    static const struct platform_desc * const \
    __platform_entry_##desc \
    __attribute__((used, section(".platform_table"))) = &(desc)

void platform_select(const char *arch);
const struct platform_desc *platform_get(void);

/* Unified IRQ handler table */
void platform_irq_register(int irq, void (*handler)(void *), void *arg);
void platform_irq_dispatch_nr(uint32_t irq);

#endif
