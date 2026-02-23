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

/* Forward declarations for Phase 2-3 ops */
struct irqchip_ops;
struct timer_ops;
struct earlycon_ops;

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

#endif
