/**
 * kernel/include/kairos/platform_core.h - Platform abstraction layer
 */

#ifndef _KAIROS_PLATFORM_CORE_H
#define _KAIROS_PLATFORM_CORE_H

#include <kairos/types.h>

#define PLATFORM_MAX_EARLY_MMIO 8
#define PLATFORM_COMPAT_MAX     64
#define PLATFORM_NAME_MAX       32
#define IRQ_DOMAIN_MAX          8
#define IRQ_DOMAIN_AUTO_VIRQ    UINT32_MAX

struct early_mmio_region {
    paddr_t base;
    size_t  size;
};

/* Forward declarations for Phase 3 ops */
struct platform_desc;
struct timer_ops;
struct earlycon_ops;
struct trap_core_event;

#define IRQCHIP_MAX_IRQS 1024

#define IRQ_FLAG_TRIGGER_NONE   0U
#define IRQ_FLAG_TRIGGER_LEVEL  (1U << 0)
#define IRQ_FLAG_TRIGGER_EDGE   (1U << 1)
#define IRQ_FLAG_TRIGGER_MASK                                           \
    (IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_TRIGGER_EDGE)
#define IRQ_FLAG_SHARED        (1U << 2)
#define IRQ_FLAG_PER_CPU       (1U << 3)
#define IRQ_FLAG_TIMER         (1U << 4)
#define IRQ_FLAG_NO_AUTO_ENABLE (1U << 5)
#define IRQ_FLAG_DEFERRED      (1U << 6)
#define IRQ_FLAG_NO_CHIP       (1U << 7)

typedef void (*irq_handler_fn)(void *arg);
typedef void (*irq_handler_event_fn)(void *arg,
                                     const struct trap_core_event *ev);

struct irqchip_ops {
    void (*init)(const struct platform_desc *plat);
    void (*enable)(int irq);
    void (*disable)(int irq);
    int (*set_type)(int irq, uint32_t type);
    int (*set_affinity)(int irq, uint32_t cpu_mask);
    uint32_t (*ack)(void);
    void (*eoi)(uint32_t irq);
    void (*send_sgi)(uint32_t cpu, uint32_t intid);
};

struct timer_ops {
    int (*irq)(void);
};

struct platform_desc {
    const char name[PLATFORM_NAME_MAX];
    const char compatible[PLATFORM_COMPAT_MAX];
    const char arch[16];

    struct early_mmio_region early_mmio[PLATFORM_MAX_EARLY_MMIO];
    int num_early_mmio;
    uint32_t irqchip_root_irqs;

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
int platform_irq_register_ex(int irq, irq_handler_event_fn handler, void *arg,
                             uint32_t flags);
void platform_irq_register(int irq, irq_handler_fn handler, void *arg);
void platform_irq_set_type(int irq, uint32_t flags);
void platform_irq_set_affinity(int irq, uint32_t cpu_mask);
int platform_irq_domain_add_linear(const char *name,
                                   const struct irqchip_ops *chip,
                                   uint32_t hwirq_base, uint32_t virq_base,
                                   uint32_t nr_irqs);
int platform_irq_domain_add_linear_fwnode(const char *name,
                                          const struct irqchip_ops *chip,
                                          uint32_t fwnode,
                                          uint32_t hwirq_base,
                                          uint32_t virq_base,
                                          uint32_t nr_irqs);
int platform_irq_domain_alloc_linear(const char *name,
                                     const struct irqchip_ops *chip,
                                     uint32_t hwirq_base, uint32_t nr_irqs,
                                     uint32_t *virq_base_out);
int platform_irq_domain_setup_cascade(const char *name,
                                      const struct irqchip_ops *chip,
                                      uint32_t hwirq_base,
                                      uint32_t nr_irqs, int parent_irq,
                                      irq_handler_event_fn handler, void *arg,
                                      uint32_t flags,
                                      uint32_t *virq_base_out);
int platform_irq_domain_alloc_linear_fwnode(const char *name,
                                            const struct irqchip_ops *chip,
                                            uint32_t fwnode,
                                            uint32_t hwirq_base,
                                            uint32_t nr_irqs,
                                            uint32_t *virq_base_out);
int platform_irq_domain_setup_cascade_fwnode(const char *name,
                                             const struct irqchip_ops *chip,
                                             uint32_t fwnode,
                                             uint32_t hwirq_base,
                                             uint32_t nr_irqs,
                                             int parent_irq,
                                             irq_handler_event_fn handler,
                                             void *arg, uint32_t flags,
                                             uint32_t *virq_base_out);
int platform_irq_domain_bind_fwnode(const struct irqchip_ops *chip,
                                    uint32_t hwirq_base, uint32_t nr_irqs,
                                    uint32_t fwnode);
int platform_irq_domain_set_cascade(uint32_t child_virq, int parent_irq,
                                    irq_handler_event_fn handler, void *arg,
                                    uint32_t flags);
int platform_irq_domain_set_cascade_fwnode(uint32_t fwnode, int parent_irq,
                                           irq_handler_event_fn handler,
                                           void *arg, uint32_t flags);
int platform_irq_domain_map(const struct irqchip_ops *chip, uint32_t hwirq);
int platform_irq_domain_map_fwnode(uint32_t fwnode, uint32_t hwirq);
void platform_irq_dispatch_hwirq(const struct irqchip_ops *chip,
                                 uint32_t hwirq,
                                 const struct trap_core_event *ev);
void platform_irq_dispatch_fwnode_hwirq(uint32_t fwnode, uint32_t hwirq,
                                        const struct trap_core_event *ev);
void platform_irq_dispatch(uint32_t irq, const struct trap_core_event *ev);
void platform_irq_dispatch_nr(uint32_t irq);
int platform_timer_irq(void);
void platform_timer_dispatch(const struct trap_core_event *ev);

#endif
