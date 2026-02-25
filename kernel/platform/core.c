/**
 * kernel/platform/core.c - Platform registration, selection, and IRQ dispatch
 */

#include <kairos/platform_core.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/fdt.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/trap_core.h>
#include <kairos/wait.h>

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

/* --- Unified IRQ descriptor table --- */

#define IRQ_ACTION_SNAPSHOT_MAX 32
#define IRQ_DESC_ACTION_FLAG_MASK                                         \
    (IRQ_FLAG_TRIGGER_MASK | IRQ_FLAG_SHARED | IRQ_FLAG_PER_CPU |         \
     IRQ_FLAG_TIMER | IRQ_FLAG_NO_AUTO_ENABLE | IRQ_FLAG_DEFERRED |       \
     IRQ_FLAG_NO_CHIP)

struct irq_action {
    struct list_head node;
    irq_handler_fn handler;
    irq_handler_event_fn handler_ev;
    void *arg;
    int irq;
    uint32_t flags;
    uint32_t refs;
    struct list_head deferred_node;
    struct trap_core_event deferred_ev;
    uint32_t deferred_pending;
    bool removed;
    bool deferred_queued;
    bool deferred_has_ev;
};

struct irq_desc {
    struct list_head actions;
    uint32_t flags;
    uint32_t affinity_mask;
    int enable_count;
    uint32_t hwirq;
    const struct irqchip_ops *chip;
    uint64_t dispatch_count;
    bool overflow_warned;
    spinlock_t lock;
};

static struct irq_desc irq_table[IRQCHIP_MAX_IRQS];
static bool irq_table_ready;

struct irq_domain {
    struct list_head node;
    struct list_head children;
    struct list_head sibling;
    struct irq_domain *parent;
    const char *name;
    const struct irqchip_ops *chip;
    uint32_t fwnode;
    uint32_t hwirq_base;
    uint32_t virq_base;
    uint32_t nr_irqs;
    int parent_irq;
    int cascade_enable_count;
    irq_handler_event_fn cascade_handler;
    void *cascade_arg;
};

static struct list_head irq_domains;
static size_t irq_domain_count;
static spinlock_t irq_domain_lock;
static bool irq_domain_warned;

static void irq_domain_cascade_action(void *arg,
                                      const struct trap_core_event *ev);

struct irq_deferred_ctx {
    struct list_head pending_actions;
    struct wait_queue wait;
    spinlock_t lock;
    struct process *worker;
    bool worker_started;
    bool worker_warned;
};

static struct irq_deferred_ctx irq_deferred;

static int irq_deferred_worker(void *arg __unused);
static struct irq_desc *platform_irq_desc_get(int irq);
static int platform_irq_register_action(int irq, irq_handler_fn handler,
                                        irq_handler_event_fn handler_ev,
                                        void *arg, uint32_t flags);
static int platform_irq_unregister_action(int irq, irq_handler_fn handler,
                                          irq_handler_event_fn handler_ev,
                                          void *arg);

static void irq_deferred_init(void)
{
    INIT_LIST_HEAD(&irq_deferred.pending_actions);
    wait_queue_init(&irq_deferred.wait);
    spin_init(&irq_deferred.lock);
    irq_deferred.worker = NULL;
    irq_deferred.worker_started = false;
    irq_deferred.worker_warned = false;
}

static bool irq_deferred_start_worker(void)
{
    if (irq_deferred.worker_started)
        return true;

    struct process *worker = kthread_create(irq_deferred_worker, NULL, "irqd");
    if (!worker) {
        if (!irq_deferred.worker_warned) {
            irq_deferred.worker_warned = true;
            pr_warn("irq: failed to create deferred worker, falling back to hardirq handlers\n");
        }
        return false;
    }
    sched_enqueue(worker);

    bool irq_state;
    spin_lock_irqsave(&irq_deferred.lock, &irq_state);
    irq_deferred.worker = worker;
    irq_deferred.worker_started = true;
    spin_unlock_irqrestore(&irq_deferred.lock, irq_state);
    return true;
}

static void irq_action_get_locked(struct irq_action *action)
{
    if (!action)
        return;
    if (action->refs != UINT32_MAX)
        action->refs++;
}

static void irq_action_put_locked(struct irq_action *action)
{
    if (!action || action->refs == 0)
        return;
    action->refs--;
}

static void irq_action_put(struct irq_action *action)
{
    if (!action)
        return;

    struct irq_desc *desc = platform_irq_desc_get(action->irq);
    if (!desc)
        return;

    bool irq_state;
    spin_lock_irqsave(&desc->lock, &irq_state);
    irq_action_put_locked(action);
    spin_unlock_irqrestore(&desc->lock, irq_state);
}

static bool irq_deferred_queue_action(struct irq_desc *desc,
                                      struct irq_action *action,
                                      const struct trap_core_event *ev)
{
    if (!desc || !action || !(action->flags & IRQ_FLAG_DEFERRED))
        return false;

    bool desc_irq_state;
    spin_lock_irqsave(&desc->lock, &desc_irq_state);
    if (action->removed) {
        spin_unlock_irqrestore(&desc->lock, desc_irq_state);
        return false;
    }

    bool irq_state;
    bool wake = false;
    spin_lock_irqsave(&irq_deferred.lock, &irq_state);
    if (!irq_deferred.worker_started) {
        spin_unlock_irqrestore(&irq_deferred.lock, irq_state);
        spin_unlock_irqrestore(&desc->lock, desc_irq_state);
        return false;
    }
    if (action->deferred_pending != UINT32_MAX)
        action->deferred_pending++;
    if (ev) {
        action->deferred_ev = *ev;
        action->deferred_has_ev = true;
    }
    if (!action->deferred_queued) {
        action->deferred_queued = true;
        irq_action_get_locked(action);
        list_add_tail(&action->deferred_node, &irq_deferred.pending_actions);
        wake = true;
    }
    spin_unlock_irqrestore(&irq_deferred.lock, irq_state);
    spin_unlock_irqrestore(&desc->lock, desc_irq_state);

    if (wake)
        wait_queue_wakeup_one(&irq_deferred.wait);
    return true;
}

static int irq_deferred_worker(void *arg __unused)
{
    for (;;) {
        struct irq_action *action = NULL;
        struct trap_core_event ev = { 0 };
        bool has_ev = false;
        uint32_t pending = 0;

        bool irq_state;
        spin_lock_irqsave(&irq_deferred.lock, &irq_state);
        if (!list_empty(&irq_deferred.pending_actions)) {
            action = list_first_entry(&irq_deferred.pending_actions,
                                      struct irq_action, deferred_node);
            list_del(&action->deferred_node);
            INIT_LIST_HEAD(&action->deferred_node);
            action->deferred_queued = false;
            pending = action->deferred_pending;
            action->deferred_pending = 0;
            has_ev = action->deferred_has_ev;
            if (has_ev)
                ev = action->deferred_ev;
            action->deferred_has_ev = false;
        }
        spin_unlock_irqrestore(&irq_deferred.lock, irq_state);

        if (!action) {
            proc_sleep_on(&irq_deferred.wait, &irq_deferred.wait, true);
            continue;
        }

        bool run_action = true;
        struct irq_desc *desc = platform_irq_desc_get(action->irq);
        if (desc) {
            spin_lock_irqsave(&desc->lock, &irq_state);
            run_action = !action->removed;
            spin_unlock_irqrestore(&desc->lock, irq_state);
        }

        if (pending == 0)
            pending = 1;
        while (run_action && pending--) {
            if (action->handler_ev) {
                action->handler_ev(action->arg, has_ev ? &ev : NULL);
            } else if (action->handler) {
                action->handler(action->arg);
            }
        }
        irq_action_put(action);
    }
}

static void platform_irq_table_init(void)
{
    if (irq_table_ready)
        return;

    bool irq_state = arch_irq_save();
    if (!irq_table_ready) {
        const struct platform_desc *plat = platform_get();
        const struct irqchip_ops *chip = plat ? plat->irqchip : NULL;

        for (int i = 0; i < IRQCHIP_MAX_IRQS; i++) {
            INIT_LIST_HEAD(&irq_table[i].actions);
            irq_table[i].flags = 0;
            irq_table[i].affinity_mask = 1U;
            irq_table[i].enable_count = 0;
            irq_table[i].hwirq = (uint32_t)i;
            irq_table[i].chip = chip;
            irq_table[i].dispatch_count = 0;
            irq_table[i].overflow_warned = false;
            spin_init(&irq_table[i].lock);
        }
        spin_init(&irq_domain_lock);
        INIT_LIST_HEAD(&irq_domains);
        irq_domain_count = 0;
        irq_domain_warned = false;
        irq_deferred_init();
        irq_table_ready = true;
    }
    arch_irq_restore(irq_state);
}

static struct irq_desc *platform_irq_desc_get(int irq)
{
    if (irq < 0 || irq >= IRQCHIP_MAX_IRQS)
        return NULL;
    platform_irq_table_init();
    return &irq_table[irq];
}

static uint32_t irq_sanitize_affinity_mask(uint32_t cpu_mask)
{
#if CONFIG_MAX_CPUS >= 32
    uint32_t valid_mask = UINT32_MAX;
#else
    uint32_t valid_mask = (1U << CONFIG_MAX_CPUS) - 1U;
#endif
    cpu_mask &= valid_mask;
    if (!cpu_mask)
        cpu_mask = 1U;
    return cpu_mask;
}

static bool irq_ranges_overlap(uint32_t base_a, uint32_t count_a,
                               uint32_t base_b, uint32_t count_b)
{
    uint64_t end_a = (uint64_t)base_a + count_a;
    uint64_t end_b = (uint64_t)base_b + count_b;
    return ((uint64_t)base_a < end_b) && ((uint64_t)base_b < end_a);
}

static int irq_domain_find_free_virq_base_locked(uint32_t nr_irqs,
                                                 uint32_t *virq_base_out)
{
    if (!virq_base_out || !nr_irqs || nr_irqs > IRQCHIP_MAX_IRQS)
        return -EINVAL;

    uint32_t max_base = IRQCHIP_MAX_IRQS - nr_irqs;
    for (uint32_t base = 0; base <= max_base; base++) {
        bool overlap = false;
        struct list_head *pos;
        list_for_each(pos, &irq_domains) {
            const struct irq_domain *dom =
                list_entry(pos, struct irq_domain, node);
            if (!irq_ranges_overlap(dom->virq_base, dom->nr_irqs,
                                    base, nr_irqs))
                continue;
            overlap = true;
            uint64_t skip = (uint64_t)dom->virq_base + dom->nr_irqs;
            if (skip > base)
                base = (uint32_t)(skip - 1);
            break;
        }
        if (!overlap) {
            *virq_base_out = base;
            return 0;
        }
    }
    return -ENOSPC;
}

static int irq_domain_map_locked_by_chip(const struct irqchip_ops *chip,
                                         uint32_t hwirq)
{
    struct list_head *pos;
    list_for_each(pos, &irq_domains) {
        const struct irq_domain *dom = list_entry(pos, struct irq_domain, node);
        uint64_t hwirq_end = (uint64_t)dom->hwirq_base + dom->nr_irqs;
        if (dom->chip != chip)
            continue;
        if ((uint64_t)hwirq < dom->hwirq_base ||
            (uint64_t)hwirq >= hwirq_end)
            continue;
        return (int)(dom->virq_base + (hwirq - dom->hwirq_base));
    }
    return -ENOENT;
}

static int irq_domain_map_locked_by_fwnode(uint32_t fwnode, uint32_t hwirq)
{
    struct list_head *pos;
    list_for_each(pos, &irq_domains) {
        const struct irq_domain *dom = list_entry(pos, struct irq_domain, node);
        uint64_t hwirq_end = (uint64_t)dom->hwirq_base + dom->nr_irqs;
        if (!dom->fwnode || dom->fwnode != fwnode)
            continue;
        if ((uint64_t)hwirq < dom->hwirq_base ||
            (uint64_t)hwirq >= hwirq_end)
            continue;
        return (int)(dom->virq_base + (hwirq - dom->hwirq_base));
    }
    return -ENOENT;
}

static struct irq_domain *irq_domain_find_locked_by_fwnode(uint32_t fwnode)
{
    if (!fwnode)
        return NULL;
    struct list_head *pos;
    list_for_each(pos, &irq_domains) {
        struct irq_domain *dom = list_entry(pos, struct irq_domain, node);
        if (dom->fwnode == fwnode)
            return dom;
    }
    return NULL;
}

static struct irq_domain *irq_domain_find_locked_by_virq(uint32_t virq)
{
    struct list_head *pos;
    list_for_each(pos, &irq_domains) {
        struct irq_domain *dom = list_entry(pos, struct irq_domain, node);
        uint64_t virq_end = (uint64_t)dom->virq_base + dom->nr_irqs;
        if ((uint64_t)virq < dom->virq_base || (uint64_t)virq >= virq_end)
            continue;
        return dom;
    }
    return NULL;
}

static struct irq_domain *irq_domain_find_locked_by_virq_base(uint32_t virq_base)
{
    struct list_head *pos;
    list_for_each(pos, &irq_domains) {
        struct irq_domain *dom = list_entry(pos, struct irq_domain, node);
        if (dom->virq_base == virq_base)
            return dom;
    }
    return NULL;
}

static bool irq_domain_is_ancestor_locked(const struct irq_domain *ancestor,
                                          const struct irq_domain *dom)
{
    const struct irq_domain *iter = dom;
    while (iter) {
        if (iter == ancestor)
            return true;
        iter = iter->parent;
    }
    return false;
}

static void irq_domain_link_parent_locked(struct irq_domain *child,
                                          struct irq_domain *parent)
{
    if (!child)
        return;
    if (child->parent)
        list_del(&child->sibling);
    INIT_LIST_HEAD(&child->sibling);
    child->parent = parent;
    if (parent)
        list_add_tail(&child->sibling, &parent->children);
}

static void irq_domain_unlink_parent_locked(struct irq_domain *child)
{
    if (!child || !child->parent)
        return;
    list_del(&child->sibling);
    INIT_LIST_HEAD(&child->sibling);
    child->parent = NULL;
}

static int irq_domain_set_cascade_locked(struct irq_domain *dom, int parent_irq,
                                         irq_handler_event_fn handler,
                                         void *arg)
{
    if (!dom || !handler)
        return -EINVAL;
    if (parent_irq < 0 || parent_irq >= IRQCHIP_MAX_IRQS)
        return -EINVAL;

    if (dom->parent_irq >= 0) {
        bool same = dom->parent_irq == parent_irq &&
                    dom->cascade_handler == handler &&
                    dom->cascade_arg == arg;
        return same ? 1 : -EEXIST;
    }

    uint64_t virq_end = (uint64_t)dom->virq_base + dom->nr_irqs;
    if ((uint64_t)parent_irq >= dom->virq_base &&
        (uint64_t)parent_irq < virq_end)
        return -EINVAL;

    struct irq_domain *parent_dom = irq_domain_find_locked_by_virq((uint32_t)parent_irq);
    if (parent_dom && irq_domain_is_ancestor_locked(dom, parent_dom))
        return -EINVAL;

    dom->parent_irq = parent_irq;
    dom->cascade_enable_count = 0;
    dom->cascade_handler = handler;
    dom->cascade_arg = arg;
    irq_domain_link_parent_locked(dom, parent_dom);
    return 0;
}

static void irq_domain_clear_cascade_locked(struct irq_domain *dom)
{
    if (!dom)
        return;
    dom->parent_irq = -1;
    dom->cascade_enable_count = 0;
    dom->cascade_handler = NULL;
    dom->cascade_arg = NULL;
    irq_domain_unlink_parent_locked(dom);
}

static int irq_domain_cascade_ref_update(uint32_t virq, bool enable,
                                         int *parent_irq_out)
{
    if (!parent_irq_out)
        return -EINVAL;
    *parent_irq_out = -1;

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    struct irq_domain *dom = irq_domain_find_locked_by_virq(virq);
    if (!dom || dom->parent_irq < 0) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -ENOENT;
    }

    if (enable) {
        if (dom->cascade_enable_count == 0)
            *parent_irq_out = dom->parent_irq;
        dom->cascade_enable_count++;
    } else {
        if (dom->cascade_enable_count <= 0) {
            spin_unlock_irqrestore(&irq_domain_lock, irq_state);
            return -EALREADY;
        }
        dom->cascade_enable_count--;
        if (dom->cascade_enable_count == 0)
            *parent_irq_out = dom->parent_irq;
    }
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);
    return 0;
}

static int platform_irq_domain_add_linear_locked(const char *name,
                                                 const struct irqchip_ops *chip,
                                                 uint32_t fwnode,
                                                 uint32_t hwirq_base,
                                                 uint32_t *virq_base_io,
                                                 uint32_t nr_irqs,
                                                 struct irq_domain *new_domain,
                                                 bool *inserted_out)
{
    if (!chip || !nr_irqs || !virq_base_io || !new_domain || !inserted_out)
        return -EINVAL;

    *inserted_out = false;

    uint32_t virq_base = *virq_base_io;
    if (virq_base == IRQ_DOMAIN_AUTO_VIRQ) {
        int alloc_ret = irq_domain_find_free_virq_base_locked(nr_irqs,
                                                              &virq_base);
        if (alloc_ret < 0)
            return alloc_ret;
    }
    if (virq_base >= IRQCHIP_MAX_IRQS ||
        ((uint64_t)virq_base + nr_irqs) > IRQCHIP_MAX_IRQS)
        return -ERANGE;

    struct list_head *pos;
    list_for_each(pos, &irq_domains) {
        const struct irq_domain *dom = list_entry(pos, struct irq_domain, node);
        if (dom->chip == chip && dom->fwnode == fwnode &&
            dom->hwirq_base == hwirq_base && dom->virq_base == virq_base &&
            dom->nr_irqs == nr_irqs) {
            *virq_base_io = dom->virq_base;
            return 0;
        }
        if (irq_ranges_overlap(dom->virq_base, dom->nr_irqs,
                               virq_base, nr_irqs))
            return -EEXIST;
        if (dom->chip == chip && dom->fwnode == fwnode &&
            irq_ranges_overlap(dom->hwirq_base, dom->nr_irqs,
                               hwirq_base, nr_irqs))
            return -EEXIST;
        if (fwnode && dom->fwnode == fwnode)
            return -EEXIST;
    }

    struct irq_domain *domain = new_domain;
    INIT_LIST_HEAD(&domain->node);
    INIT_LIST_HEAD(&domain->children);
    INIT_LIST_HEAD(&domain->sibling);
    domain->parent = NULL;
    domain->name = name;
    domain->chip = chip;
    domain->fwnode = fwnode;
    domain->hwirq_base = hwirq_base;
    domain->virq_base = virq_base;
    domain->nr_irqs = nr_irqs;
    domain->parent_irq = -1;
    domain->cascade_enable_count = 0;
    domain->cascade_handler = NULL;
    domain->cascade_arg = NULL;
    list_add_tail(&domain->node, &irq_domains);
    irq_domain_count++;
    *inserted_out = true;
    *virq_base_io = virq_base;

    return 0;
}

int platform_irq_domain_add_linear_fwnode(const char *name,
                                          const struct irqchip_ops *chip,
                                          uint32_t fwnode,
                                          uint32_t hwirq_base,
                                          uint32_t virq_base,
                                          uint32_t nr_irqs)
{
    platform_irq_table_init();

    struct irq_domain *new_domain = kzalloc(sizeof(*new_domain));
    if (!new_domain)
        return -ENOMEM;

    uint32_t resolved_virq_base = virq_base;
    bool inserted = false;
    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    int ret = platform_irq_domain_add_linear_locked(name, chip, fwnode,
                                                    hwirq_base,
                                                    &resolved_virq_base,
                                                    nr_irqs, new_domain,
                                                    &inserted);
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);
    if (ret < 0) {
        kfree(new_domain);
        return ret;
    }
    if (!inserted)
        kfree(new_domain);

    for (uint32_t i = 0; i < nr_irqs; i++) {
        struct irq_desc *desc = &irq_table[resolved_virq_base + i];
        bool desc_irq_state;
        spin_lock_irqsave(&desc->lock, &desc_irq_state);
        desc->chip = chip;
        desc->hwirq = hwirq_base + i;
        spin_unlock_irqrestore(&desc->lock, desc_irq_state);
    }

    if (inserted) {
        pr_info("irq: domain '%s' fwnode=0x%x hwirq[%u..%u] -> virq[%u..%u]\n",
                name ? name : "unnamed", fwnode,
                hwirq_base, hwirq_base + nr_irqs - 1, resolved_virq_base,
                resolved_virq_base + nr_irqs - 1);
    }
    return 0;
}

int platform_irq_domain_add_linear(const char *name,
                                   const struct irqchip_ops *chip,
                                   uint32_t hwirq_base, uint32_t virq_base,
                                   uint32_t nr_irqs)
{
    return platform_irq_domain_add_linear_fwnode(name, chip, 0, hwirq_base,
                                                 virq_base, nr_irqs);
}

int platform_irq_domain_alloc_linear(const char *name,
                                     const struct irqchip_ops *chip,
                                     uint32_t hwirq_base, uint32_t nr_irqs,
                                     uint32_t *virq_base_out)
{
    return platform_irq_domain_alloc_linear_fwnode(name, chip, 0, hwirq_base,
                                                   nr_irqs, virq_base_out);
}

int platform_irq_domain_alloc_linear_fwnode(const char *name,
                                            const struct irqchip_ops *chip,
                                            uint32_t fwnode,
                                            uint32_t hwirq_base,
                                            uint32_t nr_irqs,
                                            uint32_t *virq_base_out)
{
    if (!virq_base_out)
        return -EINVAL;

    int ret = platform_irq_domain_add_linear_fwnode(name, chip, fwnode,
                                                    hwirq_base,
                                                    IRQ_DOMAIN_AUTO_VIRQ,
                                                    nr_irqs);
    if (ret < 0)
        return ret;
    int virq = (fwnode != 0) ? platform_irq_domain_map_fwnode(fwnode, hwirq_base)
                             : platform_irq_domain_map(chip, hwirq_base);
    if (virq < 0)
        return virq;
    *virq_base_out = (uint32_t)virq;
    return 0;
}

int platform_irq_domain_setup_cascade(const char *name,
                                      const struct irqchip_ops *chip,
                                      uint32_t hwirq_base,
                                      uint32_t nr_irqs, int parent_irq,
                                      irq_handler_event_fn handler, void *arg,
                                      uint32_t flags,
                                      uint32_t *virq_base_out)
{
    int ret = platform_irq_domain_alloc_linear(name, chip, hwirq_base, nr_irqs,
                                               virq_base_out);
    if (ret < 0)
        return ret;
    return platform_irq_domain_set_cascade(*virq_base_out, parent_irq, handler,
                                           arg, flags);
}

int platform_irq_domain_setup_cascade_fwnode(const char *name,
                                             const struct irqchip_ops *chip,
                                             uint32_t fwnode,
                                             uint32_t hwirq_base,
                                             uint32_t nr_irqs,
                                             int parent_irq,
                                             irq_handler_event_fn handler,
                                             void *arg, uint32_t flags,
                                             uint32_t *virq_base_out)
{
    int ret = platform_irq_domain_alloc_linear_fwnode(name, chip, fwnode,
                                                      hwirq_base, nr_irqs,
                                                      virq_base_out);
    if (ret < 0)
        return ret;
    return platform_irq_domain_set_cascade(*virq_base_out, parent_irq, handler,
                                           arg, flags);
}

int platform_irq_domain_bind_fwnode(const struct irqchip_ops *chip,
                                    uint32_t hwirq_base, uint32_t nr_irqs,
                                    uint32_t fwnode)
{
    if (!chip || !nr_irqs || !fwnode)
        return -EINVAL;

    platform_irq_table_init();

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);

    struct list_head *pos;
    list_for_each(pos, &irq_domains) {
        const struct irq_domain *dom = list_entry(pos, struct irq_domain, node);
        if (dom->fwnode == fwnode &&
            !(dom->chip == chip && dom->hwirq_base == hwirq_base &&
              dom->nr_irqs == nr_irqs)) {
            spin_unlock_irqrestore(&irq_domain_lock, irq_state);
            return -EEXIST;
        }
    }

    list_for_each(pos, &irq_domains) {
        struct irq_domain *dom = list_entry(pos, struct irq_domain, node);
        if (dom->chip != chip || dom->hwirq_base != hwirq_base ||
            dom->nr_irqs != nr_irqs)
            continue;
        if (!dom->fwnode || dom->fwnode == fwnode) {
            dom->fwnode = fwnode;
            spin_unlock_irqrestore(&irq_domain_lock, irq_state);
            return 0;
        }
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -EEXIST;
    }

    spin_unlock_irqrestore(&irq_domain_lock, irq_state);
    return -ENOENT;
}

static void irq_domain_cascade_action(void *arg,
                                      const struct trap_core_event *ev)
{
    struct irq_domain *dom = (struct irq_domain *)arg;
    if (!dom)
        return;

    irq_handler_event_fn handler = NULL;
    void *handler_arg = NULL;

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    handler = dom->cascade_handler;
    handler_arg = dom->cascade_arg;
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);

    if (handler)
        handler(handler_arg, ev);
}

int platform_irq_domain_set_cascade_fwnode(uint32_t fwnode, int parent_irq,
                                           irq_handler_event_fn handler,
                                           void *arg, uint32_t flags)
{
    if (!fwnode)
        return -EINVAL;

    platform_irq_table_init();

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    struct irq_domain *dom = irq_domain_find_locked_by_fwnode(fwnode);
    if (!dom) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -ENOENT;
    }
    uint32_t child_virq = dom->virq_base;
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);

    return platform_irq_domain_set_cascade(child_virq, parent_irq, handler,
                                           arg, flags);
}

int platform_irq_domain_set_cascade(uint32_t child_virq, int parent_irq,
                                    irq_handler_event_fn handler, void *arg,
                                    uint32_t flags)
{
    if (!handler || parent_irq < 0 || parent_irq >= IRQCHIP_MAX_IRQS)
        return -EINVAL;

    platform_irq_table_init();

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    struct irq_domain *dom = irq_domain_find_locked_by_virq(child_virq);
    if (!dom) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -ENOENT;
    }
    int ret = irq_domain_set_cascade_locked(dom, parent_irq, handler, arg);
    if (ret < 0) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return ret;
    }
    if (ret > 0) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return 0;
    }
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);

    uint32_t action_flags = IRQ_FLAG_SHARED | IRQ_FLAG_NO_AUTO_ENABLE;
    action_flags |= (flags & (IRQ_FLAG_TRIGGER_MASK | IRQ_FLAG_DEFERRED));
    ret = platform_irq_register_action(parent_irq, NULL,
                                       irq_domain_cascade_action, dom,
                                       action_flags);
    if (ret < 0) {
        spin_lock_irqsave(&irq_domain_lock, &irq_state);
        irq_domain_clear_cascade_locked(dom);
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return ret;
    }

    return 0;
}

int platform_irq_domain_unset_cascade_fwnode(uint32_t fwnode)
{
    if (!fwnode)
        return -EINVAL;

    platform_irq_table_init();

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    struct irq_domain *dom = irq_domain_find_locked_by_fwnode(fwnode);
    if (!dom) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -ENOENT;
    }
    uint32_t child_virq = dom->virq_base;
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);

    return platform_irq_domain_unset_cascade(child_virq);
}

int platform_irq_domain_unset_cascade(uint32_t child_virq)
{
    if (child_virq >= IRQCHIP_MAX_IRQS)
        return -EINVAL;

    platform_irq_table_init();

    int parent_irq = -1;
    irq_handler_event_fn handler = NULL;
    void *handler_arg = NULL;
    struct irq_domain *dom = NULL;

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    dom = irq_domain_find_locked_by_virq(child_virq);
    if (!dom || dom->parent_irq < 0) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -ENOENT;
    }
    if (dom->cascade_enable_count > 0) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -EBUSY;
    }
    parent_irq = dom->parent_irq;
    handler = dom->cascade_handler;
    handler_arg = dom->cascade_arg;
    irq_domain_clear_cascade_locked(dom);
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);

    int ret = platform_irq_unregister_action(parent_irq, NULL,
                                             irq_domain_cascade_action, dom);
    if (ret < 0) {
        spin_lock_irqsave(&irq_domain_lock, &irq_state);
        if (dom->parent_irq < 0)
            (void)irq_domain_set_cascade_locked(dom, parent_irq, handler,
                                                handler_arg);
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return ret;
    }
    return 0;
}

int platform_irq_domain_remove_fwnode(uint32_t fwnode)
{
    if (!fwnode)
        return -EINVAL;

    platform_irq_table_init();

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    struct irq_domain *dom = irq_domain_find_locked_by_fwnode(fwnode);
    if (!dom) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -ENOENT;
    }
    uint32_t child_virq = dom->virq_base;
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);

    return platform_irq_domain_remove(child_virq);
}

int platform_irq_domain_remove(uint32_t child_virq)
{
    if (child_virq >= IRQCHIP_MAX_IRQS)
        return -EINVAL;

    platform_irq_table_init();

    uint32_t virq_base = 0;
    uint32_t nr_irqs = 0;
    bool had_cascade = false;

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    struct irq_domain *dom = irq_domain_find_locked_by_virq(child_virq);
    if (!dom) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -ENOENT;
    }
    if (!list_empty(&dom->children)) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -EBUSY;
    }
    virq_base = dom->virq_base;
    nr_irqs = dom->nr_irqs;
    had_cascade = dom->parent_irq >= 0;
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);

    if (had_cascade) {
        int ret = platform_irq_domain_unset_cascade(virq_base);
        if (ret < 0)
            return ret;
    }

    for (uint32_t i = 0; i < nr_irqs; i++) {
        struct irq_desc *desc = &irq_table[virq_base + i];
        bool desc_irq_state;
        spin_lock_irqsave(&desc->lock, &desc_irq_state);
        bool busy = (desc->enable_count > 0) || !list_empty(&desc->actions);
        spin_unlock_irqrestore(&desc->lock, desc_irq_state);
        if (busy)
            return -EBUSY;
    }

    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    dom = irq_domain_find_locked_by_virq_base(virq_base);
    if (!dom || dom->nr_irqs != nr_irqs) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -ENOENT;
    }
    if (!list_empty(&dom->children) || dom->parent_irq >= 0 ||
        dom->cascade_enable_count > 0) {
        spin_unlock_irqrestore(&irq_domain_lock, irq_state);
        return -EBUSY;
    }
    irq_domain_unlink_parent_locked(dom);
    list_del(&dom->node);
    irq_domain_count--;
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);

    const struct platform_desc *plat = platform_get();
    const struct irqchip_ops *root_chip = plat ? plat->irqchip : NULL;
    for (uint32_t i = 0; i < nr_irqs; i++) {
        struct irq_desc *desc = &irq_table[virq_base + i];
        bool desc_irq_state;
        spin_lock_irqsave(&desc->lock, &desc_irq_state);
        desc->flags = 0;
        desc->affinity_mask = 1U;
        desc->hwirq = virq_base + i;
        desc->chip = root_chip;
        desc->dispatch_count = 0;
        desc->overflow_warned = false;
        spin_unlock_irqrestore(&desc->lock, desc_irq_state);
    }

    kfree(dom);
    return 0;
}

int platform_irq_domain_map(const struct irqchip_ops *chip, uint32_t hwirq)
{
    if (!chip)
        return -EINVAL;

    platform_irq_table_init();

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    int virq = irq_domain_map_locked_by_chip(chip, hwirq);
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);
    return virq;
}

int platform_irq_domain_map_fwnode(uint32_t fwnode, uint32_t hwirq)
{
    if (!fwnode)
        return -EINVAL;

    platform_irq_table_init();

    bool irq_state;
    spin_lock_irqsave(&irq_domain_lock, &irq_state);
    int virq = irq_domain_map_locked_by_fwnode(fwnode, hwirq);
    spin_unlock_irqrestore(&irq_domain_lock, irq_state);
    return virq;
}

static void irq_desc_recalc_flags_locked(struct irq_desc *desc)
{
    if (!desc)
        return;

    uint32_t merged_flags = 0;
    uint32_t merged_type = IRQ_FLAG_TRIGGER_NONE;
    struct list_head *pos;
    list_for_each(pos, &desc->actions) {
        struct irq_action *action = list_entry(pos, struct irq_action, node);
        merged_flags |= (action->flags & ~IRQ_FLAG_TRIGGER_MASK);
        uint32_t action_type = action->flags & IRQ_FLAG_TRIGGER_MASK;
        if (!merged_type && action_type)
            merged_type = action_type;
    }
    desc->flags &= ~IRQ_DESC_ACTION_FLAG_MASK;
    desc->flags |= merged_flags | merged_type;
}

static int platform_irq_register_action(int irq, irq_handler_fn handler,
                                        irq_handler_event_fn handler_ev,
                                        void *arg, uint32_t flags)
{
    if ((!handler && !handler_ev) || irq < 0 || irq >= IRQCHIP_MAX_IRQS)
        return -EINVAL;

    struct irq_desc *desc = platform_irq_desc_get(irq);
    if (!desc)
        return -EINVAL;

    struct irq_action *action = kzalloc(sizeof(*action));
    if (!action)
        return -ENOMEM;

    INIT_LIST_HEAD(&action->node);
    action->handler = handler;
    action->handler_ev = handler_ev;
    action->arg = arg;
    action->irq = irq;
    action->flags = flags;
    action->refs = 0;
    INIT_LIST_HEAD(&action->deferred_node);
    action->deferred_pending = 0;
    action->removed = false;
    action->deferred_queued = false;
    action->deferred_has_ev = false;

    bool irq_state;
    spin_lock_irqsave(&desc->lock, &irq_state);

    bool had_actions = !list_empty(&desc->actions);
    bool shared = ((desc->flags | flags) & IRQ_FLAG_SHARED) != 0;
    if (had_actions && !shared) {
        pr_warn("irq: multiple handlers on irq %d without SHARED flag\n",
                irq);
    }

    uint32_t old_type = desc->flags & IRQ_FLAG_TRIGGER_MASK;
    uint32_t new_type = flags & IRQ_FLAG_TRIGGER_MASK;
    if (new_type && old_type && old_type != new_type) {
        pr_warn("irq: conflicting trigger type on irq %d (old=0x%x new=0x%x)\n",
                irq, old_type, new_type);
    } else if (new_type) {
        desc->flags = (desc->flags & ~IRQ_FLAG_TRIGGER_MASK) | new_type;
    }

    desc->flags |= (flags & ~IRQ_FLAG_TRIGGER_MASK);
    list_add_tail(&action->node, &desc->actions);

    spin_unlock_irqrestore(&desc->lock, irq_state);

    if (flags & IRQ_FLAG_DEFERRED)
        (void)irq_deferred_start_worker();
    return 0;
}

static int platform_irq_unregister_action(int irq, irq_handler_fn handler,
                                          irq_handler_event_fn handler_ev,
                                          void *arg)
{
    if ((!handler && !handler_ev) || irq < 0 || irq >= IRQCHIP_MAX_IRQS)
        return -EINVAL;

    struct irq_desc *desc = platform_irq_desc_get(irq);
    if (!desc)
        return -EINVAL;

    struct irq_action *action = NULL;
    bool irq_state;
    spin_lock_irqsave(&desc->lock, &irq_state);
    struct list_head *pos;
    struct list_head *next;
    list_for_each_safe(pos, next, &desc->actions) {
        struct irq_action *cur = list_entry(pos, struct irq_action, node);
        if (cur->handler != handler || cur->handler_ev != handler_ev ||
            cur->arg != arg)
            continue;
        list_del(&cur->node);
        INIT_LIST_HEAD(&cur->node);
        cur->removed = true;
        action = cur;
        break;
    }
    if (!action) {
        spin_unlock_irqrestore(&desc->lock, irq_state);
        return -ENOENT;
    }

    if (action->deferred_queued) {
        bool deferred_irq_state;
        spin_lock_irqsave(&irq_deferred.lock, &deferred_irq_state);
        if (action->deferred_queued) {
            list_del(&action->deferred_node);
            INIT_LIST_HEAD(&action->deferred_node);
            action->deferred_queued = false;
            action->deferred_pending = 0;
            action->deferred_has_ev = false;
            irq_action_put_locked(action);
        }
        spin_unlock_irqrestore(&irq_deferred.lock, deferred_irq_state);
    }

    bool ready = action->refs == 0;

    irq_desc_recalc_flags_locked(desc);
    spin_unlock_irqrestore(&desc->lock, irq_state);

    if (ready) {
        kfree(action);
        return 0;
    }

    for (size_t i = 0; i < 10000; i++) {
        proc_yield();
        spin_lock_irqsave(&desc->lock, &irq_state);
        bool ready = action->refs == 0;
        spin_unlock_irqrestore(&desc->lock, irq_state);
        if (!ready)
            continue;
        kfree(action);
        return 0;
    }

    pr_warn("irq: unregister timeout irq=%d handler=%p arg=%p\n",
            irq, handler_ev ? (void *)handler_ev : (void *)handler, arg);
    return -EBUSY;
}

int platform_irq_register_ex(int irq, irq_handler_event_fn handler, void *arg,
                             uint32_t flags)
{
    return platform_irq_register_action(irq, NULL, handler, arg, flags);
}

int platform_irq_unregister_ex(int irq, irq_handler_event_fn handler, void *arg)
{
    return platform_irq_unregister_action(irq, NULL, handler, arg);
}

void platform_irq_register(int irq, irq_handler_fn handler, void *arg)
{
    int ret = platform_irq_register_action(irq, handler, NULL, arg,
                                           IRQ_FLAG_TRIGGER_LEVEL);
    if (ret < 0)
        pr_warn("irq: failed to register irq %d (ret=%d)\n", irq, ret);
}

int platform_irq_unregister(int irq, irq_handler_fn handler, void *arg)
{
    return platform_irq_unregister_action(irq, handler, NULL, arg);
}

void platform_irq_set_type(int irq, uint32_t flags)
{
    struct irq_desc *desc = platform_irq_desc_get(irq);
    if (!desc)
        return;

    uint32_t type = flags & IRQ_FLAG_TRIGGER_MASK;
    if (!type)
        return;

    bool irq_state;
    spin_lock_irqsave(&desc->lock, &irq_state);
    desc->flags = (desc->flags & ~IRQ_FLAG_TRIGGER_MASK) | type;
    const struct irqchip_ops *chip = desc->chip;
    uint32_t hwirq = desc->hwirq;
    int enable_count = desc->enable_count;
    bool no_chip = (desc->flags & IRQ_FLAG_NO_CHIP) != 0;
    spin_unlock_irqrestore(&desc->lock, irq_state);

    if (!no_chip && chip && chip->set_type && enable_count > 0)
        (void)chip->set_type((int)hwirq, type);
}

void platform_irq_set_affinity(int irq, uint32_t cpu_mask)
{
    struct irq_desc *desc = platform_irq_desc_get(irq);
    if (!desc)
        return;

    uint32_t mask = irq_sanitize_affinity_mask(cpu_mask);
    bool irq_state;
    spin_lock_irqsave(&desc->lock, &irq_state);
    desc->affinity_mask = mask;
    const struct irqchip_ops *chip = desc->chip;
    uint32_t hwirq = desc->hwirq;
    int enable_count = desc->enable_count;
    bool no_chip = (desc->flags & IRQ_FLAG_NO_CHIP) != 0;
    spin_unlock_irqrestore(&desc->lock, irq_state);

    if (!no_chip && chip && chip->set_affinity && enable_count > 0)
        (void)chip->set_affinity((int)hwirq, mask);
}

void platform_irq_dispatch_hwirq(const struct irqchip_ops *chip,
                                 uint32_t hwirq,
                                 const struct trap_core_event *ev)
{
    int virq = platform_irq_domain_map(chip, hwirq);
    if (virq < 0) {
        if (!irq_domain_warned) {
            irq_domain_warned = true;
            pr_warn("irq: unmapped hwirq %u from chip %p\n", hwirq, chip);
        }
        return;
    }
    platform_irq_dispatch((uint32_t)virq, ev);
}

void platform_irq_dispatch_fwnode_hwirq(uint32_t fwnode, uint32_t hwirq,
                                        const struct trap_core_event *ev)
{
    int virq = platform_irq_domain_map_fwnode(fwnode, hwirq);
    if (virq < 0) {
        if (!irq_domain_warned) {
            irq_domain_warned = true;
            pr_warn("irq: unmapped hwirq %u for fwnode=0x%x\n", hwirq,
                    fwnode);
        }
        return;
    }
    platform_irq_dispatch((uint32_t)virq, ev);
}

void platform_irq_dispatch(uint32_t irq, const struct trap_core_event *ev)
{
    if (irq >= IRQCHIP_MAX_IRQS)
        return;

    platform_irq_table_init();

    struct irq_desc *desc = &irq_table[irq];
    struct irq_action *snapshot[IRQ_ACTION_SNAPSHOT_MAX];
    size_t nr = 0;
    bool dropped = false;
    bool irq_state;

    spin_lock_irqsave(&desc->lock, &irq_state);
    if (desc->enable_count <= 0) {
        spin_unlock_irqrestore(&desc->lock, irq_state);
        return;
    }
    desc->dispatch_count++;
    struct list_head *pos;
    list_for_each(pos, &desc->actions) {
        struct irq_action *action = list_entry(pos, struct irq_action, node);
        if (nr < ARRAY_SIZE(snapshot)) {
            irq_action_get_locked(action);
            snapshot[nr++] = action;
        } else {
            dropped = true;
        }
    }
    if (dropped && !desc->overflow_warned) {
        desc->overflow_warned = true;
        pr_warn("irq: action snapshot overflow on irq %u\n", irq);
    }
    spin_unlock_irqrestore(&desc->lock, irq_state);

    for (size_t i = 0; i < nr; i++) {
        struct irq_action *action = snapshot[i];
        bool run_action = true;
        spin_lock_irqsave(&desc->lock, &irq_state);
        run_action = !action->removed;
        spin_unlock_irqrestore(&desc->lock, irq_state);
        if (!run_action) {
            irq_action_put(action);
            continue;
        }
        if (action->flags & IRQ_FLAG_DEFERRED) {
            if (irq_deferred_queue_action(desc, action, ev)) {
                irq_action_put(action);
                continue;
            }
        }
        if (action->handler_ev)
            action->handler_ev(action->arg, ev);
        else if (action->handler)
            action->handler(action->arg);
        irq_action_put(action);
    }
}

void platform_irq_dispatch_nr(uint32_t irq)
{
    platform_irq_dispatch(irq, NULL);
}

int platform_timer_irq(void)
{
    const struct platform_desc *plat = platform_get();
    if (!plat || !plat->timer || !plat->timer->irq)
        return -ENOENT;
    int irq = plat->timer->irq();
    if (irq < 0 || irq >= IRQCHIP_MAX_IRQS)
        return -ERANGE;
    return irq;
}

void platform_timer_dispatch(const struct trap_core_event *ev)
{
    int irq = platform_timer_irq();
    if (irq < 0)
        return;
    platform_irq_dispatch((uint32_t)irq, ev);
}

/* --- arch_irq_* unified dispatch --- */

void arch_irq_init(void)
{
    platform_irq_table_init();
    const struct platform_desc *plat = platform_get();
    if (plat && plat->irqchip) {
        uint32_t root_irqs = plat->irqchip_root_irqs;
        if (!root_irqs || root_irqs > IRQCHIP_MAX_IRQS)
            root_irqs = IRQCHIP_MAX_IRQS;
        (void)platform_irq_domain_add_linear("root", plat->irqchip, 0, 0,
                                             root_irqs);
    }
    if (plat && plat->irqchip && plat->irqchip->init)
        plat->irqchip->init(plat);
}

void arch_irq_enable_nr(int irq)
{
    struct irq_desc *desc = platform_irq_desc_get(irq);
    if (!desc)
        return;

    bool irq_state;
    spin_lock_irqsave(&desc->lock, &irq_state);

    const struct irqchip_ops *chip = desc->chip;
    uint32_t hwirq = desc->hwirq;
    bool is_per_cpu = (desc->flags & IRQ_FLAG_PER_CPU) != 0;
    bool no_chip = (desc->flags & IRQ_FLAG_NO_CHIP) != 0;
    uint32_t type = desc->flags & IRQ_FLAG_TRIGGER_MASK;
    uint32_t affinity_mask = desc->affinity_mask;
    bool do_enable = false;
    int cascade_parent_irq = -1;

    if (is_per_cpu) {
        desc->enable_count++;
        do_enable = true;
    } else {
        if (desc->enable_count == 0)
            do_enable = true;
        desc->enable_count++;
    }

    spin_unlock_irqrestore(&desc->lock, irq_state);

    if (do_enable && !is_per_cpu)
        (void)irq_domain_cascade_ref_update((uint32_t)irq, true,
                                            &cascade_parent_irq);
    if (cascade_parent_irq >= 0)
        arch_irq_enable_nr(cascade_parent_irq);

    if (!do_enable || !chip || no_chip)
        return;
    if (chip->set_type && type)
        (void)chip->set_type((int)hwirq, type);
    if (chip->set_affinity)
        (void)chip->set_affinity((int)hwirq, affinity_mask);
    if (chip->enable)
        chip->enable((int)hwirq);
}

void arch_irq_disable_nr(int irq)
{
    struct irq_desc *desc = platform_irq_desc_get(irq);
    if (!desc)
        return;

    bool irq_state;
    spin_lock_irqsave(&desc->lock, &irq_state);

    const struct irqchip_ops *chip = desc->chip;
    uint32_t hwirq = desc->hwirq;
    bool is_per_cpu = (desc->flags & IRQ_FLAG_PER_CPU) != 0;
    bool no_chip = (desc->flags & IRQ_FLAG_NO_CHIP) != 0;
    bool do_disable = false;
    int cascade_parent_irq = -1;

    if (desc->enable_count <= 0) {
        spin_unlock_irqrestore(&desc->lock, irq_state);
        return;
    }

    desc->enable_count--;
    if (is_per_cpu || desc->enable_count == 0)
        do_disable = true;

    spin_unlock_irqrestore(&desc->lock, irq_state);

    if (do_disable && !is_per_cpu)
        (void)irq_domain_cascade_ref_update((uint32_t)irq, false,
                                            &cascade_parent_irq);
    if (do_disable && chip && !no_chip && chip->disable)
        chip->disable((int)hwirq);
    if (cascade_parent_irq >= 0)
        arch_irq_disable_nr(cascade_parent_irq);
}

void arch_irq_register_ex(int irq,
                          void (*handler)(void *arg,
                                          const struct trap_core_event *ev),
                          void *arg, uint32_t flags)
{
    int ret = platform_irq_register_ex(irq, handler, arg, flags);
    if (ret < 0) {
        pr_warn("irq: failed to register irq %d (ret=%d)\n", irq, ret);
        return;
    }

    if (!(flags & IRQ_FLAG_NO_AUTO_ENABLE))
        arch_irq_enable_nr(irq);
}

void arch_irq_set_type(int irq, uint32_t flags)
{
    platform_irq_set_type(irq, flags);
}

void arch_irq_set_affinity(int irq, uint32_t cpu_mask)
{
    platform_irq_set_affinity(irq, cpu_mask);
}

void arch_irq_register(int irq, void (*handler)(void *), void *arg)
{
    platform_irq_register(irq, handler, arg);
    arch_irq_enable_nr(irq);
}
