/**
 * kernel/platform/core.c - Platform registration, selection, and IRQ dispatch
 */

#include <kairos/platform_core.h>
#include <kairos/arch.h>
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

struct irq_action {
    struct list_head node;
    irq_handler_fn handler;
    irq_handler_event_fn handler_ev;
    void *arg;
    uint32_t flags;
    struct list_head deferred_node;
    struct trap_core_event deferred_ev;
    uint32_t deferred_pending;
    bool deferred_queued;
    bool deferred_has_ev;
};

struct irq_desc {
    struct list_head actions;
    uint32_t flags;
    int enable_count;
    uint32_t hwirq;
    const struct irqchip_ops *chip;
    uint64_t dispatch_count;
    bool overflow_warned;
    spinlock_t lock;
};

static struct irq_desc irq_table[IRQCHIP_MAX_IRQS];
static bool irq_table_ready;

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

static bool irq_deferred_queue_action(struct irq_action *action,
                                      const struct trap_core_event *ev)
{
    if (!action || !(action->flags & IRQ_FLAG_DEFERRED))
        return false;

    bool irq_state;
    bool wake = false;
    spin_lock_irqsave(&irq_deferred.lock, &irq_state);
    if (!irq_deferred.worker_started) {
        spin_unlock_irqrestore(&irq_deferred.lock, irq_state);
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
        list_add_tail(&action->deferred_node, &irq_deferred.pending_actions);
        wake = true;
    }
    spin_unlock_irqrestore(&irq_deferred.lock, irq_state);

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

        if (pending == 0)
            pending = 1;
        while (pending--) {
            if (action->handler_ev) {
                action->handler_ev(action->arg, has_ev ? &ev : NULL);
            } else if (action->handler) {
                action->handler(action->arg);
            }
        }
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
            irq_table[i].enable_count = 0;
            irq_table[i].hwirq = (uint32_t)i;
            irq_table[i].chip = chip;
            irq_table[i].dispatch_count = 0;
            irq_table[i].overflow_warned = false;
            spin_init(&irq_table[i].lock);
        }
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
    action->flags = flags;
    INIT_LIST_HEAD(&action->deferred_node);
    action->deferred_pending = 0;
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

int platform_irq_register_ex(int irq, irq_handler_event_fn handler, void *arg,
                             uint32_t flags)
{
    return platform_irq_register_action(irq, NULL, handler, arg, flags);
}

void platform_irq_register(int irq, irq_handler_fn handler, void *arg)
{
    int ret = platform_irq_register_action(irq, handler, NULL, arg,
                                           IRQ_FLAG_TRIGGER_LEVEL);
    if (ret < 0)
        pr_warn("irq: failed to register irq %d (ret=%d)\n", irq, ret);
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
    int enable_count = desc->enable_count;
    spin_unlock_irqrestore(&desc->lock, irq_state);

    if (chip && chip->set_type && enable_count > 0)
        (void)chip->set_type(irq, type);
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
    desc->dispatch_count++;
    struct list_head *pos;
    list_for_each(pos, &desc->actions) {
        struct irq_action *action = list_entry(pos, struct irq_action, node);
        if (nr < ARRAY_SIZE(snapshot)) {
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
        if (action->flags & IRQ_FLAG_DEFERRED) {
            if (irq_deferred_queue_action(action, ev))
                continue;
        }
        if (action->handler_ev)
            action->handler_ev(action->arg, ev);
        else if (action->handler)
            action->handler(action->arg);
    }
}

void platform_irq_dispatch_nr(uint32_t irq)
{
    platform_irq_dispatch(irq, NULL);
}

/* --- arch_irq_* unified dispatch --- */

void arch_irq_init(void)
{
    platform_irq_table_init();
    const struct platform_desc *plat = platform_get();
    if (plat && plat->irqchip) {
        for (int i = 0; i < IRQCHIP_MAX_IRQS; i++)
            irq_table[i].chip = plat->irqchip;
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
    bool is_per_cpu = (desc->flags & IRQ_FLAG_PER_CPU) != 0;
    uint32_t type = desc->flags & IRQ_FLAG_TRIGGER_MASK;
    bool do_enable = false;

    if (is_per_cpu) {
        desc->enable_count++;
        do_enable = true;
    } else {
        if (desc->enable_count == 0)
            do_enable = true;
        desc->enable_count++;
    }

    spin_unlock_irqrestore(&desc->lock, irq_state);

    if (!do_enable || !chip)
        return;
    if (chip->set_type && type)
        (void)chip->set_type(irq, type);
    if (chip->enable)
        chip->enable(irq);
}

void arch_irq_disable_nr(int irq)
{
    struct irq_desc *desc = platform_irq_desc_get(irq);
    if (!desc)
        return;

    bool irq_state;
    spin_lock_irqsave(&desc->lock, &irq_state);

    const struct irqchip_ops *chip = desc->chip;
    bool is_per_cpu = (desc->flags & IRQ_FLAG_PER_CPU) != 0;
    bool do_disable = false;

    if (desc->enable_count <= 0) {
        spin_unlock_irqrestore(&desc->lock, irq_state);
        return;
    }

    desc->enable_count--;
    if (is_per_cpu || desc->enable_count == 0)
        do_disable = true;

    spin_unlock_irqrestore(&desc->lock, irq_state);

    if (do_disable && chip && chip->disable)
        chip->disable(irq);
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

void arch_irq_register(int irq, void (*handler)(void *), void *arg)
{
    platform_irq_register(irq, handler, arg);
    arch_irq_enable_nr(irq);
}
