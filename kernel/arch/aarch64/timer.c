/**
 * kernel/arch/aarch64/timer.c - AArch64 generic timer
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/tick.h>
#include <kairos/types.h>

#define TIMER_PPI_IRQ 30  /* EL1 Physical Timer PPI (INTID 30) */

static uint64_t timer_freq;
static uint64_t timer_interval;
static bool timer_irq_registered;
static int timer_virq = TIMER_PPI_IRQ;

static inline uint64_t cntfrq(void) {
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}

static inline uint64_t cntpct(void) {
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntpct_el0" : "=r"(val));
    return val;
}

static void aarch64_timer_irq_handler(void *arg,
                                      const struct trap_core_event *ev) {
    (void)arg;
    arch_timer_ack();
    tick_policy_on_timer_irq(ev);
}

static int aarch64_timer_irq_virq(void)
{
    const struct platform_desc *plat = platform_get();
    if (!plat || !plat->irqchip)
        return TIMER_PPI_IRQ;
    int virq = platform_irq_domain_map(plat->irqchip, TIMER_PPI_IRQ);
    return (virq >= 0) ? virq : TIMER_PPI_IRQ;
}

const struct timer_ops aarch64_timer_ops = {
    .irq = aarch64_timer_irq_virq,
};

void arch_timer_init(uint64_t hz) {
    if (!hz)
        hz = CONFIG_HZ;
    timer_freq = cntfrq();
    timer_interval = timer_freq / hz;

    __asm__ __volatile__("msr cntp_tval_el0, %0" :: "r"(timer_interval));
    __asm__ __volatile__("msr cntp_ctl_el0, %0" :: "r"((uint64_t)1));

    bool irq_state = arch_irq_save();
    bool need_register = !timer_irq_registered;
    if (need_register)
        timer_irq_registered = true;
    arch_irq_restore(irq_state);
    int irq = platform_timer_irq();
    timer_virq = (irq >= 0) ? irq : aarch64_timer_irq_virq();

    if (need_register) {
        arch_irq_register_ex(timer_virq, aarch64_timer_irq_handler, NULL,
                             IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_PER_CPU |
                                 IRQ_FLAG_TIMER);
    } else {
        arch_irq_enable_nr(timer_virq);
    }

    if (arch_cpu_id() == 0) {
        pr_info("Timer: %lu Hz (interval=%lu ticks)\n",
                (unsigned long)hz, (unsigned long)timer_interval);
    }
}

uint64_t arch_timer_ticks(void) { return cntpct(); }
uint64_t arch_timer_freq(void) { return timer_freq; }
uint64_t arch_timer_ticks_to_ns(uint64_t t) { return (t * 1000000000ULL) / timer_freq; }
uint64_t arch_timer_ns_to_ticks(uint64_t ns) { return (ns * timer_freq) / 1000000000ULL; }
void arch_timer_set_next(uint64_t t) { __asm__ __volatile__("msr cntp_tval_el0, %0" :: "r"(t)); }

void arch_timer_ack(void) {
    /* Re-arm the timer for the next tick */
    __asm__ __volatile__("msr cntp_tval_el0, %0" :: "r"(timer_interval));
}

uint64_t arch_timer_get_ticks(void) { return tick_policy_get_ticks(); }
