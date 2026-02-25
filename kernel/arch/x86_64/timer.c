/**
 * kernel/arch/x86_64/timer.c - x86_64 timer
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/tick.h>
#include <kairos/types.h>

#define PIT_FREQ 1193182
#define PIT_CH2  0x42
#define PIT_CMD  0x43
#define PIT_SPKR 0x61

#define LAPIC_TIMER_DIV  0x3E0
#define LAPIC_TIMER_INIT 0x380
#define LAPIC_TIMER_CURR 0x390
#define LAPIC_LVT_TIMER  0x320
#define X86_TIMER_VIRQ 0

extern uint32_t lapic_read(uint32_t reg);
extern void lapic_init(void);
extern void lapic_eoi(void);
extern void lapic_timer_init(uint32_t hz);

static uint64_t lapic_ticks_per_sec = 0;
static bool timer_irq_registered;
static int timer_virq = X86_TIMER_VIRQ;

static void x86_timer_irq_handler(void *arg,
                                  const struct trap_core_event *ev) {
    (void)arg;
    tick_policy_on_timer_irq(ev);
}

static int x86_timer_irq_virq(void)
{
    const struct platform_desc *plat = platform_get();
    if (!plat || !plat->irqchip)
        return X86_TIMER_VIRQ;
    int virq = platform_irq_domain_map(plat->irqchip, X86_TIMER_VIRQ);
    return (virq >= 0) ? virq : X86_TIMER_VIRQ;
}

const struct timer_ops x86_timer_ops = {
    .irq = x86_timer_irq_virq,
};

static void pit_sleep_10ms(void) {
    uint16_t count = PIT_FREQ / 100;
    uint8_t tmp = inb(PIT_SPKR);
    outb(PIT_SPKR, (tmp & 0xFC) | 1);
    outb(PIT_CMD, 0xB0); /* ch2, lobyte/hibyte, mode 0 */
    outb(PIT_CH2, count & 0xFF);
    outb(PIT_CH2, (count >> 8) & 0xFF);
    while (!(inb(PIT_SPKR) & 0x20))
        ;
    outb(PIT_SPKR, tmp);
}

void arch_timer_init(uint64_t hz) {
    if (!hz)
        hz = CONFIG_HZ;

    lapic_init();

    /* Calibrate LAPIC timer using PIT for 10ms */
    uint32_t div = 0x3; /* divide by 16 */
    *((volatile uint32_t *)((uint8_t *)phys_to_virt(0xFEE00000) + LAPIC_TIMER_DIV)) = div;
    *((volatile uint32_t *)((uint8_t *)phys_to_virt(0xFEE00000) + LAPIC_LVT_TIMER)) = 0x20;
    *((volatile uint32_t *)((uint8_t *)phys_to_virt(0xFEE00000) + LAPIC_TIMER_INIT)) = 0xFFFFFFFF;

    pit_sleep_10ms();

    uint32_t curr = lapic_read(LAPIC_TIMER_CURR);
    uint32_t elapsed = 0xFFFFFFFF - curr;
    lapic_ticks_per_sec = (uint64_t)elapsed * 100;

    uint32_t initial = (uint32_t)(lapic_ticks_per_sec / hz);
    *((volatile uint32_t *)((uint8_t *)phys_to_virt(0xFEE00000) + LAPIC_LVT_TIMER)) = 0x20000 | 0x20;
    *((volatile uint32_t *)((uint8_t *)phys_to_virt(0xFEE00000) + LAPIC_TIMER_INIT)) = initial;

    bool irq_state = arch_irq_save();
    bool need_register = !timer_irq_registered;
    if (need_register)
        timer_irq_registered = true;
    arch_irq_restore(irq_state);
    int irq = platform_timer_irq();
    timer_virq = (irq >= 0) ? irq : x86_timer_irq_virq();

    if (need_register) {
        arch_irq_register_ex(
            timer_virq, x86_timer_irq_handler, NULL,
            IRQ_FLAG_TRIGGER_EDGE | IRQ_FLAG_PER_CPU | IRQ_FLAG_TIMER |
                IRQ_FLAG_NO_CHIP);
    } else {
        arch_irq_enable_nr(timer_virq);
    }

    pr_info("Timer: %lu Hz (lapic=%lu)\n", (unsigned long)hz,
            (unsigned long)lapic_ticks_per_sec);
}

uint64_t arch_timer_ticks(void) {
    return arch_timer_get_ticks();
}

uint64_t arch_timer_freq(void) {
    return CONFIG_HZ;
}

uint64_t arch_timer_ticks_to_ns(uint64_t t) {
    uint64_t freq = arch_timer_freq();
    return (t * 1000000000ULL) / freq;
}

uint64_t arch_timer_ns_to_ticks(uint64_t ns) {
    uint64_t freq = arch_timer_freq();
    return (ns * freq) / 1000000000ULL;
}

void arch_timer_set_next(uint64_t t) {
    (void)t;
}

void arch_timer_ack(void) {}

uint64_t arch_timer_get_ticks(void) {
    return tick_policy_get_ticks();
}
