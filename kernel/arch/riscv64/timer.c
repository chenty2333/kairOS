/**
 * kernel/arch/riscv64/timer.c - RISC-V 64 Timer Implementation
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/tick.h>
#include <kairos/types.h>

#define SBI_EXT_TIME 0x54494D45
#define TIMER_FREQ 10000000 /* 10 MHz */
#define RISCV_TIMER_VIRQ 0

static uint64_t timer_freq = TIMER_FREQ;
static uint64_t ticks_per_int;
static bool timer_irq_registered;

static int riscv_timer_irq_virq(void)
{
    return RISCV_TIMER_VIRQ;
}

const struct timer_ops riscv_timer_ops = {
    .irq = riscv_timer_irq_virq,
};

static void riscv_timer_irq_handler(void *arg,
                                    const struct trap_core_event *ev) {
    (void)arg;
    sbi_call(SBI_EXT_TIME, 0, rdtime() + ticks_per_int, 0, 0);
    tick_policy_on_timer_irq(ev);
}

void arch_timer_init(uint64_t hz) {
    if (!hz)
        hz = CONFIG_HZ;
    ticks_per_int = timer_freq / hz;
    sbi_call(SBI_EXT_TIME, 0, rdtime() + ticks_per_int, 0, 0);

    bool irq_state = arch_irq_save();
    bool need_register = !timer_irq_registered;
    if (need_register)
        timer_irq_registered = true;
    arch_irq_restore(irq_state);
    int timer_virq = platform_timer_irq();
    if (timer_virq < 0)
        timer_virq = RISCV_TIMER_VIRQ;

    if (need_register) {
        (void)arch_request_irq_ex(
            timer_virq, riscv_timer_irq_handler, NULL,
            IRQ_FLAG_TRIGGER_LEVEL | IRQ_FLAG_PER_CPU | IRQ_FLAG_TIMER |
                IRQ_FLAG_NO_CHIP);
    } else {
        arch_irq_enable_nr(timer_virq);
    }

    pr_info("Timer: %lu Hz, interval %lu ticks\n", (unsigned long)timer_freq,
            (unsigned long)ticks_per_int);
}

uint64_t arch_timer_ticks(void) {
    return rdtime();
}
uint64_t arch_timer_freq(void) {
    return timer_freq;
}
uint64_t arch_timer_ticks_to_ns(uint64_t t) {
    return (t * 1000000000UL) / timer_freq;
}
uint64_t arch_timer_ns_to_ticks(uint64_t ns) {
    return (ns * timer_freq) / 1000000000UL;
}
void arch_timer_set_next(uint64_t t) {
    sbi_call(SBI_EXT_TIME, 0, rdtime() + t, 0, 0);
}
void arch_timer_ack(void) {}

uint64_t arch_timer_get_ticks(void) {
    return tick_policy_get_ticks();
}
