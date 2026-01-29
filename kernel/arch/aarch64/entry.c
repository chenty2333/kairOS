/**
 * kernel/arch/aarch64/entry.c - AArch64 architecture entry logic
 */

#include <asm/arch.h>
#include <boot/limine.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/boot.h>
#include <kairos/sched.h>
#include <kairos/types.h>

#define PL011_BASE 0x09000000UL
#define PL011_DR   0x00
#define PL011_FR   0x18
#define PL011_FR_TXFF (1 << 5)

static inline void pl011_putc(char c) {
    volatile uint32_t *uart = (volatile uint32_t *)phys_to_virt(PL011_BASE);
    while (uart[PL011_FR / 4] & PL011_FR_TXFF)
        ;
    uart[PL011_DR / 4] = (uint32_t)c;
}

void arch_early_putchar(char c) {
    if (c == '\n')
        pl011_putc('\r');
    pl011_putc(c);
}

void arch_cpu_halt(void) {
    __asm__ __volatile__("wfi");
}

void arch_cpu_relax(void) {
    __asm__ __volatile__("yield" ::: "memory");
}

noreturn void arch_cpu_shutdown(void) {
    for (;;)
        arch_cpu_halt();
}

noreturn void arch_cpu_reset(void) {
    for (;;)
        arch_cpu_halt();
}

void arch_irq_enable(void) {
    __asm__ __volatile__("msr daifclr, #2" ::: "memory");
}

void arch_irq_disable(void) {
    __asm__ __volatile__("msr daifset, #2" ::: "memory");
}

bool arch_irq_save(void) {
    uint64_t daif;
    __asm__ __volatile__("mrs %0, daif" : "=r"(daif));
    arch_irq_disable();
    return (daif & (1 << 7)) == 0;
}

void arch_irq_restore(bool state) {
    if (state)
        arch_irq_enable();
}

bool arch_irq_enabled(void) {
    uint64_t daif;
    __asm__ __volatile__("mrs %0, daif" : "=r"(daif));
    return (daif & (1 << 7)) == 0;
}

void arch_breakpoint(void) {
    __asm__ __volatile__("brk #0");
}

void arch_cpu_init(int cpu_id) {
    __asm__ __volatile__("msr tpidr_el1, %0" :: "r"((uint64_t)cpu_id));
}

extern void gic_send_sgi(uint32_t cpu, uint32_t intid);

void arch_send_ipi(int cpu, int type) {
    struct percpu_data *data = sched_cpu_data(cpu);
    if (data)
        __sync_fetch_and_or(&data->ipi_pending_mask, (1 << type));
    gic_send_sgi((uint32_t)cpu, 1);
}
