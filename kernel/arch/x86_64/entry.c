/**
 * kernel/arch/x86_64/entry.c - x86_64 architecture entry logic
 */

#include <asm/arch.h>
#include <boot/limine.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/boot.h>
#include <kairos/sched.h>
#include <kairos/types.h>

#define COM1_PORT 0x3f8

static inline void serial_init(void) {
    outb(COM1_PORT + 1, 0x00);
    outb(COM1_PORT + 3, 0x80);
    outb(COM1_PORT + 0, 0x03);
    outb(COM1_PORT + 1, 0x00);
    outb(COM1_PORT + 3, 0x03);
    outb(COM1_PORT + 2, 0xC7);
    outb(COM1_PORT + 4, 0x0B);
}

static inline int serial_tx_ready(void) {
    return inb(COM1_PORT + 5) & 0x20;
}

void arch_early_putchar(char c) {
    if (c == '\n') {
        arch_early_putchar('\r');
    }
    while (!serial_tx_ready())
        ;
    outb(COM1_PORT + 0, (uint8_t)c);
}

void arch_cpu_halt(void) {
    __asm__ __volatile__("hlt");
}

void arch_cpu_relax(void) {
    __asm__ __volatile__("pause" ::: "memory");
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
    __asm__ __volatile__("sti" ::: "memory");
}

void arch_irq_disable(void) {
    __asm__ __volatile__("cli" ::: "memory");
}

bool arch_irq_save(void) {
    uint64_t flags;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    return (flags & (1ULL << 9)) != 0;
}

void arch_irq_restore(bool state) {
    if (state)
        arch_irq_enable();
}

bool arch_irq_enabled(void) {
    uint64_t flags;
    __asm__ __volatile__("pushfq; popq %0" : "=r"(flags));
    return (flags & (1ULL << 9)) != 0;
}

void arch_breakpoint(void) {
    __asm__ __volatile__("int3");
}

static inline void wrmsr(uint32_t msr, uint64_t val) {
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ __volatile__("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

static uint64_t cpu_id_slots[CONFIG_MAX_CPUS];

void arch_cpu_init(int cpu_id) {
    serial_init();
    if (cpu_id < CONFIG_MAX_CPUS) {
        cpu_id_slots[cpu_id] = (uint64_t)cpu_id;
        wrmsr(0xC0000101, (uint64_t)&cpu_id_slots[cpu_id]); /* IA32_GS_BASE */
    }
}

extern void lapic_send_ipi(uint32_t apic_id, uint32_t vector);

void arch_send_ipi(int cpu, int type) {
    struct percpu_data *data = sched_cpu_data(cpu);
    if (data)
        __sync_fetch_and_or(&data->ipi_pending_mask, (1 << type));
    const struct boot_info *bi = boot_info_get();
    uint32_t apic_id = bi ? (uint32_t)bi->cpus[cpu].hw_id : (uint32_t)cpu;
    lapic_send_ipi(apic_id, 0xF0);
}
