/**
 * kernel/arch/x86_64/entry.c - x86_64 architecture entry logic
 */

#include <asm/arch.h>
#include <boot/limine.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/boot.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/types.h>

#define COM1_PORT 0x3f8

#define GDT_KERNEL_CODE 0x08
#define GDT_KERNEL_DATA 0x10
#define GDT_USER_CODE   0x18
#define GDT_USER_DATA   0x20
#define GDT_TSS         0x28

struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t gran;
    uint8_t base_high;
} __attribute__((packed));

struct gdt_tss_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t gran;
    uint8_t base_high;
    uint32_t base_upper;
    uint32_t reserved;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

struct tss {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap;
} __attribute__((packed));

struct gdt_table {
    struct gdt_entry entries[5];
    struct gdt_tss_entry tss;
} __attribute__((aligned(16)));

static struct gdt_table cpu_gdt[CONFIG_MAX_CPUS];
static struct tss cpu_tss[CONFIG_MAX_CPUS];

static bool serial_inited = false;

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
    if (!serial_inited) {
        serial_init();
        serial_inited = true;
    }
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

static void gdt_set_entry(struct gdt_entry *e, uint32_t base, uint32_t limit,
                          uint8_t access, uint8_t gran) {
    e->limit_low = (uint16_t)(limit & 0xffff);
    e->base_low = (uint16_t)(base & 0xffff);
    e->base_mid = (uint8_t)((base >> 16) & 0xff);
    e->access = access;
    e->gran = (uint8_t)(((limit >> 16) & 0x0f) | (gran & 0xf0));
    e->base_high = (uint8_t)((base >> 24) & 0xff);
}

static void gdt_set_tss(struct gdt_tss_entry *e, uint64_t base,
                        uint32_t limit) {
    e->limit_low = (uint16_t)(limit & 0xffff);
    e->base_low = (uint16_t)(base & 0xffff);
    e->base_mid = (uint8_t)((base >> 16) & 0xff);
    e->access = 0x89; /* Present, type 9 (available 64-bit TSS) */
    e->gran = (uint8_t)((limit >> 16) & 0x0f);
    e->base_high = (uint8_t)((base >> 24) & 0xff);
    e->base_upper = (uint32_t)(base >> 32);
    e->reserved = 0;
}

static void x86_gdt_init(int cpu_id) {
    if (cpu_id < 0 || cpu_id >= CONFIG_MAX_CPUS)
        cpu_id = 0;

    struct gdt_table *gdt = &cpu_gdt[cpu_id];
    struct tss *tss = &cpu_tss[cpu_id];
    memset(gdt, 0, sizeof(*gdt));
    memset(tss, 0, sizeof(*tss));

    gdt_set_entry(&gdt->entries[0], 0, 0, 0, 0);
    gdt_set_entry(&gdt->entries[1], 0, 0xfffff, 0x9A, 0xA0);
    gdt_set_entry(&gdt->entries[2], 0, 0xfffff, 0x92, 0xC0);
    gdt_set_entry(&gdt->entries[3], 0, 0xfffff, 0xFA, 0xA0);
    gdt_set_entry(&gdt->entries[4], 0, 0xfffff, 0xF2, 0xC0);

    tss->iomap = sizeof(*tss);
    gdt_set_tss(&gdt->tss, (uint64_t)tss, sizeof(*tss) - 1);

    struct gdt_ptr gdtr = {
        .limit = (uint16_t)(sizeof(*gdt) - 1),
        .base = (uint64_t)gdt,
    };
    __asm__ __volatile__("lgdt %0" : : "m"(gdtr));

    uint16_t data = GDT_KERNEL_DATA;
    uint16_t zero = 0;
    __asm__ __volatile__(
        "mov %0, %%ds\n"
        "mov %0, %%es\n"
        "mov %0, %%ss\n"
        :
        : "r"(data)
        : "memory");
    __asm__ __volatile__(
        "mov %0, %%fs\n"
        "mov %0, %%gs\n"
        :
        : "r"(zero)
        : "memory");

    __asm__ __volatile__(
        "pushq %[cs]\n"
        "leaq 1f(%%rip), %%rax\n"
        "pushq %%rax\n"
        "lretq\n"
        "1:\n"
        :
        : [cs] "i"(GDT_KERNEL_CODE)
        : "rax", "memory");

    uint16_t tss_sel = GDT_TSS;
    __asm__ __volatile__("ltr %0" : : "r"(tss_sel));
}

void arch_tss_set_rsp0(uint64_t rsp0) {
    int cpu_id = arch_cpu_id();
    if (cpu_id < 0 || cpu_id >= CONFIG_MAX_CPUS)
        cpu_id = 0;
    cpu_tss[cpu_id].rsp0 = rsp0;
}

void arch_cpu_init(int cpu_id) {
    x86_gdt_init(cpu_id);
    serial_init();
    serial_inited = true;
    if (cpu_id < CONFIG_MAX_CPUS) {
        cpu_id_slots[cpu_id] = (uint64_t)cpu_id;
        wrmsr(0xC0000101, (uint64_t)&cpu_id_slots[cpu_id]); /* IA32_GS_BASE */
    }
    uint64_t rsp;
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(rsp));
    arch_tss_set_rsp0(rsp);
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
