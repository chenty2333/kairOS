/**
 * kernel/arch/aarch64/entry.c - AArch64 architecture entry logic
 */

#include <asm/arch.h>
#include <boot/limine.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/boot.h>
#include <kairos/console.h>
#include <kairos/fdt.h>
#include <kairos/init.h>
#include <kairos/platform_core.h>
#include <kairos/sched.h>
#include <kairos/types.h>

#define PL011_BASE_FALLBACK 0x09000000UL
#define PL011_DR   0x00
#define PL011_FR   0x18
#define PL011_IMSC 0x38
#define PL011_ICR  0x44
#define PL011_FR_TXFF (1 << 5)
#define PL011_FR_RXFE (1 << 4)
#define PL011_INT_RX (1U << 4)
#define PL011_INT_RT (1U << 6)
// WARN: QEMU virt wires PL011 RX to GIC SPI 33.
#define PL011_IRQ_FALLBACK 33

static bool early_console_ready;
static bool pl011_rx_irq_inited;
static bool pl011_cfg_inited;
static uintptr_t pl011_base = PL011_BASE_FALLBACK;
static int pl011_irq = PL011_IRQ_FALLBACK;
static bool pl011_irq_available = true;

static int pl011_irq_to_virq(int irq)
{
    if (irq <= 0)
        return irq;
    const struct platform_desc *plat = platform_get();
    if (!plat || !plat->irqchip)
        return irq;
    int virq = platform_irq_domain_map(plat->irqchip, (uint32_t)irq);
    return (virq >= 0) ? virq : irq;
}

void aarch64_early_console_set_ready(bool ready) {
    early_console_ready = ready;
}

static inline volatile uint32_t *pl011_regs(void) {
    const struct boot_info *bi = boot_info_get();
    if (!early_console_ready || !bi || !bi->hhdm_offset)
        return NULL;
    return (volatile uint32_t *)(uintptr_t)(bi->hhdm_offset + pl011_base);
}

static inline void pl011_putc(char c) {
    volatile uint32_t *uart = pl011_regs();
    if (!uart)
        return;
    while (uart[PL011_FR / 4] & PL011_FR_TXFF)
        ;
    uart[PL011_DR / 4] = (uint32_t)c;
}

static inline int pl011_getc_nb(void) {
    volatile uint32_t *uart = pl011_regs();
    if (!uart)
        return -1;
    if (uart[PL011_FR / 4] & PL011_FR_RXFE)
        return -1;
    return (int)(uart[PL011_DR / 4] & 0xffU);
}

static void pl011_rx_irq_handler(void *arg) {
    (void)arg;
    console_poll_input();
    volatile uint32_t *uart = pl011_regs();
    if (uart)
        uart[PL011_ICR / 4] = PL011_INT_RX | PL011_INT_RT;
}

void arch_early_putchar(char c) {
    if (c == '\n')
        pl011_putc('\r');
    pl011_putc(c);
}

int arch_early_getchar(void) {
    int ch;
    while ((ch = pl011_getc_nb()) < 0) {
    }
    return ch;
}

int arch_early_getchar_nb(void) {
    return pl011_getc_nb();
}

static void pl011_try_configure_from_fdt(void) {
    if (pl011_cfg_inited)
        return;

    const void *dtb = init_boot_dtb();
    if (!dtb)
        return;

    bool irq_state = arch_irq_save();
    if (pl011_cfg_inited) {
        arch_irq_restore(irq_state);
        return;
    }
    pl011_cfg_inited = true;
    arch_irq_restore(irq_state);

    static const char *const compat_list[] = {
        "arm,pl011",
        "arm,sbsa-uart",
    };
    struct fdt_uart_info info;
    if (fdt_get_stdout_uart(dtb, compat_list, ARRAY_SIZE(compat_list), &info) !=
        0)
        return;

    pl011_base = (uintptr_t)info.base;
    pl011_irq_available = info.irq > 0;
    if (pl011_irq_available)
        pl011_irq = info.irq;
}

void arch_console_input_init(void) {
    pl011_try_configure_from_fdt();

    volatile uint32_t *uart = pl011_regs();
    if (!uart)
        return;

    bool irq_state = arch_irq_save();
    if (pl011_rx_irq_inited) {
        arch_irq_restore(irq_state);
        return;
    }
    pl011_rx_irq_inited = true;
    arch_irq_restore(irq_state);

    uart[PL011_ICR / 4] = 0x7ff;
    if (pl011_irq_available) {
        uart[PL011_IMSC / 4] |= PL011_INT_RX | PL011_INT_RT;
        arch_irq_register(pl011_irq_to_virq(pl011_irq),
                          pl011_rx_irq_handler, NULL);
    } else {
        uart[PL011_IMSC / 4] &= ~(PL011_INT_RX | PL011_INT_RT);
    }
    console_poll_input();
}

void arch_cpu_halt(void) {
    __asm__ __volatile__("wfi");
}

void arch_cpu_relax(void) {
    __asm__ __volatile__("yield" ::: "memory");
}

/* PSCI function IDs (SMCCC convention) */
#define PSCI_SYSTEM_OFF  0x84000008
#define PSCI_SYSTEM_RESET 0x84000009

static inline int32_t psci_call(uint32_t fn) {
    register uint64_t x0 __asm__("x0") = fn;
    __asm__ __volatile__("hvc #0" : "+r"(x0) :: "x1", "x2", "x3");
    return (int32_t)x0;
}

noreturn void arch_cpu_shutdown(void) {
    psci_call(PSCI_SYSTEM_OFF);
    /* If PSCI fails, fall back to wfi loop */
    for (;;)
        arch_cpu_halt();
}

noreturn void arch_cpu_reset(void) {
    psci_call(PSCI_SYSTEM_RESET);
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

    /* Ensure VBAR_EL1 is set (secondary CPUs need this too) */
    extern void vector_table(void);
    __asm__ __volatile__("msr vbar_el1, %0" :: "r"(&vector_table));
}

extern void gic_send_sgi(uint32_t cpu, uint32_t intid);

void arch_send_ipi(int cpu, int type) {
    struct percpu_data *data = sched_cpu_data(cpu);
    if (data)
        __sync_fetch_and_or(&data->ipi_pending_mask, (1 << type));
    gic_send_sgi((uint32_t)cpu, 1);
}
