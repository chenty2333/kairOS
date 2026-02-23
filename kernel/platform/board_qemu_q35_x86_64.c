/**
 * kernel/platform/board_qemu_q35_x86_64.c - QEMU Q35 x86_64 board
 */

#include <kairos/platform_core.h>

extern const struct irqchip_ops __attribute__((weak)) apic_ops;

static const struct platform_desc qemu_q35_x86_64 = {
    .name       = "qemu-q35-x86_64",
    .compatible = "",
    .arch       = "x86_64",
    .num_early_mmio = 2,
    .early_mmio = {
        { .base = 0xFEC00000, .size = 0x1000 },    /* IOAPIC */
        { .base = 0xFEE00000, .size = 0x1000 },    /* LAPIC */
    },
    .irqchip = &apic_ops,
};

PLATFORM_REGISTER(qemu_q35_x86_64);
