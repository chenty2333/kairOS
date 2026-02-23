/**
 * kernel/platform/board_qemu_virt_riscv64.c - QEMU virt RISC-V board
 */

#include <kairos/platform_core.h>

extern const struct irqchip_ops __attribute__((weak)) plic_ops;

static const struct platform_desc qemu_virt_riscv64 = {
    .name       = "qemu-virt-riscv64",
    .compatible = "riscv-virtio",
    .arch       = "riscv64",
    .num_early_mmio = 2,
    .early_mmio = {
        { .base = 0x0c000000, .size = 0x400000 },  /* PLIC + CLINT */
        { .base = 0x10000000, .size = 0x100000 },  /* VirtIO */
    },
    .irqchip = &plic_ops,
};

PLATFORM_REGISTER(qemu_virt_riscv64);
