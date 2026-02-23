/**
 * kernel/platform/board_qemu_virt_aarch64.c - QEMU virt AArch64 board
 */

#include <kairos/platform_core.h>

static const struct platform_desc qemu_virt_aarch64 = {
    .name       = "qemu-virt-aarch64",
    .compatible = "linux,dummy-virt",
    .arch       = "aarch64",
    .num_early_mmio = 3,
    .early_mmio = {
        { .base = 0x08000000, .size = 0x100000 },  /* GIC */
        { .base = 0x09000000, .size = 0x1000   },  /* PL011 UART */
        { .base = 0x0A000000, .size = 0x4000   },  /* VirtIO MMIO */
    },
};

PLATFORM_REGISTER(qemu_virt_aarch64);
