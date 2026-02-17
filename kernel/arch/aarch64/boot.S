/**
 * kernel/arch/aarch64/boot.S - AArch64 kernel entry point (Limine)
 *
 * Handles EL2→EL1 transition, early system register init, BSS clear,
 * then jumps to limine_bootstrap.
 */

#include <kairos/config.h>

.section .text.boot
.global _start
.global _secondary_start

/*
 * Macro: drop from EL2 to EL1 if needed.
 * Clobbers x0, x1. On return we are guaranteed EL1h.
 */
.macro DROP_TO_EL1
    mrs x0, CurrentEL
    lsr x0, x0, #2          /* EL field is bits [3:2] */
    cmp x0, #2
    b.ne 90f                /* already EL1 (or EL0/EL3) */

    /* Configure EL1 to use AArch64 */
    mrs x1, hcr_el2
    orr x1, x1, #(1 << 31) /* HCR_EL2.RW = 1 (EL1 is AArch64) */
    msr hcr_el2, x1

    /* Return to EL1h with DAIF masked */
    mov x1, #0x3c5          /* EL1h | DAIF mask */
    msr spsr_el2, x1
    adr x1, 90f
    msr elr_el2, x1
    eret
90:
.endm

/*
 * Macro: early system register setup (must run at EL1).
 * Clobbers x0.
 */
.macro INIT_SYSREGS
    /* SCTLR_EL1: MMU off, caches off, little-endian */
    msr sctlr_el1, xzr
    isb

    /* CPACR_EL1: FPEN=0b11 — no FP/SIMD traps */
    mov x0, #(3 << 20)
    msr cpacr_el1, x0

    /* Set early VBAR_EL1 so any exception before arch_trap_init() is caught */
    adrp x0, vector_table
    add  x0, x0, :lo12:vector_table
    msr vbar_el1, x0
    isb
.endm

_start:
    DROP_TO_EL1
    INIT_SYSREGS

    ldr x0, =_boot_stack_top
    mov sp, x0

    /* Clear BSS */
    ldr x0, =_bss_start
    ldr x1, =_bss_end
1:
    cmp x0, x1
    b.hs 2f
    str xzr, [x0], #8
    b 1b
2:

    bl limine_bootstrap

3:
    wfi
    b 3b

/* Secondary CPU entry (Limine MP) */
_secondary_start:
    /* x0 = struct limine_mp_info * */
    DROP_TO_EL1
    INIT_SYSREGS

    ldr x1, [x0, #32] /* extra_argument */
    mov x18, x1

    ldr x2, =_percpu_stacks
    mov x3, #CONFIG_KERNEL_STACK_SIZE
    madd x2, x1, x3, x2
    add x2, x2, x3
    mov sp, x2

    mov x0, x1
    bl secondary_cpu_main

4:
    wfi
    b 4b

.section .bss
.align 16
_boot_stack:
    .space 16384
_boot_stack_top:

.align 16
.global _percpu_stacks
_percpu_stacks:
    .space CONFIG_KERNEL_STACK_SIZE * CONFIG_MAX_CPUS
