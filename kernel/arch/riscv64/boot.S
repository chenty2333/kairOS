/**
 * kernel/arch/riscv64/boot.S - RISC-V 64 kernel entry point
 */

#include <kairos/config.h>

.section .text.boot
.global _start
.global _secondary_start

/*
 * Boot CPU entry point
 */
_start:
    /* Disable interrupts */
    csrw sie, zero

    /* Set up stack pointer (16KB boot stack) */
    la sp, _boot_stack_top

    /* Clear BSS section */
    la t0, _bss_start
    la t1, _bss_end
1:
    bgeu t0, t1, 2f
    sd zero, 0(t0)
    addi t0, t0, 8
    j 1b
2:

    /* Jump to Limine bootstrap */
    call limine_bootstrap

_halt:
    wfi
    j _halt

/*
 * Secondary CPU entry point (Limine MP)
 * a0 = struct limine_mp_info *
 */
_secondary_start:
    /* Disable interrupts */
    csrw sie, zero

    /* Load logical CPU id from extra_argument */
    ld t0, 32(a0)
    mv tp, t0

    /* Calculate per-CPU stack address */
    la t1, _percpu_stacks
    li t2, CONFIG_KERNEL_STACK_SIZE
    mul t3, t0, t2
    add t1, t1, t3
    add sp, t1, t2

    /* Clear frame pointer */
    mv s0, zero

    /* Call secondary CPU initialization (a0 = cpu_id) */
    mv a0, t0
    call secondary_cpu_main

3:
    wfi
    j 3b

.section .bss

/* Boot stack (16KB for boot CPU) */
.align 16
_boot_stack:
    .space 16384
_boot_stack_top:

/*
 * Per-CPU stacks for all CPUs
 */
.align 16
.global _percpu_stacks
_percpu_stacks:
    .space CONFIG_KERNEL_STACK_SIZE * CONFIG_MAX_CPUS
