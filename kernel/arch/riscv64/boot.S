/**
 * boot.S - RISC-V 64 kernel entry point
 *
 * This is the first code executed after OpenSBI hands control to the kernel.
 * Entry conditions (from OpenSBI):
 *   a0 = hartid (CPU ID)
 *   a1 = device tree blob (DTB) pointer
 *
 * Note: Boot hart may not be hart 0! OpenSBI can choose any hart to boot.
 */

#include <kairos/config.h>

.section .text.boot
.global _start
.global _secondary_start
.global boot_hartid

/*
 * Boot CPU entry point
 * Only the boot hart reaches here; others are parked by OpenSBI.
 */
_start:
    /* Disable interrupts */
    csrw sie, zero

    /* Store hartid in tp register for arch_cpu_id() */
    mv tp, a0

    /* Save boot hartid for later (secondary CPUs need to know) */
    la t0, boot_hartid
    sw a0, 0(t0)

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

    /* a0 = hartid, a1 = dtb pointer (both preserved) */

    /* Jump to C code */
    call kernel_main

    /* Should not return, but if it does, halt */
_halt:
    wfi
    j _halt

/*
 * Secondary CPU entry point
 * Called by SBI HSM when a secondary hart is started.
 * Entry conditions:
 *   a0 = hartid
 *   a1 = opaque value (unused)
 */
_secondary_start:
    /* Disable interrupts */
    csrw sie, zero

    /* Store hartid in tp register */
    mv tp, a0

    /* Calculate per-CPU stack address */
    /* We use hartid as index, each CPU gets STACK_SIZE bytes */
    la t0, _percpu_stacks
    li t1, CONFIG_KERNEL_STACK_SIZE
    mul t2, a0, t1          /* offset = hartid * STACK_SIZE */
    add t0, t0, t2          /* base + offset */
    add sp, t0, t1          /* sp = base + offset + STACK_SIZE (stack grows down) */

    /* Clear frame pointer */
    mv s0, zero

    /* Call secondary CPU initialization (a0 = hartid) */
    call secondary_cpu_main

    /* Should not return */
3:
    wfi
    j 3b

/*
 * Data section
 */
.section .data
.align 4
boot_hartid:
    .word 0

/*
 * BSS section
 */
.section .bss

/* Boot stack (16KB for boot CPU) */
.align 16
_boot_stack:
    .space 16384
_boot_stack_top:

/*
 * Per-CPU stacks for all CPUs (including boot CPU for uniformity in secondary path)
 * Layout: hartid 0, hartid 1, ..., hartid (MAX-1)
 */
.align 16
.global _percpu_stacks
_percpu_stacks:
    .space CONFIG_KERNEL_STACK_SIZE * CONFIG_MAX_CPUS
