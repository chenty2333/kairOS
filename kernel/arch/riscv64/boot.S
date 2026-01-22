/**
 * boot.S - RISC-V 64 kernel entry point
 *
 * This is the first code executed after OpenSBI hands control to the kernel.
 * Entry conditions (from OpenSBI):
 *   a0 = hartid (CPU ID)
 *   a1 = device tree blob (DTB) pointer
 */

.section .text.boot
.global _start

_start:
    /* Disable interrupts */
    csrw sie, zero

    /* Check hartid - only hart 0 boots, others wait */
    bnez a0, _secondary_hart

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

    /* Save hartid and DTB pointer for kernel_main */
    /* a0 = hartid (already 0) */
    /* a1 = dtb pointer (preserved) */

    /* Jump to C code */
    call kernel_main

    /* Should not return, but if it does, halt */
_halt:
    wfi
    j _halt

/* Secondary harts wait here for now */
_secondary_hart:
    wfi
    j _secondary_hart

/* Boot stack (16KB) */
.section .bss
.align 16
_boot_stack:
    .space 16384
_boot_stack_top:
