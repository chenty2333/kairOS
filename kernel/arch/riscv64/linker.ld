/**
 * Kairos kernel linker script for RISC-V 64
 *
 * Memory layout on QEMU virt:
 *   0x80000000 - 0x80200000: OpenSBI firmware
 *   0x80200000+: Kernel load address
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

KERNEL_BASE = 0x80200000;

SECTIONS
{
    . = KERNEL_BASE;

    /* Kernel start symbol */
    _kernel_start = .;

    /* Code section */
    .text : {
        *(.text.boot)       /* Boot code first */
        *(.text .text.*)
    }

    . = ALIGN(4096);

    /* Read-only data */
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        
        /* Exception table */
        . = ALIGN(8);
        __ex_table_start = .;
        KEEP(*(__ex_table))
        __ex_table_end = .;
    }

    . = ALIGN(4096);

    /* Initialized data */
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4096);

    /* BSS (uninitialized data) */
    _bss_start = .;
    .bss : {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    }
    _bss_end = .;

    . = ALIGN(4096);

    /* Kernel end symbol */
    _kernel_end = .;

    /* Discard sections we don't need */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
