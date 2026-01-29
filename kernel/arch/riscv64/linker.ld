/**
 * kernel/arch/riscv64/linker.ld - RISC-V 64 linker script (high half)
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

KERNEL_PHYS_BASE = 0x80200000;
KERNEL_VIRT_BASE = 0xffffffff80000000;

SECTIONS
{
    . = KERNEL_VIRT_BASE;

    _kernel_start = .;

    .text : {
        *(.text.boot)
        *(.text .text.*)
    }

    . = ALIGN(4096);

    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)

        . = ALIGN(8);
        __ex_table_start = .;
        KEEP(*(__ex_table))
        __ex_table_end = .;
    }

    . = ALIGN(4096);

    .limine_requests : {
        KEEP(*(.limine_requests_start_marker))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end_marker))
    }

    . = ALIGN(4096);

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4096);

    _bss_start = .;
    .bss : {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    }
    _bss_end = .;

    . = ALIGN(4096);
    _kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
