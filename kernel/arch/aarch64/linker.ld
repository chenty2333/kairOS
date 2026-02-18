/**
 * kernel/arch/aarch64/linker.ld - AArch64 linker script (high half)
 */

OUTPUT_ARCH(aarch64)
ENTRY(_start)

KERNEL_PHYS_BASE = 0x40000000;
/* Limine requires 64-bit higher-half PT_LOAD VAs >= 0xffffffff80000000. */
KERNEL_VIRT_BASE = 0xffffffff80000000;

SECTIONS
{
    . = KERNEL_VIRT_BASE;

    _kernel_start = .;

    .text : AT(ADDR(.text) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE) {
        *(.text.boot)
        *(.text .text.*)
    }

    . = ALIGN(4096);

    .rodata : AT(ADDR(.rodata) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)

        . = ALIGN(8);
        __ex_table_start = .;
        KEEP(*(__ex_table))
        __ex_table_end = .;
    }

    . = ALIGN(4096);

    .limine_requests : AT(ADDR(.limine_requests) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE) {
        KEEP(*(.limine_requests_start_marker))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end_marker))
    }

    . = ALIGN(4096);

    .data : AT(ADDR(.data) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4096);

    _bss_start = .;
    .bss : AT(ADDR(.bss) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE) {
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
