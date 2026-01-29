/**
 * kernel/arch/aarch64/boot.S - AArch64 kernel entry point (Limine)
 */

#include <kairos/config.h>

.section .text.boot
.global _start
.global _secondary_start

_start:
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
