/**
 * kernel/arch/x86_64/boot.S - x86_64 kernel entry point (Limine)
 */

#include <kairos/config.h>

.section .text.boot
.global _start
.global _secondary_start

_start:
    cli

    /* Set up a temporary stack */
    lea _boot_stack_top(%rip), %rsp

    /* Clear BSS */
    lea _bss_start(%rip), %rdi
    lea _bss_end(%rip), %rsi
1:
    cmp %rsi, %rdi
    jae 2f
    movq $0, (%rdi)
    add $8, %rdi
    jmp 1b
2:

    call limine_bootstrap

_halt:
    hlt
    jmp _halt

/*
 * Secondary CPU entry point (Limine MP)
 * rdi = struct limine_mp_info *
 */
_secondary_start:
    cli

    /* Load logical CPU id from extra_argument (offset 24) */
    mov 24(%rdi), %rax
    mov %rax, %rdi

    /* Set up per-CPU stack */
    lea _percpu_stacks(%rip), %rbx
    mov $CONFIG_KERNEL_STACK_SIZE, %rcx
    imul %rcx, %rax
    add %rax, %rbx
    add %rcx, %rbx
    mov %rbx, %rsp

    call secondary_cpu_main

3:
    hlt
    jmp 3b

.section .bss
.align 16
_boot_stack:
    .space 16384
_boot_stack_top:

.align 16
.global _percpu_stacks
_percpu_stacks:
    .space CONFIG_KERNEL_STACK_SIZE * CONFIG_MAX_CPUS
