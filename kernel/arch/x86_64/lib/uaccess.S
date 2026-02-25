/**
 * kernel/arch/x86_64/lib/uaccess.S - User memory copy
 */

.macro EX_TABLE_ENTRY insn, fixup
    .pushsection __ex_table, "a"
    .balign 8
    .quad \insn, \fixup
    .popsection
.endm

.section .text

.global __arch_copy_from_user
__arch_copy_from_user:
    mov %rdx, %rcx
.L_cfu_rep:
    rep movsb
    xor %rax, %rax
    ret
.L_cfu_fix:
    mov %rcx, %rax
    ret
    EX_TABLE_ENTRY .L_cfu_rep, .L_cfu_fix

.global __arch_copy_to_user
__arch_copy_to_user:
    mov %rdx, %rcx
.L_ctu_rep:
    rep movsb
    xor %rax, %rax
    ret
.L_ctu_fix:
    mov %rcx, %rax
    ret
    EX_TABLE_ENTRY .L_ctu_rep, .L_ctu_fix

.global __arch_strncpy_from_user
__arch_strncpy_from_user:
    xor %rax, %rax
    mov %rdx, %rcx
1:
    test %rcx, %rcx
    jz 2f
.L_sfu_ld:
    movb (%rsi), %dl
    movb %dl, (%rdi)
    inc %rsi
    inc %rdi
    dec %rcx
    test %dl, %dl
    jz 2f
    inc %rax
    jmp 1b
2:
    ret
.L_sfu_fix:
    mov $-14, %rax
    ret
    EX_TABLE_ENTRY .L_sfu_ld, .L_sfu_fix
