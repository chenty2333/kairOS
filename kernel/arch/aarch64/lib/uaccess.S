/**
 * kernel/arch/aarch64/lib/uaccess.S - Safe user memory access
 *
 * AArch64 does not need SSTATUS_SUM like RISC-V; user memory is
 * accessible from EL1 unless PAN is enabled (not used on QEMU virt).
 * Exception table entries catch faults and return remaining byte count.
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
    /* x0 = dst (kernel), x1 = src (user), x2 = len */
    mov x3, x2
1:
    cbz x3, 2f
.L_cfu_ld:
    ldrb w4, [x1], #1
    strb w4, [x0], #1
    subs x3, x3, #1
    b 1b
2:
    mov x0, #0
    ret
.L_cfu_fix:
    mov x0, x3          /* return remaining bytes */
    ret
    EX_TABLE_ENTRY .L_cfu_ld, .L_cfu_fix

.global __arch_copy_to_user
__arch_copy_to_user:
    /* x0 = dst (user), x1 = src (kernel), x2 = len */
    mov x3, x2
1:
    cbz x3, 2f
    ldrb w4, [x1], #1
.L_ctu_st:
    strb w4, [x0], #1
    subs x3, x3, #1
    b 1b
2:
    mov x0, #0
    ret
.L_ctu_fix:
    mov x0, x3
    ret
    EX_TABLE_ENTRY .L_ctu_st, .L_ctu_fix

.global __arch_strncpy_from_user
__arch_strncpy_from_user:
    /* x0 = dst, x1 = src (user), x2 = max_len */
    mov x3, x2
    mov x4, #0          /* bytes copied */
1:
    cbz x3, 2f
.L_sfu_ld:
    ldrb w5, [x1], #1
    strb w5, [x0], #1
    subs x3, x3, #1
    cbz w5, 2f
    add x4, x4, #1
    b 1b
2:
    mov x0, x4
    ret
.L_sfu_fix:
    mov x0, #-14         /* -EFAULT */
    ret
    EX_TABLE_ENTRY .L_sfu_ld, .L_sfu_fix
