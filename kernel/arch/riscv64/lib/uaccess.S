/**
 * kernel/arch/riscv64/lib/uaccess.S - Safe user memory access primitives
 */

#include <asm/arch.h>

.macro EX_TABLE_ENTRY insn, fixup
    .pushsection __ex_table, "a"
    .balign 8
    .quad \insn, \fixup
    .popsection
.endm

.section .text
.global __arch_copy_from_user
.global __arch_copy_to_user
.global __arch_strncpy_from_user

__arch_copy_from_user:
    li t0, SSTATUS_SUM; csrs sstatus, t0
    mv t1, a0; mv t2, a1; mv t3, a2
1:  beqz t3, 2f
.L_ld: lb t4, 0(t2)
    sb t4, 0(t1)
    addi t1, t1, 1; addi t2, t2, 1; addi t3, t3, -1
    j 1b
2:  li a0, 0; csrc sstatus, t0; ret
.L_fix: csrc sstatus, t0; mv a0, t3; ret
    EX_TABLE_ENTRY .L_ld, .L_fix

__arch_copy_to_user:
    li t0, SSTATUS_SUM; csrs sstatus, t0
    mv t1, a0; mv t2, a1; mv t3, a2
1:  beqz t3, 2f
    lb t4, 0(t2)
.L_st: sb t4, 0(t1)
    addi t1, t1, 1; addi t2, t2, 1; addi t3, t3, -1
    j 1b
2:  li a0, 0; csrc sstatus, t0; ret
.L_st_fix: csrc sstatus, t0; mv a0, t3; ret
    EX_TABLE_ENTRY .L_st, .L_st_fix

__arch_strncpy_from_user:
    li t0, SSTATUS_SUM; csrs sstatus, t0
    mv t1, a0; mv t2, a1; mv t3, a2; li t5, 0
1:  beqz t3, 2f
.L_ns: lb t4, 0(t2)
    sb t4, 0(t1)
    beqz t4, 2f
    addi t1, t1, 1; addi t2, t2, 1; addi t5, t5, 1; addi t3, t3, -1
    j 1b
2:  mv a0, t5; csrc sstatus, t0; ret
.L_ns_fix: csrc sstatus, t0; li a0, -14; ret
    EX_TABLE_ENTRY .L_ns, .L_ns_fix