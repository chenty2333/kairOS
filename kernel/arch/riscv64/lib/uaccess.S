/*
 * uaccess.S - Safe user memory access primitives with exception tables
 */

/* RISC-V Status Register bits */
#define SSTATUS_SUM (1 << 18)

    .section .text
    .global __arch_copy_from_user
    .global __arch_copy_to_user
    .global __arch_strncpy_from_user

/*
 * Macro to create exception table entry
 * @insn_label: Label of the faulting instruction
 * @fixup_label: Label to jump to if fault occurs
 */
.macro EX_TABLE_ENTRY insn_label, fixup_label
    .pushsection __ex_table, "a"
    .balign 8
    .quad \insn_label, \fixup_label
    .popsection
.endm

/*
 * unsigned long __arch_copy_from_user(void *to, const void *from, unsigned long n)
 * a0 = to, a1 = from, a2 = n
 * Returns: number of bytes NOT copied (0 on success)
 */
__arch_copy_from_user:
    /* Enable SUM */
    li t0, SSTATUS_SUM
    csrs sstatus, t0

    /* Save original count for return calculation if needed */
    mv t1, a0   /* t1 = dst */
    mv t2, a1   /* t2 = src */
    mv t3, a2   /* t3 = count */

    /* Check for zero length */
    beqz t3, 2f

1:
    /* Load byte from user (src) - FAULTABLE */
.L_copy_from_user_load:
    lb t4, 0(t2)
    
    /* Store byte to kernel (dst) - safe */
    sb t4, 0(t1)

    addi t1, t1, 1
    addi t2, t2, 1
    addi t3, t3, -1
    bnez t3, 1b

2:
    /* Success, return 0 */
    li a0, 0
    
    /* Disable SUM */
    csrc sstatus, t0
    ret

/* Fixup handler */
.L_copy_from_user_fixup:
    /* Disable SUM */
    csrc sstatus, t0
    /* Return remaining bytes (t3) */
    mv a0, t3
    ret

    /* Exception table entries */
    EX_TABLE_ENTRY .L_copy_from_user_load, .L_copy_from_user_fixup

/*
 * unsigned long __arch_copy_to_user(void *to, const void *from, unsigned long n)
 * a0 = to, a1 = from, a2 = n
 */
__arch_copy_to_user:
    li t0, SSTATUS_SUM
    csrs sstatus, t0

    mv t1, a0   /* dst */
    mv t2, a1   /* src */
    mv t3, a2   /* count */

    beqz t3, 2f

1:
    /* Load byte from kernel - safe */
    lb t4, 0(t2)

    /* Store byte to user - FAULTABLE */
.L_copy_to_user_store:
    sb t4, 0(t1)

    addi t1, t1, 1
    addi t2, t2, 1
    addi t3, t3, -1
    bnez t3, 1b

2:
    li a0, 0
    csrc sstatus, t0
    ret

.L_copy_to_user_fixup:
    csrc sstatus, t0
    mv a0, t3
    ret

    EX_TABLE_ENTRY .L_copy_to_user_store, .L_copy_to_user_fixup

/*
 * long __arch_strncpy_from_user(char *dst, const char *src, long count)
 * Returns: length of string copied (excluding null), or -EFAULT
 */
__arch_strncpy_from_user:
    li t0, SSTATUS_SUM
    csrs sstatus, t0

    mv t1, a0   /* dst */
    mv t2, a1   /* src */
    mv t3, a2   /* count / remaining */
    li t5, 0    /* copied length */

    beqz t3, 2f

1:
.L_strncpy_load:
    lb t4, 0(t2)
    sb t4, 0(t1)

    beqz t4, 3f /* Found null */

    addi t1, t1, 1
    addi t2, t2, 1
    addi t5, t5, 1
    addi t3, t3, -1
    bnez t3, 1b

2:
    /* Count exhausted, return count */
    mv a0, t5
    csrc sstatus, t0
    ret

3:
    /* Found null, return length */
    mv a0, t5
    csrc sstatus, t0
    ret

.L_strncpy_fixup:
    csrc sstatus, t0
    li a0, -14 /* -EFAULT */
    ret

    EX_TABLE_ENTRY .L_strncpy_load, .L_strncpy_fixup
