/**
 * kernel/arch/riscv64/trapasm.S - Trap Entry/Exit
 */

.section .text

/* Macro to save/restore registers from trap frame */
.macro do_regs op, base
    \op x1, 0*8(\base);   \op x3, 2*8(\base);   \op x4, 3*8(\base)
    \op x5, 4*8(\base);   \op x6, 5*8(\base);   \op x7, 6*8(\base)
    \op x8, 7*8(\base);   \op x9, 8*8(\base);   \op x10, 9*8(\base)
    \op x11, 10*8(\base); \op x12, 11*8(\base); \op x13, 12*8(\base)
    \op x14, 13*8(\base); \op x15, 14*8(\base); \op x16, 15*8(\base)
    \op x17, 16*8(\base); \op x18, 17*8(\base); \op x19, 18*8(\base)
    \op x20, 19*8(\base); \op x21, 20*8(\base); \op x22, 21*8(\base)
    \op x23, 22*8(\base); \op x24, 23*8(\base); \op x25, 24*8(\base)
    \op x26, 25*8(\base); \op x27, 26*8(\base); \op x28, 27*8(\base)
    \op x29, 28*8(\base); \op x30, 29*8(\base); \op x31, 30*8(\base)
.endm

#define TF_SIZE (31*8 + 4*8)

.globl trap_entry
.align 4
trap_entry:
    csrrw sp, sscratch, sp
    bnez sp, 1f
    csrrw sp, sscratch, sp
1:
    addi sp, sp, -TF_SIZE
    do_regs sd, sp

    /* Save original SP from sscratch */
    csrr t0, sscratch
    beqz t0, 3f
    sd t0, 1*8(sp); csrw sscratch, zero; j 4f
3:  addi t0, sp, TF_SIZE; sd t0, 1*8(sp)
4:
    /* Save CSRs */
    csrr t0, sepc;    sd t0, 31*8(sp)
    csrr t0, sstatus; sd t0, 32*8(sp)
    csrr t0, scause;  sd t0, 33*8(sp)
    csrr t0, stval;   sd t0, 34*8(sp)

    mv a0, sp
    call trap_dispatch

.globl trap_return
trap_return:
    ld t0, 31*8(sp); csrw sepc, t0
    ld t1, 32*8(sp); csrw sstatus, t1

    /* Set sscratch if returning to user */
    andi t0, t1, (1 << 8)
    bnez t0, 1f
    addi t0, sp, TF_SIZE; csrw sscratch, t0
1:
    do_regs ld, sp
    ld sp, 1*8(sp)
    sret