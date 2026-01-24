/**
 * trap.S - RISC-V 64 Trap Entry/Exit
 *
 * This file contains the low-level trap handling code that:
 * 1. Saves all registers to the trap frame
 * 2. Calls the C trap handler
 * 3. Restores registers and returns from trap
 *
 * RISC-V trap handling:
 * - stvec points to trap_entry
 * - On trap, hardware sets:
 *   - sepc = PC at trap
 *   - scause = cause of trap
 *   - stval = trap-specific value (fault address, etc.)
 *   - sstatus.SPP = previous privilege mode
 */

.section .text

/* Trap frame offsets (must match struct trap_frame in trap.c) */
.equ TF_RA,     0
.equ TF_SP,     8
.equ TF_GP,     16
.equ TF_TP,     24
.equ TF_T0,     32
.equ TF_T1,     40
.equ TF_T2,     48
.equ TF_S0,     56
.equ TF_S1,     64
.equ TF_A0,     72
.equ TF_A1,     80
.equ TF_A2,     88
.equ TF_A3,     96
.equ TF_A4,     104
.equ TF_A5,     112
.equ TF_A6,     120
.equ TF_A7,     128
.equ TF_S2,     136
.equ TF_S3,     144
.equ TF_S4,     152
.equ TF_S5,     160
.equ TF_S6,     168
.equ TF_S7,     176
.equ TF_S8,     184
.equ TF_S9,     192
.equ TF_S10,    200
.equ TF_S11,    208
.equ TF_T3,     216
.equ TF_T4,     224
.equ TF_T5,     232
.equ TF_T6,     240
.equ TF_SEPC,   248
.equ TF_SSTATUS, 256
.equ TF_SCAUSE, 264
.equ TF_STVAL,  272
.equ TF_SIZE,   280

/**
 * trap_entry - Entry point for all traps
 *
 * When we arrive here:
 * - sp points to kernel stack (if from user) or current stack (if from kernel)
 * - All registers contain values from before the trap
 */
.globl trap_entry
.align 4
trap_entry:
    /* Save sp temporarily to sscratch, swap with kernel sp if from user */
    csrrw   sp, sscratch, sp

    /* If sp != 0, we came from user mode (sscratch held kstack) */
    bnez    sp, 1f

    /* If sp == 0, sscratch was 0 (kernel mode). Swap back to restore sp. */
    csrrw   sp, sscratch, sp

1:
    /* Allocate trap frame on stack */
    addi    sp, sp, -TF_SIZE

    /* Save general purpose registers */
    sd      ra, TF_RA(sp)
    /* sp saved later */
    sd      gp, TF_GP(sp)
    sd      tp, TF_TP(sp)
    sd      t0, TF_T0(sp)
    sd      t1, TF_T1(sp)
    sd      t2, TF_T2(sp)
    sd      s0, TF_S0(sp)
    sd      s1, TF_S1(sp)
    sd      a0, TF_A0(sp)
    sd      a1, TF_A1(sp)
    sd      a2, TF_A2(sp)
    sd      a3, TF_A3(sp)
    sd      a4, TF_A4(sp)
    sd      a5, TF_A5(sp)
    sd      a6, TF_A6(sp)
    sd      a7, TF_A7(sp)
    sd      s2, TF_S2(sp)
    sd      s3, TF_S3(sp)
    sd      s4, TF_S4(sp)
    sd      s5, TF_S5(sp)
    sd      s6, TF_S6(sp)
    sd      s7, TF_S7(sp)
    sd      s8, TF_S8(sp)
    sd      s9, TF_S9(sp)
    sd      s10, TF_S10(sp)
    sd      s11, TF_S11(sp)
    sd      t3, TF_T3(sp)
    sd      t4, TF_T4(sp)
    sd      t5, TF_T5(sp)
    sd      t6, TF_T6(sp)

    /* Save original sp (from sscratch if from user, otherwise compute it) */
    csrr    t0, sscratch
    beqz    t0, 3f
    /* From user: t0 has user sp */
    sd      t0, TF_SP(sp)
    /* Clear sscratch (we're in kernel now) */
    csrw    sscratch, zero
    j       4f
3:
    /* From kernel: compute original sp */
    addi    t0, sp, TF_SIZE
    sd      t0, TF_SP(sp)
4:

    /* Save CSRs */
    csrr    t0, sepc
    sd      t0, TF_SEPC(sp)
    csrr    t0, sstatus
    sd      t0, TF_SSTATUS(sp)
    csrr    t0, scause
    sd      t0, TF_SCAUSE(sp)
    csrr    t0, stval
    sd      t0, TF_STVAL(sp)

    /* Call C handler with trap frame pointer as argument */
    mv      a0, sp
    call    trap_dispatch

    /* Fall through to trap_return */

/**
 * trap_return - Return from trap
 *
 * Restores all registers from trap frame and executes sret.
 * Can also be called directly to switch to a new context.
 */
.globl trap_return
trap_return:
    /* Restore CSRs */
    ld      t0, TF_SEPC(sp)
    ld      t1, TF_SSTATUS(sp)
    csrw    sepc, t0
    csrw    sstatus, t1

    /* Check if returning to user mode (SPP bit in sstatus) */
    andi    t0, t1, (1 << 8)    /* SSTATUS_SPP */
    bnez    t0, 1f

    /* Returning to user: set sscratch to kernel sp for next trap */
    addi    t0, sp, TF_SIZE
    csrw    sscratch, t0

1:
    /* Restore general purpose registers */
    ld      ra, TF_RA(sp)
    /* sp restored last */
    ld      gp, TF_GP(sp)
    ld      tp, TF_TP(sp)
    ld      t0, TF_T0(sp)
    ld      t1, TF_T1(sp)
    ld      t2, TF_T2(sp)
    ld      s0, TF_S0(sp)
    ld      s1, TF_S1(sp)
    ld      a0, TF_A0(sp)
    ld      a1, TF_A1(sp)
    ld      a2, TF_A2(sp)
    ld      a3, TF_A3(sp)
    ld      a4, TF_A4(sp)
    ld      a5, TF_A5(sp)
    ld      a6, TF_A6(sp)
    ld      a7, TF_A7(sp)
    ld      s2, TF_S2(sp)
    ld      s3, TF_S3(sp)
    ld      s4, TF_S4(sp)
    ld      s5, TF_S5(sp)
    ld      s6, TF_S6(sp)
    ld      s7, TF_S7(sp)
    ld      s8, TF_S8(sp)
    ld      s9, TF_S9(sp)
    ld      s10, TF_S10(sp)
    ld      s11, TF_S11(sp)
    ld      t3, TF_T3(sp)
    ld      t4, TF_T4(sp)
    ld      t5, TF_T5(sp)
    ld      t6, TF_T6(sp)

    /* Restore sp last */
    ld      sp, TF_SP(sp)

    /* Return from trap */
    sret
