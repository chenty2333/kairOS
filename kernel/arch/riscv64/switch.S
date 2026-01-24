/**
 * context.S - RISC-V 64 Context Switching
 *
 * Implements context switching between processes/threads.
 *
 * RISC-V calling convention (for callee-saved registers):
 *   s0-s11 (x8-x9, x18-x27) - Saved registers
 *   sp (x2) - Stack pointer
 *   ra (x1) - Return address
 *
 * We only save callee-saved registers because caller-saved registers
 * are already saved by the calling function.
 */

#include <kairos/config.h>

.section .text

/**
 * struct arch_context layout (must match context.c):
 *   0x00: ra   (return address)
 *   0x08: sp   (stack pointer)
 *   0x10: s0   (frame pointer)
 *   0x18: s1
 *   0x20: s2
 *   0x28: s3
 *   0x30: s4
 *   0x38: s5
 *   0x40: s6
 *   0x48: s7
 *   0x50: s8
 *   0x58: s9
 *   0x60: s10
 *   0x68: s11
 *   0x70: kernel_stack (base address)
 *   0x78: user_stack
 *   0x80: satp (page table)
 */

/**
 * arch_context_switch - Switch from old context to new context
 *
 * void arch_context_switch(struct arch_context *old, struct arch_context *new);
 *
 * Arguments:
 *   a0 = old context pointer
 *   a1 = new context pointer
 *
 * Saves current context to *old, restores context from *new.
 */
.globl arch_context_switch
.type arch_context_switch, @function
arch_context_switch:
    /* Save old context */
    sd ra,  0x00(a0)
    sd sp,  0x08(a0)
    sd s0,  0x10(a0)
    sd s1,  0x18(a0)
    sd s2,  0x20(a0)
    sd s3,  0x28(a0)
    sd s4,  0x30(a0)
    sd s5,  0x38(a0)
    sd s6,  0x40(a0)
    sd s7,  0x48(a0)
    sd s8,  0x50(a0)
    sd s9,  0x58(a0)
    sd s10, 0x60(a0)
    sd s11, 0x68(a0)

    /* Restore new context */
    ld ra,  0x00(a1)
    ld sp,  0x08(a1)
    ld s0,  0x10(a1)
    ld s1,  0x18(a1)
    ld s2,  0x20(a1)
    ld s3,  0x28(a1)
    ld s4,  0x30(a1)
    ld s5,  0x38(a1)
    ld s6,  0x40(a1)
    ld s7,  0x48(a1)
    ld s8,  0x50(a1)
    ld s9,  0x58(a1)
    ld s10, 0x60(a1)
    ld s11, 0x68(a1)

    ret
.size arch_context_switch, . - arch_context_switch

/**
 * arch_enter_user - Enter user mode
 *
 * noreturn void arch_enter_user(struct arch_context *ctx);
 *
 * Sets up the trap frame and returns to user mode via sret.
 * This is used for the initial entry into a user process.
 *
 * Arguments:
 *   a0 = context pointer (contains user entry point and stack)
 */
.globl arch_enter_user
.type arch_enter_user, @function
arch_enter_user:
    /* Load user entry point into sepc */
    ld t0, 0x00(a0)     /* ra holds entry point for new process */
    csrw sepc, t0

    /* Load user stack pointer */
    ld sp, 0x78(a0)     /* user_stack */

    /* Set sstatus for user mode:
     * - Clear SPP (bit 8) for user mode
     * - Set SPIE (bit 5) to enable interrupts after sret
     * Use atomic bit manipulation to preserve other bits (like FS)
     */
    li t0, (1 << 8)     /* SPP bit */
    csrc sstatus, t0
    li t0, (1 << 5)     /* SPIE bit */
    csrs sstatus, t0

    /* Set sscratch to kernel stack for trap entry */
    ld t0, 0x70(a0)     /* kernel_stack */
    csrw sscratch, t0

    /* Clear all user-visible registers */
    li ra, 0
    li gp, 0
    li tp, 0
    li t0, 0
    li t1, 0
    li t2, 0
    li s0, 0
    li s1, 0
    /* a0 will be set to entry argument if needed */
    li a0, 0
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a5, 0
    li a6, 0
    li a7, 0
    li s2, 0
    li s3, 0
    li s4, 0
    li s5, 0
    li s6, 0
    li s7, 0
    li s8, 0
    li s9, 0
    li s10, 0
    li s11, 0
    li t3, 0
    li t4, 0
    li t5, 0
    li t6, 0

    /* Return to user mode */
    sret
.size arch_enter_user, . - arch_enter_user

/**
 * kthread_entry - Entry point for new kernel threads
 *
 * When a new kernel thread is created, arch_context_init sets up:
 *   ra = kthread_entry
 *   s0 = function to call
 *   s1 = argument
 *
 * This wrapper calls the actual thread function and then exits.
 */
.globl kthread_entry
.type kthread_entry, @function
kthread_entry:
    /* Enable interrupts */
    csrsi sstatus, 2    /* Set SIE bit */

    /* Call the thread function: fn(arg) */
    mv a0, s1           /* arg */
    jalr s0             /* call fn */

    /* Thread returned - call proc_exit with return value */
    /* a0 already contains return value from fn */
    call proc_exit

    /* Should never reach here */
1:  wfi
    j 1b
.size kthread_entry, . - kthread_entry
