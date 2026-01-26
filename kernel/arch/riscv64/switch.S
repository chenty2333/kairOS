/**
 * kernel/arch/riscv64/switch.S - Context Switching
 */

.section .text

/* Macro to save/restore callee-saved registers */
.macro do_ctx op, base
    \op ra,  0x00(\base)
    \op sp,  0x08(\base)
    \op s0,  0x10(\base)
    \op s1,  0x18(\base)
    \op s2,  0x20(\base)
    \op s3,  0x28(\base)
    \op s4,  0x30(\base)
    \op s5,  0x38(\base)
    \op s6,  0x40(\base)
    \op s7,  0x48(\base)
    \op s8,  0x50(\base)
    \op s9,  0x58(\base)
    \op s10, 0x60(\base)
    \op s11, 0x68(\base)
.endm

/**
 * void arch_context_switch(struct arch_context *old, struct arch_context *new)
 */
.globl arch_context_switch
arch_context_switch:
    do_ctx sd, a0
    do_ctx ld, a1
    ret

/**
 * noreturn void arch_enter_user(struct arch_context *ctx)
 */
.globl arch_enter_user
arch_enter_user:
    ld t0, 0x00(a0)     /* Entry point */
    csrw sepc, t0
    ld sp, 0x78(a0)     /* User stack */
    ld t0, 0x70(a0)     /* Kernel stack */
    csrw sscratch, t0

    /* Set sstatus: clear SPP, set SPIE */
    li t0, (1 << 8)
    csrc sstatus, t0
    li t0, (1 << 5)
    csrs sstatus, t0

    /* Zero out registers for security/cleanliness */
    li ra, 0; li gp, 0; li tp, 0; li t0, 0; li t1, 0; li t2, 0; li s0, 0; li s1, 0
    li a0, 0; li a1, 0; li a2, 0; li a3, 0; li a4, 0; li a5, 0; li a6, 0; li a7, 0
    li s2, 0; li s3, 0; li s4, 0; li s5, 0; li s6, 0; li s7, 0; li s8, 0; li s9, 0
    li s10, 0; li s11, 0; li t3, 0; li t4, 0; li t5, 0; li t6, 0
    sret

/**
 * kthread_entry - Entry point for kernel threads
 */
.globl kthread_entry
kthread_entry:
    call sched_post_switch_cleanup
    csrsi sstatus, 2    /* Enable interrupts */
    mv a0, s1           /* Argument */
    jalr s0             /* Call fn */
    call proc_exit
1:  wfi; j 1b