/**
 * kernel/arch/aarch64/trapasm.S - Exception vectors (AArch64)
 *
 * AArch64 requires 16 vector entries, each 128 bytes (.align 7).
 * Layout:
 *   0-3:   Current EL, SP_EL0  (should not happen)
 *   4-7:   Current EL, SP_ELx  (kernel sync/irq/fiq/serror)
 *   8-11:  Lower EL, AArch64   (user sync/irq/fiq/serror)
 *   12-15: Lower EL, AArch32   (not supported)
 */

#define FRAME_SIZE (31*8 + 5*8)  /* x0-x30 + sp + elr + spsr + esr + far */

/*
 * SAVE_FRAME: allocate trap frame on the kernel stack and save all state.
 * For user-mode entry (\from_user == 1), save SP_EL0 instead of current SP.
 */
.macro SAVE_FRAME from_user=0
    sub sp, sp, #FRAME_SIZE
    stp x0,  x1,  [sp, #0]
    stp x2,  x3,  [sp, #16]
    stp x4,  x5,  [sp, #32]
    stp x6,  x7,  [sp, #48]
    stp x8,  x9,  [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]

    /* Save interrupted SP */
.if \from_user
    mrs x1, sp_el0
.else
    mov x1, sp
    add x1, x1, #FRAME_SIZE
.endif
    str x1, [sp, #(31*8)]       /* tf->sp */

    mrs x1, elr_el1
    str x1, [sp, #(31*8 + 8)]   /* tf->elr */
    mrs x1, spsr_el1
    str x1, [sp, #(31*8 + 16)]  /* tf->spsr */
    mrs x1, esr_el1
    str x1, [sp, #(31*8 + 24)]  /* tf->esr */
    mrs x1, far_el1
    str x1, [sp, #(31*8 + 32)]  /* tf->far */
.endm

/*
 * RESTORE_FRAME: restore all state and deallocate the trap frame.
 * For user-mode return (\to_user == 1), restore SP_EL0.
 */
.macro RESTORE_FRAME to_user=0
    /* Restore ELR and SPSR first (before we clobber x1) */
    ldr x1, [sp, #(31*8 + 8)]
    msr elr_el1, x1
    ldr x1, [sp, #(31*8 + 16)]
    msr spsr_el1, x1

.if \to_user
    ldr x1, [sp, #(31*8)]
    msr sp_el0, x1
.endif

    ldp x0,  x1,  [sp, #0]
    ldp x2,  x3,  [sp, #16]
    ldp x4,  x5,  [sp, #32]
    ldp x6,  x7,  [sp, #48]
    ldp x8,  x9,  [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #FRAME_SIZE
.endm

/* --- Vector table: 16 entries, each .align 7 (128 bytes) --- */

.section .text
.align 11
.global vector_table
vector_table:

/* 0-3: Current EL with SP_EL0 — should never happen */
.align 7
    b unexpected_exception
.align 7
    b unexpected_exception
.align 7
    b unexpected_exception
.align 7
    b unexpected_exception

/* 4-7: Current EL with SP_ELx — kernel mode */
.align 7
    b el1_sync
.align 7
    b el1_irq
.align 7
    b unexpected_exception   /* FIQ */
.align 7
    b unexpected_exception   /* SError */

/* 8-11: Lower EL, AArch64 — user mode */
.align 7
    b el0_sync
.align 7
    b el0_irq
.align 7
    b unexpected_exception   /* FIQ */
.align 7
    b unexpected_exception   /* SError */

/* 12-15: Lower EL, AArch32 — not supported */
.align 7
    b unexpected_exception
.align 7
    b unexpected_exception
.align 7
    b unexpected_exception
.align 7
    b unexpected_exception

/* --- Handlers --- */

el1_sync:
    SAVE_FRAME from_user=0
    mov x0, sp
    bl aarch64_trap_dispatch
    RESTORE_FRAME to_user=0
    eret

el1_irq:
    SAVE_FRAME from_user=0
    str xzr, [sp, #(31*8 + 24)]   /* ESR_EL1 is architecturally UNKNOWN for IRQ */
    mov x0, sp
    bl aarch64_trap_dispatch
    RESTORE_FRAME to_user=0
    eret

el0_sync:
    SAVE_FRAME from_user=1
    mov x0, sp
    bl aarch64_trap_dispatch
    RESTORE_FRAME to_user=1
    eret

el0_irq:
    SAVE_FRAME from_user=1
    str xzr, [sp, #(31*8 + 24)]   /* ESR_EL1 is architecturally UNKNOWN for IRQ */
    mov x0, sp
    bl aarch64_trap_dispatch
    RESTORE_FRAME to_user=1
    eret

unexpected_exception:
    SAVE_FRAME from_user=0
    mov x0, sp
    bl aarch64_trap_dispatch
    b .   /* should not return */
