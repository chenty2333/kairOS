/**
 * kernel/arch/aarch64/trapasm.S - Exception vectors
 */

.section .text
.align 11
.global vector_table

vector_table:
    b sync_el1
    b irq_el1
    b fiq_el1
    b serr_el1
    b sync_el0
    b irq_el0
    b fiq_el0
    b serr_el0

.macro SAVE_FRAME
    sub sp, sp, #(31*8 + 5*8)
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
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
    mov x1, sp
    add x1, x1, #(31*8 + 5*8)
    str x1, [sp, #(31*8)]
    mrs x1, elr_el1
    str x1, [sp, #(31*8 + 8)]
    mrs x1, spsr_el1
    str x1, [sp, #(31*8 + 16)]
    mrs x1, esr_el1
    str x1, [sp, #(31*8 + 24)]
    mrs x1, far_el1
    str x1, [sp, #(31*8 + 32)]
.endm

.macro RESTORE_FRAME
    /* restore registers */
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
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
    add sp, sp, #(31*8 + 5*8)
.endm

sync_el1:
    SAVE_FRAME
    mov x0, sp
    bl aarch64_trap_dispatch
    RESTORE_FRAME
    eret

irq_el1:
    SAVE_FRAME
    mov x0, sp
    bl aarch64_trap_dispatch
    RESTORE_FRAME
    eret

fiq_el1:
    b sync_el1
serr_el1:
    b sync_el1

sync_el0:
    b sync_el1
irq_el0:
    b irq_el1
fiq_el0:
    b sync_el1
serr_el0:
    b sync_el1
