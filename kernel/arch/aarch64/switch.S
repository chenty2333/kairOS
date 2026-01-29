/**
 * kernel/arch/aarch64/switch.S - Context switch
 */

.section .text

/* struct arch_context offsets */
.set CTX_X19, 0
.set CTX_X20, 8
.set CTX_X21, 16
.set CTX_X22, 24
.set CTX_X23, 32
.set CTX_X24, 40
.set CTX_X25, 48
.set CTX_X26, 56
.set CTX_X27, 64
.set CTX_X28, 72
.set CTX_X29, 80
.set CTX_SP, 88
.set CTX_LR, 96
.set CTX_KSTACK, 104
.set CTX_USTACK, 112
.set CTX_TTBR0, 120
.set CTX_KFN, 128
.set CTX_KARG, 136

.global arch_context_switch
arch_context_switch:
    stp x19, x20, [x0, #CTX_X19]
    stp x21, x22, [x0, #CTX_X21]
    stp x23, x24, [x0, #CTX_X23]
    stp x25, x26, [x0, #CTX_X25]
    stp x27, x28, [x0, #CTX_X27]
    str x29, [x0, #CTX_X29]
    mov x2, sp
    str x2, [x0, #CTX_SP]
    str x30, [x0, #CTX_LR]

    ldp x19, x20, [x1, #CTX_X19]
    ldp x21, x22, [x1, #CTX_X21]
    ldp x23, x24, [x1, #CTX_X23]
    ldp x25, x26, [x1, #CTX_X25]
    ldp x27, x28, [x1, #CTX_X27]
    ldr x29, [x1, #CTX_X29]
    ldr x2, [x1, #CTX_SP]
    mov sp, x2
    ldr x30, [x1, #CTX_LR]
    ret

.global arch_enter_user
arch_enter_user:
    ldr x1, [x0, #CTX_USTACK]
    mov sp, x1
    ldr x1, [x0, #CTX_LR]
    msr elr_el1, x1
    eret

.global kthread_entry
kthread_entry:
    bl sched_post_switch_cleanup
    msr daifclr, #2
    mov x0, x20
    blr x19
    bl proc_exit
1:  wfi; b 1b

.global fork_ret
fork_ret:
    bl sched_post_switch_cleanup
    msr daifclr, #2
    mov x0, sp
    bl aarch64_return_to_user
1:  wfi; b 1b

.global aarch64_return_to_user
aarch64_return_to_user:
    mov x17, x0
    ldr x18, [x17, #(31*8)]       /* saved sp */
    ldr x19, [x17, #(31*8 + 8)]   /* saved elr */
    ldr x20, [x17, #(31*8 + 16)]  /* saved spsr */

    ldp x0, x1, [x17, #0]
    ldp x2, x3, [x17, #16]
    ldp x4, x5, [x17, #32]
    ldp x6, x7, [x17, #48]
    ldp x8, x9, [x17, #64]
    ldp x10, x11, [x17, #80]
    ldp x12, x13, [x17, #96]
    ldp x14, x15, [x17, #112]
    ldr x16, [x17, #128]
    ldp x21, x22, [x17, #168]
    ldp x23, x24, [x17, #184]
    ldp x25, x26, [x17, #200]
    ldp x27, x28, [x17, #216]
    ldr x29, [x17, #232]
    ldr x30, [x17, #240]

    msr elr_el1, x19
    msr spsr_el1, x20
    mov sp, x18

    ldp x18, x19, [x17, #144]
    ldr x20, [x17, #160]
    ldr x17, [x17, #136]
    eret
