/**
 * kernel/arch/x86_64/switch.S - Context switch
 */

.section .text

/* struct arch_context offsets */
.set CTX_R15, 0
.set CTX_R14, 8
.set CTX_R13, 16
.set CTX_R12, 24
.set CTX_RBX, 32
.set CTX_RBP, 40
.set CTX_RIP, 48
.set CTX_RSP, 56
.set CTX_RFLAGS, 64
.set CTX_KSTACK, 72
.set CTX_USTACK, 80
.set CTX_CR3, 88
.set CTX_KFN, 96
.set CTX_KARG, 104

.global arch_context_switch
arch_context_switch:
    mov %r15, CTX_R15(%rdi)
    mov %r14, CTX_R14(%rdi)
    mov %r13, CTX_R13(%rdi)
    mov %r12, CTX_R12(%rdi)
    mov %rbx, CTX_RBX(%rdi)
    mov %rbp, CTX_RBP(%rdi)
    mov %rsp, CTX_RSP(%rdi)
    lea 1f(%rip), %rax
    mov %rax, CTX_RIP(%rdi)

    mov CTX_R15(%rsi), %r15
    mov CTX_R14(%rsi), %r14
    mov CTX_R13(%rsi), %r13
    mov CTX_R12(%rsi), %r12
    mov CTX_RBX(%rsi), %rbx
    mov CTX_RBP(%rsi), %rbp
    mov CTX_RSP(%rsi), %rsp
    mov CTX_RIP(%rsi), %rax
    jmp *%rax
1:
    ret

.global arch_enter_user
arch_enter_user:
    mov CTX_USTACK(%rdi), %rsp
    mov CTX_KSTACK(%rdi), %rax
    mov %rax, %gs:0

    mov $0x23, %ax
    pushq %rax
    pushq %rsp
    pushfq
    mov $0x1B, %ax
    pushq %rax
    mov CTX_RIP(%rdi), %rax
    pushq %rax
    iretq

.global kthread_entry
kthread_entry:
    call sched_post_switch_cleanup
    sti
    mov %r13, %rdi
    call *%r12
    call proc_exit
1:  hlt; jmp 1b

.global fork_ret
fork_ret:
    call sched_post_switch_cleanup
    sti
    mov %rsp, %rdi
    call x86_return_to_user
1:  hlt; jmp 1b

.global x86_return_to_user
x86_return_to_user:
    mov %rdi, %rsp
    pop %rax
    pop %rbx
    pop %rcx
    pop %rdx
    pop %rbp
    pop %rdi
    pop %rsi
    pop %r8
    pop %r9
    pop %r10
    pop %r11
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    add $16, %rsp /* trapno + err */
    iretq
