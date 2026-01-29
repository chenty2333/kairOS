/**
 * kernel/arch/x86_64/lib/uaccess.S - User memory copy
 */

.global __arch_copy_from_user
__arch_copy_from_user:
    mov %rdi, %rax
    rep movsb
    xor %rax, %rax
    ret

.global __arch_copy_to_user
__arch_copy_to_user:
    mov %rdi, %rax
    rep movsb
    xor %rax, %rax
    ret

.global __arch_strncpy_from_user
__arch_strncpy_from_user:
    /* rdi=dest, rsi=src, rdx=count */
    xor %rax, %rax
1:
    test %rdx, %rdx
    jz 2f
    movb (%rsi), %cl
    movb %cl, (%rdi)
    inc %rsi
    inc %rdi
    dec %rdx
    inc %rax
    test %cl, %cl
    jnz 1b
2:
    ret
