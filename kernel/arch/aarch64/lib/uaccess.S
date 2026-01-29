/**
 * kernel/arch/aarch64/lib/uaccess.S - User memory copy
 */

.global __arch_copy_from_user
__arch_copy_from_user:
    mov x3, x2
1:
    cbz x3, 2f
    ldrb w4, [x1], #1
    strb w4, [x0], #1
    subs x3, x3, #1
    b 1b
2:
    mov x0, #0
    ret

.global __arch_copy_to_user
__arch_copy_to_user:
    mov x3, x2
1:
    cbz x3, 2f
    ldrb w4, [x1], #1
    strb w4, [x0], #1
    subs x3, x3, #1
    b 1b
2:
    mov x0, #0
    ret

.global __arch_strncpy_from_user
__arch_strncpy_from_user:
    mov x3, x2
    mov x4, #0
1:
    cbz x3, 2f
    ldrb w5, [x1], #1
    strb w5, [x0], #1
    add x4, x4, #1
    subs x3, x3, #1
    cbz w5, 2f
    b 1b
2:
    mov x0, x4
    ret
