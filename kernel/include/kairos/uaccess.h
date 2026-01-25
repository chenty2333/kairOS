#ifndef _KAIROS_UACCESS_H
#define _KAIROS_UACCESS_H

#include <kairos/types.h>

/* Include architecture-specific implementation */
#include <asm/uaccess.h>

/**
 * copy_from_user - Copy data from user space to kernel space
 * @to: Kernel destination buffer
 * @from: User source buffer
 * @n: Number of bytes to copy
 *
 * Returns 0 on success, or -EFAULT on error.
 */
static inline int copy_from_user(void *to, const void *from, size_t n) {
    if (!access_ok(from, n)) {
        return -EFAULT;
    }
    /* __arch_copy_from_user returns bytes NOT copied (0 on success) */
    if (__arch_copy_from_user(to, from, n) != 0) {
        return -EFAULT;
    }
    return 0;
}

/**
 * copy_to_user - Copy data from kernel space to user space
 * @to: User destination buffer
 * @from: Kernel source buffer
 * @n: Number of bytes to copy
 *
 * Returns 0 on success, or -EFAULT on error.
 */
static inline int copy_to_user(void *to, const void *from, size_t n) {
    if (!access_ok(to, n)) {
        return -EFAULT;
    }
    if (__arch_copy_to_user(to, from, n) != 0) {
        return -EFAULT;
    }
    return 0;
}

/**
 * strncpy_from_user - Copy a string from user space
 * @dest: Kernel buffer
 * @src: User string
 * @count: Max size
 *
 * Returns string length (excluding null), or -EFAULT.
 */
static inline long strncpy_from_user(char *dest, const char *src,
                                     size_t count) {
    if (!access_ok(src, 1)) {
        return -EFAULT;
    }
    return __arch_strncpy_from_user(dest, src, count);
}

#endif /* _KAIROS_UACCESS_H */