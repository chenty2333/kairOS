#ifndef _KAIROS_UACCESS_H
#define _KAIROS_UACCESS_H

#include <kairos/types.h>

/**
 * copy_from_user - Copy data from user space to kernel space
 * @to: Kernel destination buffer
 * @from: User source buffer
 * @n: Number of bytes to copy
 *
 * Returns 0 on success, or negative error code.
 * 
 * TODO: In the future, this must check if 'from' is in user address range
 * and handle page faults safely. For now (Phase 5), it's a direct copy.
 */
static inline int copy_from_user(void *to, const void *from, size_t n)
{
    char *d = to;
    const char *s = from;
    while (n--) {
        *d++ = *s++;
    }
    return 0;
}

/**
 * copy_to_user - Copy data from kernel space to user space
 * @to: User destination buffer
 * @from: Kernel source buffer
 * @n: Number of bytes to copy
 *
 * Returns 0 on success, or negative error code.
 */
static inline int copy_to_user(void *to, const void *from, size_t n)
{
    char *d = to;
    const char *s = from;
    while (n--) {
        *d++ = *s++;
    }
    return 0;
}

/**
 * strncpy_from_user - Copy a string from user space
 * @dest: Kernel buffer
 * @src: User string
 * @count: Max size
 *
 * Returns string length (excluding null), or negative error.
 */
static inline long strncpy_from_user(char *dest, const char *src, size_t count)
{
    long res = 0;
    while (count > 0) {
        char c = *src++;
        *dest++ = c;
        if (c == '\0') {
            return res;
        }
        res++;
        count--;
    }
    return res;
}

#endif /* _KAIROS_UACCESS_H */
