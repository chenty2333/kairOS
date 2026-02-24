#ifndef _KAIROS_UACCESS_H
#define _KAIROS_UACCESS_H

#include <kairos/config.h>
#if CONFIG_KERNEL_FAULT_INJECT
#include <kairos/fault_inject.h>
#endif
#include <kairos/types.h>

/* Include architecture-specific implementation */
#include <asm/uaccess.h>

static inline int uaccess_prefault(const void *addr, size_t n, bool write) {
    if (n == 0)
        return 0;

    struct process *p = proc_current();
    if (!p || !p->mm)
        return -EFAULT;

    uintptr_t start = ALIGN_DOWN((uintptr_t)addr, CONFIG_PAGE_SIZE);
    uintptr_t end = ALIGN_DOWN((uintptr_t)addr + n - 1, CONFIG_PAGE_SIZE);
    uint32_t flags = write ? PTE_WRITE : 0;

    for (uintptr_t va = start; va <= end; va += CONFIG_PAGE_SIZE) {
        int ret = mm_handle_fault(p->mm, (vaddr_t)va, flags);
        if (ret < 0)
            return -EFAULT;
    }
    return 0;
}

/**
 * copy_from_user - Copy data from user space to kernel space
 * @to: Kernel destination buffer
 * @from: User source buffer
 * @n: Number of bytes to copy
 *
 * Returns 0 on success, or -EFAULT on error.
 */
static inline int copy_from_user(void *to, const void *from, size_t n) {
#if CONFIG_KERNEL_FAULT_INJECT
    if (fault_inject_should_fail(FAULT_INJECT_POINT_COPY_FROM_USER)) {
        return -EFAULT;
    }
#endif
    if (!access_ok(from, n)) {
        return -EFAULT;
    }
    if (uaccess_prefault(from, n, false) < 0) {
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
#if CONFIG_KERNEL_FAULT_INJECT
    if (fault_inject_should_fail(FAULT_INJECT_POINT_COPY_TO_USER)) {
        return -EFAULT;
    }
#endif
    if (!access_ok(to, n)) {
        return -EFAULT;
    }
    if (uaccess_prefault(to, n, true) < 0) {
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
    if (count == 0)
        return 0;
    if (!access_ok(src, count)) {
        return -EFAULT;
    }
    return __arch_strncpy_from_user(dest, src, count);
}

#endif /* _KAIROS_UACCESS_H */
