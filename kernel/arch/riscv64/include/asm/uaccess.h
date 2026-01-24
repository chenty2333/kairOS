#ifndef _ASM_RISCV64_UACCESS_H
#define _ASM_RISCV64_UACCESS_H

#include <kairos/types.h>

/*
 * User Address Space Limit (SV39)
 * User: 0x0000000000000000 - 0x0000003FFFFFFFFF
 */
#define USER_DS_LIMIT 0x0000004000000000UL

/**
 * access_ok - Check if a user pointer is valid
 * @addr: User address
 * @size: Size of data
 *
 * Returns true if the range is within user space.
 */
static inline bool access_ok(const void *addr, size_t size)
{
    unsigned long ptr = (unsigned long)addr;
    unsigned long limit = USER_DS_LIMIT;
    
    return (ptr <= limit) && (size <= limit - ptr);
}

/*
 * RISC-V Status Register (sstatus) bits
 */
#define SSTATUS_SUM (1UL << 18)

static inline void arch_user_access_enable(void)
{
    __asm__ __volatile__("csrs sstatus, %0" :: "r"(SSTATUS_SUM));
}

static inline void arch_user_access_disable(void)
{
    __asm__ __volatile__("csrc sstatus, %0" :: "r"(SSTATUS_SUM));
}

/*
 * Raw architecture copy functions
 * Implemented in kernel/arch/riscv64/lib/uaccess.S
 */
unsigned long __arch_copy_from_user(void *to, const void *from, unsigned long n);
unsigned long __arch_copy_to_user(void *to, const void *from, unsigned long n);
long __arch_strncpy_from_user(char *dest, const char *src, long count);

/* Exception table search (implemented in arch/riscv64/extable.c) */
unsigned long search_exception_table(unsigned long addr);

#endif /* _ASM_RISCV64_UACCESS_H */
