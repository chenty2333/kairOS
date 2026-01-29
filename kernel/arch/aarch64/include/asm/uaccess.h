#ifndef _ASM_AARCH64_UACCESS_H
#define _ASM_AARCH64_UACCESS_H

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/types.h>

#define USER_DS_LIMIT 0x0000ffffffffffffULL

static inline bool access_ok(const void *addr, size_t size) {
    if (size == 0)
        return true;
    unsigned long start = (unsigned long)addr;
    unsigned long end = start + size - 1;
    if (end < start)
        return false;
    if (end > USER_DS_LIMIT)
        return false;

    struct process *p = proc_current();
    if (!p || !p->mm)
        return false;

    for (unsigned long va = start; va <= end;
         va = ALIGN_DOWN(va, CONFIG_PAGE_SIZE) + CONFIG_PAGE_SIZE) {
        uint64_t pte = arch_mmu_get_pte(p->mm->pgdir, (vaddr_t)va);
        if (!(pte & PTE_VALID) || !(pte & PTE_USER))
            return false;
        if (va + CONFIG_PAGE_SIZE < va)
            break;
    }
    return true;
}

unsigned long __arch_copy_from_user(void *to, const void *from, unsigned long n);
unsigned long __arch_copy_to_user(void *to, const void *from, unsigned long n);
long __arch_strncpy_from_user(char *dest, const char *src, long count);

unsigned long search_exception_table(unsigned long addr);

#endif /* _ASM_AARCH64_UACCESS_H */
