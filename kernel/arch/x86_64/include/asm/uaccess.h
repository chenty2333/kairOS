#ifndef _ASM_X86_64_UACCESS_H
#define _ASM_X86_64_UACCESS_H

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/types.h>

#define USER_DS_LIMIT 0x00007fffffffffffULL

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

    /* Do not require PTEs to be present; demand paging will fault them in. */
    return true;
}

unsigned long __arch_copy_from_user(void *to, const void *from, unsigned long n);
unsigned long __arch_copy_to_user(void *to, const void *from, unsigned long n);
long __arch_strncpy_from_user(char *dest, const char *src, long count);

unsigned long search_exception_table(unsigned long addr);

#endif /* _ASM_X86_64_UACCESS_H */
