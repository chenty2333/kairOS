/**
 * kernel/arch/aarch64/extable.c - Exception table (stub)
 */

#include <kairos/types.h>

unsigned long search_exception_table(unsigned long addr) {
    (void)addr;
    return 0;
}
