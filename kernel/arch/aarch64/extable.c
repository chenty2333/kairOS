/**
 * kernel/arch/aarch64/extable.c - Exception table
 *
 * Searches the __ex_table section for a fixup address matching
 * the faulting instruction. Used by uaccess routines.
 */

#include <kairos/types.h>

struct exception_table_entry {
    unsigned long insn;
    unsigned long fixup;
};

extern const struct exception_table_entry __ex_table_start[];
extern const struct exception_table_entry __ex_table_end[];

unsigned long search_exception_table(unsigned long addr)
{
    const struct exception_table_entry *e;

    for (e = __ex_table_start; e < __ex_table_end; e++) {
        if (e->insn == addr) {
            return e->fixup;
        }
    }

    return 0;
}
