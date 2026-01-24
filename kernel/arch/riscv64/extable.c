#include <kairos/types.h>

struct exception_table_entry {
    unsigned long insn;
    unsigned long fixup;
};

extern const struct exception_table_entry __ex_table_start[];
extern const struct exception_table_entry __ex_table_end[];

/**
 * search_exception_table - Search for an exception handler
 * @addr: The address of the instruction that caused the fault
 *
 * Returns the address of the fixup code, or 0 if not found.
 */
unsigned long search_exception_table(unsigned long addr)
{
    const struct exception_table_entry *e;

    /* Linear search for now - optimize to binary search if table grows large */
    for (e = __ex_table_start; e < __ex_table_end; e++) {
        if (e->insn == addr) {
            return e->fixup;
        }
    }

    return 0;
}
