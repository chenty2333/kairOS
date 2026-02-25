#ifndef _ASM_AARCH64_ARCH_H
#define _ASM_AARCH64_ARCH_H

/**
 * kernel/arch/aarch64/include/asm/arch.h - AArch64 definitions
 */

#ifndef __ASSEMBLER__
#include <kairos/types.h>
#endif

#define ARCH_HAS_CPU_ID 1
#define ARCH_HAS_CONTEXT_SET_USER_SP 1
#define ARCH_HAS_EARLY_GETCHAR 1

#ifndef __ASSEMBLER__

static inline int arch_cpu_id(void) {
    uint64_t id;
    __asm__ __volatile__("mrs %0, tpidr_el1" : "=r"(id));
    return (int)id;
}

void aarch64_early_console_set_ready(bool ready);

struct trap_frame {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t elr;
    uint64_t spsr;
    uint64_t esr;
    uint64_t far;
};

#define tf_a0 regs[0]
#define tf_a1 regs[1]
#define tf_a2 regs[2]
#define tf_a3 regs[3]
#define tf_a4 regs[4]
#define tf_a5 regs[5]
#define tf_a6 regs[6]
#define tf_a7 regs[8]   /* AArch64 Linux ABI: syscall number in x8 */
#define tf_sp sp
#define sepc elr

#endif /* __ASSEMBLER__ */

#endif /* _ASM_AARCH64_ARCH_H */
