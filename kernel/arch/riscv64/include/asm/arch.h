#ifndef _ASM_RISCV64_ARCH_H
#define _ASM_RISCV64_ARCH_H

/**
 * kernel/arch/riscv64/include/asm/arch.h - RISC-V 64 Architecture Definitions
 */

#ifndef __ASSEMBLER__
#include <kairos/config.h>
#include <kairos/types.h>
#endif

/* sstatus register bits */
#define SSTATUS_SIE (1UL << 1)
#define SSTATUS_SPIE (1UL << 5)
#define SSTATUS_SPP (1UL << 8)
#define SSTATUS_SUM (1UL << 18)

/* scause values */
#define SCAUSE_INTERRUPT (1UL << 63)

#ifndef __ASSEMBLER__

/* Get current CPU ID from tp register */
static inline int arch_cpu_id(void) {
    unsigned long tp;
    __asm__ __volatile__("mv %0, tp" : "=r"(tp));
    return (int)tp;
}
static inline void arch_set_cpu_id(int cpu) {
    __asm__ __volatile__("mv tp, %0" : : "r"((unsigned long)cpu));
}
#define ARCH_HAS_CPU_ID_STABLE 1
static inline int arch_cpu_id_stable(void) {
    return arch_cpu_id();
}
#define ARCH_HAS_CPU_ID 1
#define ARCH_HAS_CONTEXT_KERNEL_STACK 1
#define ARCH_HAS_CONTEXT_SET_USER_SP 1
#define ARCH_HAS_EARLY_GETCHAR 1

/* SBI return structure */
struct sbi_ret {
    long error;
    long value;
};

/* Underlying SBI ecall */
static inline struct sbi_ret sbi_ecall(int ext, int fid, unsigned long arg0,
                                       unsigned long arg1, unsigned long arg2,
                                       unsigned long arg3, unsigned long arg4,
                                       unsigned long arg5) {
    struct sbi_ret ret;
    register unsigned long a0 __asm__("a0") = arg0;
    register unsigned long a1 __asm__("a1") = arg1;
    register unsigned long a2 __asm__("a2") = arg2;
    register unsigned long a3 __asm__("a3") = arg3;
    register unsigned long a4 __asm__("a4") = arg4;
    register unsigned long a5 __asm__("a5") = arg5;
    register unsigned long a6 __asm__("a6") = fid;
    register unsigned long a7 __asm__("a7") = ext;

    __asm__ __volatile__("ecall"
                         : "+r"(a0), "+r"(a1)
                         : "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)
                         : "memory");

    ret.error = a0;
    ret.value = a1;
    return ret;
}

/* Simplified SBI call for common 0-3 argument cases */
static inline struct sbi_ret sbi_call(int ext, int fid, unsigned long a0,
                                      unsigned long a1, unsigned long a2) {
    return sbi_ecall(ext, fid, a0, a1, a2, 0, 0, 0);
}

/* Trap frame layout (must match trapasm.S) */
struct trap_frame {
    uint64_t regs[31]; /* x1 - x31 */
    uint64_t sepc;
    uint64_t sstatus;
    uint64_t scause;
    uint64_t stval;
};

#define tf_ra regs[0]
#define tf_sp regs[1]
#define tf_a0 regs[9]
#define tf_a1 regs[10]
#define tf_a2 regs[11]
#define tf_a3 regs[12]
#define tf_a4 regs[13]
#define tf_a5 regs[14]
#define tf_a6 regs[15]
#define tf_a7 regs[16]

/* CSR access helpers */
static inline uint64_t rdtime(void) {
    uint64_t val;
    __asm__ __volatile__("rdtime %0" : "=r"(val));
    return val;
}

#endif /* __ASSEMBLER__ */

#endif /* _ASM_RISCV64_ARCH_H */
