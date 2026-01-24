#ifndef _ASM_RISCV64_ARCH_H
#define _ASM_RISCV64_ARCH_H

/*
 * Optimized inline implementation for RISC-V 64
 */

/* 
 * arch_cpu_id - Get current CPU ID
 * Optimized to read directly from tp register
 */
static inline int arch_cpu_id(void)
{
    unsigned long tp;
    __asm__ __volatile__("mv %0, tp" : "=r"(tp));
    return (int)tp;
}
#define ARCH_HAS_CPU_ID 1

#endif /* _ASM_RISCV64_ARCH_H */
