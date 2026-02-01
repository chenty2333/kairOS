#ifndef _ASM_X86_64_ARCH_H
#define _ASM_X86_64_ARCH_H

/**
 * kernel/arch/x86_64/include/asm/arch.h - x86_64 definitions
 */

#ifndef __ASSEMBLER__
#include <kairos/types.h>
#endif

#define ARCH_HAS_CPU_ID 1
#define ARCH_HAS_CONTEXT_SET_USER_SP 1

#ifndef __ASSEMBLER__

static inline void outb(uint16_t port, uint8_t val) {
    __asm__ __volatile__("outb %0, %1" : : "a"(val), "Nd"(port));
}
static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ __volatile__("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
static inline void outl(uint16_t port, uint32_t val) {
    __asm__ __volatile__("outl %0, %1" : : "a"(val), "Nd"(port));
}
static inline uint32_t inl(uint16_t port) {
    uint32_t ret;
    __asm__ __volatile__("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline int arch_cpu_id(void) {
    uint64_t id;
    __asm__ __volatile__("mov %%gs:0, %0" : "=r"(id));
    return (int)id;
}

struct trap_frame {
    uint64_t rax, rbx, rcx, rdx, rbp, rdi, rsi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t trapno, err;
    uint64_t rip, cs, rflags, rsp, ss;
};

#define tf_a0 rax
#define tf_a1 rdi
#define tf_a2 rsi
#define tf_a3 rdx
#define tf_a4 rcx
#define tf_a5 r8
#define tf_a6 r9
#define tf_sp rsp
#define sepc rip

#endif /* __ASSEMBLER__ */

#endif /* _ASM_X86_64_ARCH_H */
