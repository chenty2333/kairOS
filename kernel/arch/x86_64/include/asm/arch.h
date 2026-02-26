#ifndef _ASM_X86_64_ARCH_H
#define _ASM_X86_64_ARCH_H

/**
 * kernel/arch/x86_64/include/asm/arch.h - x86_64 definitions
 */

#ifndef __ASSEMBLER__
#include <kairos/config.h>
#include <kairos/types.h>
#endif

#define ARCH_HAS_CPU_ID 1
#define ARCH_HAS_CPU_ID_STABLE 1
#define ARCH_HAS_CONTEXT_SET_USER_SP 1
#define ARCH_HAS_CONTEXT_TLS 1
#define ARCH_HAS_TSS 1

#ifndef __ASSEMBLER__

extern uint64_t x86_cpu_id_slots[CONFIG_MAX_CPUS];

static inline uint64_t x86_read_gs_base(void) {
    uint32_t lo;
    uint32_t hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000101));
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

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

static inline int arch_cpu_id_stable(void) {
    uint64_t base = x86_read_gs_base();
    uint64_t start = (uint64_t)&x86_cpu_id_slots[0];
    uint64_t end = (uint64_t)&x86_cpu_id_slots[CONFIG_MAX_CPUS];
    if (base >= start && base < end) {
        uint64_t delta = base - start;
        if ((delta & (sizeof(uint64_t) - 1)) == 0)
            return (int)(delta / sizeof(uint64_t));
    }
    return 0;
}

static inline int arch_cpu_id(void) {
    return arch_cpu_id_stable();
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
