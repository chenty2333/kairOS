/**
 * kernel/include/kairos/io.h - I/O Access Primitives
 *
 * Standard I/O accessors for MMIO regions.
 * Ensures compiler does not reorder or optimize away memory accesses.
 */

#ifndef _KAIROS_IO_H
#define _KAIROS_IO_H

#include <kairos/types.h>

/* 
 * Memory barriers for RISC-V
 * fence i, o: Ordering between all memory reads (i) and all memory writes (o)
 */
#define mb()  __asm__ __volatile__ ("fence i, o" ::: "memory")
#define rmb() __asm__ __volatile__ ("fence i, i" ::: "memory")
#define wmb() __asm__ __volatile__ ("fence o, o" ::: "memory")

/* 8-bit access */
static inline uint8_t readb(const volatile void *addr) {
    uint8_t val = *(const volatile uint8_t *)addr;
    rmb();
    return val;
}

static inline void writeb(uint8_t value, volatile void *addr) {
    wmb();
    *(volatile uint8_t *)addr = value;
}

/* 16-bit access */
static inline uint16_t readw(const volatile void *addr) {
    uint16_t val = *(const volatile uint16_t *)addr;
    rmb();
    return val;
}

static inline void writew(uint16_t value, volatile void *addr) {
    wmb();
    *(volatile uint16_t *)addr = value;
}

/* 32-bit access */
static inline uint32_t readl(const volatile void *addr) {
    uint32_t val = *(const volatile uint32_t *)addr;
    rmb();
    return val;
}

static inline void writel(uint32_t value, volatile void *addr) {
    wmb();
    *(volatile uint32_t *)addr = value;
}

/* 64-bit access */
static inline uint64_t readq(const volatile void *addr) {
    uint64_t val = *(const volatile uint64_t *)addr;
    rmb();
    return val;
}

static inline void writeq(uint64_t value, volatile void *addr) {
    wmb();
    *(volatile uint64_t *)addr = value;
}

#endif
