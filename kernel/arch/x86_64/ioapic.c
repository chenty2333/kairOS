/**
 * kernel/arch/x86_64/ioapic.c - IOAPIC
 */

#include <kairos/mm.h>
#include <kairos/types.h>

#define IOAPIC_BASE_PHYS 0xFEC00000UL

#define IOAPIC_REGSEL 0x00
#define IOAPIC_WINDOW 0x10

#define IOAPIC_REDTBL 0x10

static volatile uint32_t *ioapic_base;

static inline void ioapic_write(uint32_t reg, uint32_t val) {
    ioapic_base[IOAPIC_REGSEL / 4] = reg;
    ioapic_base[IOAPIC_WINDOW / 4] = val;
}

static inline uint32_t ioapic_read(uint32_t reg) {
    ioapic_base[IOAPIC_REGSEL / 4] = reg;
    return ioapic_base[IOAPIC_WINDOW / 4];
}

void ioapic_route_irq(int irq, int vector, int cpu, bool masked) {
    if (!ioapic_base || irq < 0)
        return;
    uint32_t low = (uint32_t)vector & 0xFF;
    if (masked)
        low |= 0x10000;
    uint32_t high = (uint32_t)(cpu & 0xFF) << 24;
    ioapic_write(IOAPIC_REDTBL + irq * 2, low);
    ioapic_write(IOAPIC_REDTBL + irq * 2 + 1, high);
}

void ioapic_init(void) {
    ioapic_base = (volatile uint32_t *)ioremap(IOAPIC_BASE_PHYS, 4096);
    for (int i = 0; i < 24; i++) {
        ioapic_write(IOAPIC_REDTBL + i * 2, 0x10000 | (32 + i));
        ioapic_write(IOAPIC_REDTBL + i * 2 + 1, 0);
    }
}
