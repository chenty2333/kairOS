/**
 * kernel/arch/x86_64/apic.c - Local APIC
 */

#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/types.h>

#define LAPIC_BASE_PHYS 0xFEE00000UL

#define LAPIC_ID       0x20
#define LAPIC_EOI      0xB0
#define LAPIC_SVR      0xF0
#define LAPIC_ESR      0x280
#define LAPIC_ICR_LOW  0x300
#define LAPIC_ICR_HIGH 0x310
#define LAPIC_LVT_TIMER 0x320
#define LAPIC_TIMER_INIT 0x380
#define LAPIC_TIMER_CURR 0x390
#define LAPIC_TIMER_DIV  0x3E0

static volatile uint32_t *lapic_base;

static inline void lapic_write(uint32_t reg, uint32_t val) {
    lapic_base[reg / 4] = val;
    lapic_base[reg / 4];
}

uint32_t lapic_read(uint32_t reg) {
    return lapic_base[reg / 4];
}

void lapic_init(void) {
    lapic_base = (volatile uint32_t *)ioremap(LAPIC_BASE_PHYS, 4096);
    lapic_write(LAPIC_SVR, 0x100 | 0xFF); /* enable, spurious vector */
    lapic_write(LAPIC_ESR, 0);
    lapic_write(LAPIC_TIMER_DIV, 0x3);
}

void lapic_eoi(void) {
    if (lapic_base)
        lapic_write(LAPIC_EOI, 0);
}

void lapic_send_ipi(uint32_t apic_id, uint32_t vector) {
    lapic_write(LAPIC_ICR_HIGH, apic_id << 24);
    lapic_write(LAPIC_ICR_LOW, vector | (0x0 << 8));
}

void lapic_timer_init(uint32_t hz) {
    (void)hz;
    lapic_write(LAPIC_LVT_TIMER, 0x20000 | 0x20); /* periodic, vector 32 */
}
