/**
 * kernel/arch/aarch64/gic.c - GICv2 controller
 */

#include <kairos/mm.h>
#include <kairos/types.h>

#define GICD_BASE 0x08000000UL
#define GICC_BASE 0x08010000UL

#define GICD_CTLR 0x000
#define GICD_ISENABLER 0x100
#define GICD_ICENABLER 0x180
#define GICD_IPRIORITYR 0x400

#define GICC_CTLR 0x0000
#define GICC_PMR  0x0004
#define GICC_IAR  0x000C
#define GICC_EOIR 0x0010
#define GICD_SGIR 0xF00

static volatile uint32_t *gicd;
static volatile uint32_t *gicc;

void gic_init(void) {
    gicd = (volatile uint32_t *)ioremap(GICD_BASE, 0x1000);
    gicc = (volatile uint32_t *)ioremap(GICC_BASE, 0x1000);
    gicd[GICD_CTLR / 4] = 1;
    gicc[GICC_PMR / 4] = 0xFF;
    gicc[GICC_CTLR / 4] = 1;
}

uint32_t gic_ack_irq(void) {
    return gicc[GICC_IAR / 4];
}

void gic_eoi(uint32_t irq) {
    gicc[GICC_EOIR / 4] = irq;
}

void gic_enable_irq(uint32_t irq) {
    gicd[(GICD_ISENABLER / 4) + (irq / 32)] = (1U << (irq % 32));
}

void gic_disable_irq(uint32_t irq) {
    gicd[(GICD_ICENABLER / 4) + (irq / 32)] = (1U << (irq % 32));
}

void gic_set_priority(uint32_t irq, uint8_t prio) {
    gicd[(GICD_IPRIORITYR / 4) + irq] = prio;
}

void gic_send_sgi(uint32_t cpu, uint32_t intid) {
    uint32_t val = (1U << (16 + cpu)) | (intid & 0x0F);
    gicd[GICD_SGIR / 4] = val;
}
