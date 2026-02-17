/**
 * kernel/arch/aarch64/gic.c - GICv3 interrupt controller
 *
 * Uses system registers for CPU interface (ICC_*), MMIO for
 * Distributor (GICD) and Redistributor (GICR).
 */

#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/types.h>

/* GICD (Distributor) — MMIO */
#define GICD_BASE       0x08000000UL
#define GICD_CTLR       0x000
#define GICD_TYPER      0x004
#define GICD_ISENABLER  0x100
#define GICD_ICENABLER  0x180
#define GICD_IPRIORITYR 0x400
#define GICD_ITARGETSR  0x800
#define GICD_ICFGR      0xC00

#define GICD_CTLR_ARE_S     (1U << 4)
#define GICD_CTLR_ENABLE_G1 (1U << 1)

/* GICR (Redistributor) — MMIO */
#define GICR_BASE       0x080A0000UL
#define GICR_WAKER      0x014
#define GICR_WAKER_PSLEEP    (1U << 1)
#define GICR_WAKER_CASLEEP   (1U << 2)
#define GICR_SGI_BASE   0x10000
#define GICR_ISENABLER0 (GICR_SGI_BASE + 0x100)
#define GICR_ICENABLER0 (GICR_SGI_BASE + 0x180)
#define GICR_IPRIORITYR (GICR_SGI_BASE + 0x400)

static volatile uint32_t *gicd;
static volatile uint8_t  *gicr;

/* --- System register accessors (GICv3 CPU interface) --- */

static inline void gic_write_icc_sre(uint64_t val) {
    __asm__ __volatile__("msr S3_0_C12_C12_5, %0" :: "r"(val));
}

static inline void gic_write_icc_pmr(uint64_t val) {
    __asm__ __volatile__("msr S3_0_C4_C6_0, %0" :: "r"(val));
}

static inline void gic_write_icc_igrpen1(uint64_t val) {
    __asm__ __volatile__("msr S3_0_C12_C12_7, %0" :: "r"(val));
}

static inline uint64_t gic_read_icc_iar1(void) {
    uint64_t val;
    __asm__ __volatile__("mrs %0, S3_0_C12_C12_0" : "=r"(val));
    return val;
}

static inline void gic_write_icc_eoir1(uint64_t val) {
    __asm__ __volatile__("msr S3_0_C12_C12_1, %0" :: "r"(val));
}

static inline void gic_write_icc_sgi1r(uint64_t val) {
    __asm__ __volatile__("msr S3_0_C12_C11_5, %0" :: "r"(val));
}

/* --- Redistributor helpers --- */

static void gicr_wake(void) {
    volatile uint32_t *waker = (volatile uint32_t *)(gicr + GICR_WAKER);
    uint32_t val = *waker;
    val &= ~GICR_WAKER_PSLEEP;
    *waker = val;

    /* Wait for ChildrenAsleep to clear */
    while (*waker & GICR_WAKER_CASLEEP)
        ;
}

/* --- Public interface --- */

void gic_init(void) {
    gicd = (volatile uint32_t *)ioremap(GICD_BASE, 0x10000);
    gicr = (volatile uint8_t *)ioremap(GICR_BASE, 0x20000);

    /* Distributor: enable ARE + Group1 */
    gicd[GICD_CTLR / 4] = GICD_CTLR_ARE_S | GICD_CTLR_ENABLE_G1;

    /* Wake up this CPU's Redistributor */
    gicr_wake();

    /* Set all SGI/PPI priorities to 0xA0 (via Redistributor) */
    for (int i = 0; i < 32; i++) {
        gicr[GICR_IPRIORITYR + i] = 0xA0;
    }

    /* CPU interface via system registers */
    gic_write_icc_sre(1);       /* Enable system register interface */
    __asm__ __volatile__("isb");
    gic_write_icc_pmr(0xFF);    /* Allow all priorities */
    gic_write_icc_igrpen1(1);   /* Enable Group1 interrupts */
    __asm__ __volatile__("isb");

    pr_info("GIC: GICv3 initialized\n");
}

uint32_t gic_ack_irq(void) {
    return (uint32_t)gic_read_icc_iar1();
}

void gic_eoi(uint32_t irq) {
    gic_write_icc_eoir1((uint64_t)irq);
}

void gic_enable_irq(uint32_t irq) {
    if (irq < 32) {
        /* SGI/PPI: via Redistributor */
        volatile uint32_t *reg =
            (volatile uint32_t *)(gicr + GICR_ISENABLER0);
        *reg = (1U << irq);
    } else {
        /* SPI: via Distributor */
        gicd[(GICD_ISENABLER / 4) + (irq / 32)] = (1U << (irq % 32));
    }
}

void gic_disable_irq(uint32_t irq) {
    if (irq < 32) {
        volatile uint32_t *reg =
            (volatile uint32_t *)(gicr + GICR_ICENABLER0);
        *reg = (1U << irq);
    } else {
        gicd[(GICD_ICENABLER / 4) + (irq / 32)] = (1U << (irq % 32));
    }
}

void gic_set_priority(uint32_t irq, uint8_t prio) {
    if (irq < 32) {
        gicr[GICR_IPRIORITYR + irq] = prio;
    } else {
        volatile uint8_t *d = (volatile uint8_t *)gicd;
        d[GICD_IPRIORITYR + irq] = prio;
    }
}

void gic_send_sgi(uint32_t cpu, uint32_t intid) {
    /* GICv3 SGI: ICC_SGI1R_EL1
     * Bits [23:16] = target list, [27:24] = Aff1, etc.
     * For simple single-cluster: target_list = (1 << cpu), INTID in [27:24]
     * Actually: INTID is bits [27:24], target list is bits [15:0]
     */
    uint64_t val = ((uint64_t)(intid & 0xf) << 24) | (1ULL << cpu);
    gic_write_icc_sgi1r(val);
}
