/**
 * kernel/arch/aarch64/gic.c - GICv3 irqchip_ops implementation
 *
 * Uses system registers for CPU interface (ICC_*), MMIO for
 * Distributor (GICD) and Redistributor (GICR).
 */

#include <kairos/mm.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/types.h>

/* GICD register offsets */
#define GICD_CTLR       0x000
#define GICD_ISENABLER  0x100
#define GICD_ICENABLER  0x180
#define GICD_IPRIORITYR 0x400

#define GICD_CTLR_ARE_S     (1U << 4)
#define GICD_CTLR_ENABLE_G1 (1U << 1)

/* GICR register offsets (relative to GICR base) */
#define GICR_WAKER      0x014
#define GICR_WAKER_PSLEEP    (1U << 1)
#define GICR_WAKER_CASLEEP   (1U << 2)
#define GICR_SGI_BASE   0x10000
#define GICR_ISENABLER0 (GICR_SGI_BASE + 0x100)
#define GICR_ICENABLER0 (GICR_SGI_BASE + 0x180)
#define GICR_IPRIORITYR (GICR_SGI_BASE + 0x400)
#define GICR_STRIDE     0x20000

/* WARN: GICR offset 0xA0000 from GICD is QEMU virt specific */
#define GICR_OFFSET     0xA0000

static volatile uint32_t *gicd;
static volatile uint8_t  *gicr_base;
static volatile int gicd_ready;

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

static inline volatile uint8_t *gicr_local(void) {
    int cpu = arch_cpu_id();
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        cpu = 0;
    return gicr_base + ((size_t)cpu * GICR_STRIDE);
}

static void gicr_wake(volatile uint8_t *gicr)
{
    volatile uint32_t *waker = (volatile uint32_t *)(gicr + GICR_WAKER);
    uint32_t val = *waker;
    val &= ~GICR_WAKER_PSLEEP;
    *waker = val;
    while (*waker & GICR_WAKER_CASLEEP)
        ;
}

static void gicv3_init(const struct platform_desc *plat)
{
    if (!gicd || !gicr_base) {
        paddr_t gic_base = plat->early_mmio[0].base;
        gicd = (volatile uint32_t *)ioremap(gic_base, 0x10000);
        gicr_base = (volatile uint8_t *)ioremap(
            gic_base + GICR_OFFSET, GICR_STRIDE * CONFIG_MAX_CPUS);
    }
    if (!gicd || !gicr_base)
        return;

    if (__sync_bool_compare_and_swap(&gicd_ready, 0, 1))
        gicd[GICD_CTLR / 4] = GICD_CTLR_ARE_S | GICD_CTLR_ENABLE_G1;

    volatile uint8_t *gicr = gicr_local();
    gicr_wake(gicr);

    for (int i = 0; i < 32; i++)
        gicr[GICR_IPRIORITYR + i] = 0xA0;

    gic_write_icc_sre(1);
    __asm__ __volatile__("isb");
    gic_write_icc_pmr(0xFF);
    gic_write_icc_igrpen1(1);
    __asm__ __volatile__("isb");

    if (arch_cpu_id() == 0)
        pr_info("GIC: GICv3 initialized\n");
}

static void gicv3_enable(int irq)
{
    uint32_t uirq = (uint32_t)irq;
    if (uirq < 32) {
        volatile uint8_t *gicr = gicr_local();
        volatile uint32_t *reg =
            (volatile uint32_t *)(gicr + GICR_ISENABLER0);
        *reg = (1U << uirq);
    } else {
        gicd[(GICD_ISENABLER / 4) + (uirq / 32)] = (1U << (uirq % 32));
    }
}

static void gicv3_disable(int irq)
{
    uint32_t uirq = (uint32_t)irq;
    if (uirq < 32) {
        volatile uint8_t *gicr = gicr_local();
        volatile uint32_t *reg =
            (volatile uint32_t *)(gicr + GICR_ICENABLER0);
        *reg = (1U << uirq);
    } else {
        gicd[(GICD_ICENABLER / 4) + (uirq / 32)] = (1U << (uirq % 32));
    }
}

static uint32_t gicv3_ack(void)
{
    return (uint32_t)gic_read_icc_iar1();
}

static void gicv3_eoi(uint32_t irq)
{
    gic_write_icc_eoir1((uint64_t)irq);
}

void gic_send_sgi(uint32_t cpu, uint32_t intid)
{
    uint64_t val = ((uint64_t)(intid & 0xf) << 24) | (1ULL << cpu);
    gic_write_icc_sgi1r(val);
}

const struct irqchip_ops gicv3_ops = {
    .init     = gicv3_init,
    .enable   = gicv3_enable,
    .disable  = gicv3_disable,
    .ack      = gicv3_ack,
    .eoi      = gicv3_eoi,
    .send_sgi = gic_send_sgi,
};
