/**
 * kernel/arch/riscv64/irqchip.c - RISC-V IRQ backend mux (PLIC/AIA-IMSIC)
 */

#include <asm/arch.h>
#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/config.h>
#include <kairos/pci.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/spinlock.h>
#include <kairos/types.h>

#ifndef CONFIG_RISCV_AIA
#define CONFIG_RISCV_AIA 0
#endif

extern const struct irqchip_ops plic_ops;

#define RISCV_IMSIC_QEMU_S_BASE       0x28000000ULL
#define RISCV_IMSIC_MMIO_PAGE_SHIFT   12U
#define RISCV_IMSIC_MMIO_PAGE_SIZE    (1ULL << RISCV_IMSIC_MMIO_PAGE_SHIFT)
#define RISCV_IMSIC_MAX_ID            255U
#define RISCV_IMSIC_MSI_FIRST_ID      64U
#define RISCV_IMSIC_EIDELIVERY        0x70U
#define RISCV_IMSIC_EITHRESHOLD       0x72U
#define RISCV_IMSIC_EIE0              0xC0U
#define RISCV_TOPEI_ID_SHIFT          16U
#define RISCV_TOPEI_ID_MASK           0x7FFU

enum riscv_irq_backend {
    RISCV_IRQ_BACKEND_NONE = 0,
    RISCV_IRQ_BACKEND_PLIC = 1,
    RISCV_IRQ_BACKEND_IMSIC = 2,
};

static volatile enum riscv_irq_backend riscv_irq_backend_active =
    RISCV_IRQ_BACKEND_PLIC;
#if CONFIG_RISCV_AIA
static volatile int riscv_irq_backend_ready;
static bool riscv_irq_backend_none_warned;
#endif

static spinlock_t imsic_lock = SPINLOCK_INIT;
static volatile int imsic_state_ready;
static uint32_t imsic_affinity[RISCV_IMSIC_MAX_ID + 1];
static bool imsic_enabled[RISCV_IMSIC_MAX_ID + 1];
static bool imsic_msi_used[RISCV_IMSIC_MAX_ID + 1];
static uint16_t imsic_next_msi_id = RISCV_IMSIC_MSI_FIRST_ID;
static bool imsic_remote_affinity_warned;

static inline void imsic_select(unsigned long reg)
{
    __asm__ __volatile__("csrw siselect, %0" : : "r"(reg) : "memory");
}

static inline void imsic_write(unsigned long reg, unsigned long val)
{
    imsic_select(reg);
    __asm__ __volatile__("csrw sireg, %0" : : "r"(val) : "memory");
}

static inline void imsic_set_bits(unsigned long reg, unsigned long bits)
{
    imsic_select(reg);
    unsigned long val = 0;
    __asm__ __volatile__("csrr %0, sireg" : "=r"(val) : : "memory");
    val |= bits;
    __asm__ __volatile__("csrw sireg, %0" : : "r"(val) : "memory");
}

static inline void imsic_clear_bits(unsigned long reg, unsigned long bits)
{
    imsic_select(reg);
    unsigned long val = 0;
    __asm__ __volatile__("csrr %0, sireg" : "=r"(val) : : "memory");
    val &= ~bits;
    __asm__ __volatile__("csrw sireg, %0" : : "r"(val) : "memory");
}

static inline uint32_t imsic_claim_id(void)
{
    unsigned long topei = 0;
    __asm__ __volatile__("csrrw %0, stopei, zero"
                         : "=r"(topei)
                         :
                         : "memory");
    return (uint32_t)((topei >> RISCV_TOPEI_ID_SHIFT) & RISCV_TOPEI_ID_MASK);
}

static uint32_t imsic_valid_cpu_mask(void)
{
    int cpu_count = arch_cpu_count();
    if (cpu_count <= 0)
        cpu_count = 1;
    if (cpu_count > CONFIG_MAX_CPUS)
        cpu_count = CONFIG_MAX_CPUS;
#if CONFIG_MAX_CPUS >= 32
    return (cpu_count >= 32) ? UINT32_MAX : ((1U << cpu_count) - 1U);
#else
    return (1U << cpu_count) - 1U;
#endif
}

static uint32_t imsic_pick_target_cpu(uint32_t cpu_mask)
{
    cpu_mask &= imsic_valid_cpu_mask();
    if (!cpu_mask)
        return 0;
    return (uint32_t)__builtin_ctz(cpu_mask);
}

static uint64_t imsic_cpu_page_pa(uint32_t cpu)
{
    const struct boot_info *bi = boot_info_get();
    uint64_t hartid = cpu;
    if (bi && cpu < bi->cpu_count)
        hartid = bi->cpus[cpu].hw_id;
    return RISCV_IMSIC_QEMU_S_BASE +
           (hartid << RISCV_IMSIC_MMIO_PAGE_SHIFT);
}

static int imsic_local_set_enable(uint32_t id, bool enable)
{
    if (id == 0 || id > RISCV_IMSIC_MAX_ID)
        return -EINVAL;
    if (arch_cpu_id() != 0)
        return 0;

    unsigned long isel = (unsigned long)(RISCV_IMSIC_EIE0 + (id / 32U));
    unsigned long bit = 1UL << (id % 32U);
    if (enable)
        imsic_set_bits(isel, bit);
    else
        imsic_clear_bits(isel, bit);
    return 0;
}

static int imsic_apply_local_state(uint32_t id)
{
    if (id == 0 || id > RISCV_IMSIC_MAX_ID)
        return -EINVAL;

    uint32_t cpu = (uint32_t)arch_cpu_id();
    bool enable = imsic_enabled[id];
    uint32_t affinity = imsic_affinity[id] & imsic_valid_cpu_mask();
    if (!affinity)
        affinity = 1U;
    imsic_affinity[id] = affinity;

    bool local_target = (cpu < 32U) && ((affinity & (1U << cpu)) != 0);
    return imsic_local_set_enable(id, enable && local_target);
}

static void __attribute__((unused)) imsic_init(const struct platform_desc *plat)
{
    (void)plat;

    if (__sync_bool_compare_and_swap(&imsic_state_ready, 0, 1)) {
        spin_init(&imsic_lock);
        for (uint32_t i = 0; i <= RISCV_IMSIC_MAX_ID; i++) {
            imsic_affinity[i] = 1U;
            imsic_enabled[i] = false;
            imsic_msi_used[i] = false;
        }
        imsic_remote_affinity_warned = false;
        imsic_next_msi_id = RISCV_IMSIC_MSI_FIRST_ID;
        __sync_synchronize();
        imsic_state_ready = 2;
    }
    while (imsic_state_ready != 2)
        arch_cpu_relax();
    if (arch_cpu_id() != 0)
        return;

    imsic_write(RISCV_IMSIC_EITHRESHOLD, 0);
    imsic_write(RISCV_IMSIC_EIDELIVERY, 1);

    bool irq_state;
    spin_lock_irqsave(&imsic_lock, &irq_state);
    for (uint32_t id = 1; id <= RISCV_IMSIC_MAX_ID; id++)
        (void)imsic_apply_local_state(id);
    spin_unlock_irqrestore(&imsic_lock, irq_state);

    if (arch_cpu_id() == 0) {
        pr_info("irqchip: using IMSIC backend (QEMU virt AIA, base=%p)\n",
                (void *)(uintptr_t)RISCV_IMSIC_QEMU_S_BASE);
    }
}

static void imsic_enable(int irq)
{
    if (irq <= 0 || irq > (int)RISCV_IMSIC_MAX_ID)
        return;

    bool irq_state;
    spin_lock_irqsave(&imsic_lock, &irq_state);
    imsic_enabled[(uint32_t)irq] = true;
    (void)imsic_apply_local_state((uint32_t)irq);
    spin_unlock_irqrestore(&imsic_lock, irq_state);
}

static void imsic_disable(int irq)
{
    if (irq <= 0 || irq > (int)RISCV_IMSIC_MAX_ID)
        return;

    bool irq_state;
    spin_lock_irqsave(&imsic_lock, &irq_state);
    imsic_enabled[(uint32_t)irq] = false;
    (void)imsic_apply_local_state((uint32_t)irq);
    spin_unlock_irqrestore(&imsic_lock, irq_state);
}

static int imsic_set_type(int irq, uint32_t type)
{
    (void)irq;
    (void)type;
    return 0;
}

static int imsic_set_affinity(int irq, uint32_t cpu_mask)
{
    if (irq <= 0 || irq > (int)RISCV_IMSIC_MAX_ID)
        return -EINVAL;

    cpu_mask &= imsic_valid_cpu_mask();
    if (!cpu_mask)
        return -EINVAL;

    bool irq_state;
    spin_lock_irqsave(&imsic_lock, &irq_state);
    imsic_affinity[(uint32_t)irq] = cpu_mask;
    (void)imsic_apply_local_state((uint32_t)irq);
    spin_unlock_irqrestore(&imsic_lock, irq_state);
    return 0;
}

static uint32_t imsic_ack(void)
{
    if (arch_cpu_id() != 0)
        return 0;
    return imsic_claim_id();
}

static void imsic_eoi(uint32_t irq)
{
    (void)irq;
}

static void riscv_irqchip_init(const struct platform_desc *plat)
{
#if CONFIG_RISCV_AIA
    if (__sync_bool_compare_and_swap(&riscv_irq_backend_ready, 0, 1)) {
        if (__arch_imsic_csr_probe() == 0) {
            riscv_irq_backend_active = RISCV_IRQ_BACKEND_IMSIC;
        } else {
            riscv_irq_backend_active = RISCV_IRQ_BACKEND_NONE;
            if (arch_cpu_id() == 0) {
                pr_warn("irqchip: IMSIC CSR access unavailable; fallback to no-op backend\n");
            }
        }
        __sync_synchronize();
        riscv_irq_backend_ready = 2;
    }
    while (riscv_irq_backend_ready != 2)
        arch_cpu_relax();

    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_IMSIC) {
        imsic_init(plat);
        return;
    }
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_NONE)
        return;
#else
    riscv_irq_backend_active = RISCV_IRQ_BACKEND_PLIC;
#endif

    if (plic_ops.init)
        plic_ops.init(plat);
}

static void riscv_irqchip_enable(int irq)
{
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_IMSIC) {
        imsic_enable(irq);
        return;
    }
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_NONE)
        return;
    if (plic_ops.enable)
        plic_ops.enable(irq);
}

static void riscv_irqchip_disable(int irq)
{
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_IMSIC) {
        imsic_disable(irq);
        return;
    }
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_NONE)
        return;
    if (plic_ops.disable)
        plic_ops.disable(irq);
}

static int riscv_irqchip_set_type(int irq, uint32_t type)
{
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_IMSIC)
        return imsic_set_type(irq, type);
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_NONE)
        return -EOPNOTSUPP;
    if (plic_ops.set_type)
        return plic_ops.set_type(irq, type);
    return 0;
}

static int riscv_irqchip_set_affinity(int irq, uint32_t cpu_mask)
{
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_IMSIC)
        return imsic_set_affinity(irq, cpu_mask);
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_NONE)
        return -EOPNOTSUPP;
    if (plic_ops.set_affinity)
        return plic_ops.set_affinity(irq, cpu_mask);
    return -EOPNOTSUPP;
}

static uint32_t riscv_irqchip_ack(void)
{
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_IMSIC)
        return imsic_ack();
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_NONE)
        return 0;
    if (plic_ops.ack)
        return plic_ops.ack();
    return 0;
}

static void riscv_irqchip_eoi(uint32_t irq)
{
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_IMSIC) {
        imsic_eoi(irq);
        return;
    }
    if (riscv_irq_backend_active == RISCV_IRQ_BACKEND_NONE) {
#if CONFIG_RISCV_AIA
        if (!riscv_irq_backend_none_warned && arch_cpu_id() == 0) {
            pr_warn("irqchip: no external IRQ backend active; MSI/MSI-X routing disabled\n");
            riscv_irq_backend_none_warned = true;
        }
#endif
        return;
    }
    if (plic_ops.eoi)
        plic_ops.eoi(irq);
}

const struct irqchip_ops riscv_irqchip_ops = {
    .init = riscv_irqchip_init,
    .enable = riscv_irqchip_enable,
    .disable = riscv_irqchip_disable,
    .set_type = riscv_irqchip_set_type,
    .set_affinity = riscv_irqchip_set_affinity,
    .ack = riscv_irqchip_ack,
    .eoi = riscv_irqchip_eoi,
};

static int imsic_pci_compose_msg(uint8_t irq, uint32_t cpu_mask,
                                 struct pci_msi_msg *msg)
{
    if (!msg)
        return -EINVAL;
    if (irq == 0 || irq > RISCV_IMSIC_MAX_ID)
        return -EINVAL;

    cpu_mask &= imsic_valid_cpu_mask();
    if (!cpu_mask)
        return -EINVAL;

    uint32_t target_cpu = imsic_pick_target_cpu(cpu_mask);
    if (target_cpu != (uint32_t)arch_cpu_id()) {
        if (!imsic_remote_affinity_warned) {
            pr_warn("pci: riscv IMSIC remote affinity is not yet synchronized across harts; keeping local target\n");
            imsic_remote_affinity_warned = true;
        }
        return -EOPNOTSUPP;
    }

    uint64_t addr = imsic_cpu_page_pa(target_cpu);
    msg->address_lo = (uint32_t)addr;
    msg->address_hi = (uint32_t)(addr >> 32);
    msg->data = irq;
    msg->irq = irq;
    return 0;
}

int riscv_irqchip_pci_msi_setup(const struct pci_device *pdev,
                                struct pci_msi_msg *msg)
{
    (void)pdev;
    if (!msg)
        return -EINVAL;
    if (riscv_irq_backend_active != RISCV_IRQ_BACKEND_IMSIC)
        return -EOPNOTSUPP;

    bool irq_state;
    spin_lock_irqsave(&imsic_lock, &irq_state);

    uint16_t start = imsic_next_msi_id;
    uint16_t id = start;
    int ret = -ENOSPC;
    do {
        if (!imsic_msi_used[id]) {
            imsic_msi_used[id] = true;
            imsic_enabled[id] = true;
            imsic_affinity[id] = 1U;
            imsic_next_msi_id =
                (id == RISCV_IMSIC_MAX_ID) ? RISCV_IMSIC_MSI_FIRST_ID
                                           : (uint16_t)(id + 1U);
            ret = 0;
            break;
        }
        id = (id == RISCV_IMSIC_MAX_ID) ? RISCV_IMSIC_MSI_FIRST_ID
                                        : (uint16_t)(id + 1U);
    } while (id != start);

    if (ret == 0)
        (void)imsic_apply_local_state(id);

    spin_unlock_irqrestore(&imsic_lock, irq_state);
    if (ret < 0)
        return ret;

    return imsic_pci_compose_msg((uint8_t)id, 1U, msg);
}

int riscv_irqchip_pci_msi_affinity_msg(const struct pci_device *pdev, uint8_t irq,
                                       uint32_t cpu_mask,
                                       struct pci_msi_msg *msg)
{
    (void)pdev;
    if (!msg)
        return -EINVAL;
    if (riscv_irq_backend_active != RISCV_IRQ_BACKEND_IMSIC)
        return -EOPNOTSUPP;

    cpu_mask &= imsic_valid_cpu_mask();
    if (!cpu_mask)
        return -EINVAL;

    bool irq_state;
    spin_lock_irqsave(&imsic_lock, &irq_state);
    if (irq == 0 || irq > RISCV_IMSIC_MAX_ID || !imsic_msi_used[irq]) {
        spin_unlock_irqrestore(&imsic_lock, irq_state);
        return -EINVAL;
    }
    imsic_affinity[irq] = cpu_mask;
    (void)imsic_apply_local_state(irq);
    spin_unlock_irqrestore(&imsic_lock, irq_state);

    return imsic_pci_compose_msg(irq, cpu_mask, msg);
}
