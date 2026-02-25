/**
 * kernel/arch/x86_64/pci.c - x86_64 PCI MSI message setup
 */

#include <kairos/boot.h>
#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/pci.h>
#include <kairos/types.h>

#define X86_MSI_ADDR_BASE 0xFEE00000U
#define X86_IRQ_VECTOR_BASE 32U

static uint8_t x86_msi_pick_irq(const struct pci_device *pdev)
{
    if (pdev && pdev->intx_irq_line > 0 && pdev->intx_irq_line < 24)
        return pdev->intx_irq_line;

    static const uint8_t fallback_irqs[] = { 16, 17, 18, 19, 20, 21, 22, 23 };
    static uint32_t next_idx;
    uint32_t idx = __atomic_fetch_add(&next_idx, 1, __ATOMIC_RELAXED);
    return fallback_irqs[idx % ARRAY_SIZE(fallback_irqs)];
}

static uint32_t x86_msi_sanitize_mask(uint32_t cpu_mask)
{
#if CONFIG_MAX_CPUS >= 32
    uint32_t valid_mask = UINT32_MAX;
#else
    uint32_t valid_mask = (1U << CONFIG_MAX_CPUS) - 1U;
#endif
    return cpu_mask & valid_mask;
}

static uint8_t x86_msi_pick_cpu(uint32_t cpu_mask)
{
    cpu_mask = x86_msi_sanitize_mask(cpu_mask);
    if (!cpu_mask)
        return 0;
    return (uint8_t)__builtin_ctz(cpu_mask);
}

static uint8_t x86_msi_apic_id_for_cpu(uint8_t cpu)
{
    const struct boot_info *bi = boot_info_get();
    if (bi && cpu < bi->cpu_count)
        return (uint8_t)(bi->cpus[cpu].hw_id & 0xffU);
    return cpu;
}

int arch_pci_msi_affinity_msg(const struct pci_device *pdev, uint8_t irq,
                              uint32_t cpu_mask, struct pci_msi_msg *msg)
{
    if (!pdev || !msg)
        return -EINVAL;

    cpu_mask = x86_msi_sanitize_mask(cpu_mask);
    if (!cpu_mask)
        return -EINVAL;

    uint16_t vector = (uint16_t)(X86_IRQ_VECTOR_BASE + irq);
    if (vector < 32 || vector > 255)
        return -EOPNOTSUPP;

    uint8_t target_cpu = x86_msi_pick_cpu(cpu_mask);
    uint8_t lapic_id = x86_msi_apic_id_for_cpu(target_cpu);
    msg->address_lo = X86_MSI_ADDR_BASE | ((uint32_t)lapic_id << 12);
    msg->address_hi = 0;
    msg->data = vector;
    msg->irq = irq;
    return 0;
}

int arch_pci_msi_setup(const struct pci_device *pdev, struct pci_msi_msg *msg)
{
    if (!pdev || !msg)
        return -EINVAL;

    uint8_t irq = x86_msi_pick_irq(pdev);
    uint8_t this_cpu = (uint8_t)arch_cpu_id();
    uint32_t cpu_mask = 1U;
    if (this_cpu < 32)
        cpu_mask = 1U << this_cpu;
    if (cpu_mask == 0)
        cpu_mask = 1U;
    return arch_pci_msi_affinity_msg(pdev, irq, cpu_mask, msg);
}
