/**
 * kernel/arch/x86_64/pci.c - x86_64 PCI MSI message setup
 */

#include <kairos/pci.h>
#include <kairos/types.h>

#define X86_LAPIC_ID_REG 0x20
#define X86_MSI_ADDR_BASE 0xFEE00000U
#define X86_IRQ_VECTOR_BASE 32U

extern uint32_t lapic_read(uint32_t reg);

static uint8_t x86_msi_pick_irq(const struct pci_device *pdev)
{
    if (pdev && pdev->intx_irq_line > 0 && pdev->intx_irq_line < 24)
        return pdev->intx_irq_line;

    static const uint8_t fallback_irqs[] = { 16, 17, 18, 19, 20, 21, 22, 23 };
    static uint32_t next_idx;
    uint32_t idx = __atomic_fetch_add(&next_idx, 1, __ATOMIC_RELAXED);
    return fallback_irqs[idx % ARRAY_SIZE(fallback_irqs)];
}

int arch_pci_msi_setup(const struct pci_device *pdev, struct pci_msi_msg *msg)
{
    if (!pdev || !msg)
        return -EINVAL;

    uint8_t irq = x86_msi_pick_irq(pdev);
    uint16_t vector = (uint16_t)(X86_IRQ_VECTOR_BASE + irq);
    if (vector < 32 || vector > 255)
        return -EOPNOTSUPP;

    uint32_t lapic_id = (lapic_read(X86_LAPIC_ID_REG) >> 24) & 0xffU;
    msg->address_lo = X86_MSI_ADDR_BASE | (lapic_id << 12);
    msg->address_hi = 0;
    msg->data = vector;
    msg->irq = irq;
    return 0;
}
