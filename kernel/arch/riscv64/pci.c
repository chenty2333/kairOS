/**
 * kernel/arch/riscv64/pci.c - RISC-V PCI host controller init (ECAM)
 *
 * Implements arch_pci_host_init() by finding the pci-host-ecam-generic
 * firmware descriptor registered by the FDT scanner, then ioremap-ing
 * the ECAM region and populating the pci_host structure.
 */

#include <kairos/pci.h>
#include <kairos/firmware.h>
#include <kairos/device.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>

static bool riscv64_msi_warned;

struct pci_host_match {
    struct pci_host *host;
    bool found;
};

static int pci_ecam_match(struct fw_device_desc *desc, void *arg)
{
    struct pci_host_match *m = arg;

    if (strcmp(desc->compatible, "pci-host-ecam-generic") != 0)
        return 0;

    /* Find ECAM MMIO resource */
    paddr_t ecam_base = 0;
    size_t ecam_size = 0;
    uint32_t irq_base = 32; /* default PLIC INTx base */

    for (size_t i = 0; i < desc->num_resources; i++) {
        if (desc->resources[i].flags == IORESOURCE_MEM) {
            ecam_base = (paddr_t)desc->resources[i].start;
            ecam_size = (size_t)(desc->resources[i].end -
                                  desc->resources[i].start + 1);
        } else if (desc->resources[i].flags == IORESOURCE_IRQ) {
            irq_base = (uint32_t)desc->resources[i].start;
        }
    }

    if (!ecam_base || !ecam_size) {
        pr_err("pci: ecam descriptor missing MMIO resource\n");
        return 0;
    }

    m->host->ecam_base = ioremap(ecam_base, ecam_size);
    m->host->bus_start = 0;
    m->host->bus_end = 255;
    m->host->irq_base = irq_base;
    m->found = true;

    pr_info("pci: ecam @ %p-%p mapped, irq_base %u\n",
            (void *)ecam_base,
            (void *)(ecam_base + ecam_size - 1),
            irq_base);

    return 1; /* stop iteration */
}

int arch_pci_host_init(struct pci_host *host)
{
    struct pci_host_match m = { .host = host, .found = false };

    fw_for_each_desc(pci_ecam_match, &m);

    if (!m.found)
        return -ENODEV;

    return 0;
}

int arch_pci_msi_setup(const struct pci_device *pdev, struct pci_msi_msg *msg)
{
    (void)pdev;
    (void)msg;

    if (!riscv64_msi_warned) {
        pr_warn("pci: riscv64 MSI backend requires AIA/IMSIC; current PLIC path remains INTx-only\n");
        riscv64_msi_warned = true;
    }
    return -EOPNOTSUPP;
}

int arch_pci_msi_affinity_msg(const struct pci_device *pdev, uint8_t irq,
                              uint32_t cpu_mask, struct pci_msi_msg *msg)
{
    (void)pdev;
    (void)irq;
    (void)cpu_mask;
    (void)msg;
    return -EOPNOTSUPP;
}
