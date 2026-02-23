/**
 * kernel/arch/aarch64/pci.c - AArch64 PCI host controller init (ACPI MCFG)
 *
 * Uses ACPI RSDP -> XSDT/RSDT -> MCFG to discover PCI ECAM range under
 * UEFI/ACPI boot on QEMU virt.
 */

#include <kairos/boot.h>
#include <kairos/mm.h>
#include <kairos/pci.h>
#include <kairos/printk.h>
#include <kairos/string.h>

struct acpi_rsdp {
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_addr;
    uint32_t length;
    uint64_t xsdt_addr;
    uint8_t ext_checksum;
    uint8_t reserved[3];
} __packed;

struct acpi_sdt_header {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __packed;

struct acpi_mcfg {
    struct acpi_sdt_header hdr;
    uint64_t reserved;
} __packed;

struct acpi_mcfg_entry {
    uint64_t ecam_base;
    uint16_t segment;
    uint8_t bus_start;
    uint8_t bus_end;
    uint32_t reserved;
} __packed;

static bool acpi_checksum_ok(const void *data, size_t len) {
    const uint8_t *p = data;
    uint8_t sum = 0;

    for (size_t i = 0; i < len; i++)
        sum = (uint8_t)(sum + p[i]);

    return sum == 0;
}

static const struct acpi_sdt_header *acpi_map_sdt(uint64_t phys) {
    if (!phys)
        return NULL;

    const struct acpi_sdt_header *hdr =
        (const struct acpi_sdt_header *)phys_to_virt((paddr_t)phys);
    if (!hdr)
        return NULL;
    if (hdr->length < sizeof(*hdr))
        return NULL;
    if (!acpi_checksum_ok(hdr, hdr->length))
        return NULL;

    return hdr;
}

static const struct acpi_sdt_header *acpi_find_sdt(
    const struct acpi_rsdp *rsdp, const char sig[4]) {
    if (!rsdp)
        return NULL;

    if (rsdp->revision >= 2 && rsdp->xsdt_addr) {
        const struct acpi_sdt_header *xsdt = acpi_map_sdt(rsdp->xsdt_addr);
        if (xsdt && memcmp(xsdt->signature, "XSDT", 4) == 0) {
            size_t n = (xsdt->length - sizeof(*xsdt)) / sizeof(uint64_t);
            const uint64_t *ents =
                (const uint64_t *)((const uint8_t *)xsdt + sizeof(*xsdt));
            for (size_t i = 0; i < n; i++) {
                const struct acpi_sdt_header *sdt = acpi_map_sdt(ents[i]);
                if (sdt && memcmp(sdt->signature, sig, 4) == 0)
                    return sdt;
            }
        }
    }

    if (rsdp->rsdt_addr) {
        const struct acpi_sdt_header *rsdt =
            acpi_map_sdt((uint64_t)rsdp->rsdt_addr);
        if (rsdt && memcmp(rsdt->signature, "RSDT", 4) == 0) {
            size_t n = (rsdt->length - sizeof(*rsdt)) / sizeof(uint32_t);
            const uint32_t *ents =
                (const uint32_t *)((const uint8_t *)rsdt + sizeof(*rsdt));
            for (size_t i = 0; i < n; i++) {
                const struct acpi_sdt_header *sdt = acpi_map_sdt(ents[i]);
                if (sdt && memcmp(sdt->signature, sig, 4) == 0)
                    return sdt;
            }
        }
    }

    return NULL;
}

int arch_pci_host_init(struct pci_host *host) {
    if (!host)
        return -EINVAL;

    const struct boot_info *bi = boot_info_get();
    if (!bi || !bi->rsdp)
        return -ENODEV;

    const struct acpi_rsdp *rsdp = (const struct acpi_rsdp *)bi->rsdp;
    if (memcmp(rsdp->signature, "RSD PTR ", 8) != 0)
        return -EINVAL;
    if (!acpi_checksum_ok(rsdp, 20))
        return -EINVAL;
    if (rsdp->revision >= 2) {
        if (rsdp->length < sizeof(*rsdp))
            return -EINVAL;
        if (!acpi_checksum_ok(rsdp, rsdp->length))
            return -EINVAL;
    }

    const struct acpi_mcfg *mcfg =
        (const struct acpi_mcfg *)acpi_find_sdt(rsdp, "MCFG");
    if (!mcfg) {
        pr_warn("pci: ACPI MCFG not found\n");
        return -ENODEV;
    }

    if (mcfg->hdr.length < sizeof(*mcfg))
        return -EINVAL;

    size_t entry_count = (mcfg->hdr.length - sizeof(*mcfg)) /
                         sizeof(struct acpi_mcfg_entry);
    const struct acpi_mcfg_entry *entries =
        (const struct acpi_mcfg_entry *)((const uint8_t *)mcfg +
                                         sizeof(*mcfg));

    const struct acpi_mcfg_entry *chosen = NULL;
    for (size_t i = 0; i < entry_count; i++) {
        if (entries[i].segment != 0)
            continue;
        if (entries[i].bus_start > entries[i].bus_end)
            continue;
        if (!entries[i].ecam_base)
            continue;
        if (entries[i].bus_start != 0) {
            pr_warn("pci: unsupported MCFG bus start %u\n",
                    entries[i].bus_start);
            continue;
        }
        chosen = &entries[i];
        break;
    }

    if (!chosen)
        return -ENODEV;

    uint64_t bus_count = (uint64_t)chosen->bus_end - chosen->bus_start + 1;
    uint64_t ecam_size = bus_count << 20;
    if (!ecam_size)
        return -EINVAL;

    host->ecam_base = ioremap((paddr_t)chosen->ecam_base, (size_t)ecam_size);
    if (!host->ecam_base) {
        pr_err("pci: failed to map ECAM @ %p (size 0x%lx)\n",
               (void *)(uintptr_t)chosen->ecam_base,
               (unsigned long)ecam_size);
        return -ENOMEM;
    }

    host->bus_start = chosen->bus_start;
    host->bus_end = chosen->bus_end;
    host->irq_base = 32;

    pr_info("pci: ACPI ECAM @ %p size 0x%lx bus %u-%u irq_base %u\n",
            (void *)(uintptr_t)chosen->ecam_base,
            (unsigned long)ecam_size,
            host->bus_start, host->bus_end, host->irq_base);

    return 0;
}
