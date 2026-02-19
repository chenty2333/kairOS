/**
 * kernel/bus/pci.c - PCI bus with ECAM enumeration
 */

#include <kairos/pci.h>
#include <kairos/io.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>

/* ------------------------------------------------------------------ */
/*  Weak arch hook — overridden by arch/riscv64/pci.c                 */
/* ------------------------------------------------------------------ */

__attribute__((weak)) int arch_pci_host_init(struct pci_host *host)
{
    (void)host;
    return -ENODEV;
}

/* ------------------------------------------------------------------ */
/*  ECAM config-space accessors                                       */
/* ------------------------------------------------------------------ */

uint8_t pci_read_config_8(struct pci_host *host, uint8_t bus,
                           uint8_t slot, uint8_t func, uint16_t off)
{
    return readb(pci_ecam_addr(host->ecam_base, bus, slot, func, off));
}

uint16_t pci_read_config_16(struct pci_host *host, uint8_t bus,
                              uint8_t slot, uint8_t func, uint16_t off)
{
    return readw(pci_ecam_addr(host->ecam_base, bus, slot, func, off));
}

uint32_t pci_read_config_32(struct pci_host *host, uint8_t bus,
                              uint8_t slot, uint8_t func, uint16_t off)
{
    return readl(pci_ecam_addr(host->ecam_base, bus, slot, func, off));
}

void pci_write_config_8(struct pci_host *host, uint8_t bus,
                         uint8_t slot, uint8_t func, uint16_t off, uint8_t val)
{
    writeb(val, pci_ecam_addr(host->ecam_base, bus, slot, func, off));
}

void pci_write_config_16(struct pci_host *host, uint8_t bus,
                          uint8_t slot, uint8_t func, uint16_t off, uint16_t val)
{
    writew(val, pci_ecam_addr(host->ecam_base, bus, slot, func, off));
}

void pci_write_config_32(struct pci_host *host, uint8_t bus,
                          uint8_t slot, uint8_t func, uint16_t off, uint32_t val)
{
    writel(val, pci_ecam_addr(host->ecam_base, bus, slot, func, off));
}

/* ------------------------------------------------------------------ */
/*  pci_set_master — enable bus-master + memory-space in COMMAND reg   */
/* ------------------------------------------------------------------ */

void pci_set_master(struct pci_host *host, struct pci_device *pdev)
{
    uint16_t cmd = pci_read_config_16(host, pdev->bus, pdev->slot,
                                       pdev->func, PCI_COMMAND);
    cmd |= PCI_COMMAND_MASTER | PCI_COMMAND_MEMORY;
    pci_write_config_16(host, pdev->bus, pdev->slot, pdev->func,
                         PCI_COMMAND, cmd);
}

/* ------------------------------------------------------------------ */
/*  BAR decoding                                                       */
/* ------------------------------------------------------------------ */

static void pci_decode_bars(struct pci_host *host, struct pci_device *pdev,
                             int num_bars)
{
    for (int i = 0; i < num_bars; i++) {
        uint16_t bar_off = PCI_BAR0 + (uint16_t)(i * 4);
        uint32_t orig = pci_read_config_32(host, pdev->bus, pdev->slot,
                                            pdev->func, bar_off);

        /* Write all-ones to determine size */
        pci_write_config_32(host, pdev->bus, pdev->slot, pdev->func,
                             bar_off, 0xffffffff);
        uint32_t mask = pci_read_config_32(host, pdev->bus, pdev->slot,
                                            pdev->func, bar_off);
        /* Restore original value */
        pci_write_config_32(host, pdev->bus, pdev->slot, pdev->func,
                             bar_off, orig);

        if (mask == 0) {
            pdev->bar[i] = 0;
            pdev->bar_size[i] = 0;
            continue;
        }

        if (orig & PCI_BAR_IO) {
            /* I/O BAR */
            uint32_t size = ~(mask & ~0x3u) + 1;
            pdev->bar[i] = orig & ~0x3u;
            pdev->bar_size[i] = size;
        } else {
            /* Memory BAR */
            uint32_t mem_type = orig & PCI_BAR_MEM_TYPE_MASK;
            if (mem_type == PCI_BAR_MEM_TYPE_64 && i + 1 < num_bars) {
                /* 64-bit BAR: read upper 32 bits from next BAR */
                uint16_t bar_hi = PCI_BAR0 + (uint16_t)((i + 1) * 4);
                uint32_t orig_hi = pci_read_config_32(host, pdev->bus,
                    pdev->slot, pdev->func, bar_hi);
                pci_write_config_32(host, pdev->bus, pdev->slot,
                    pdev->func, bar_hi, 0xffffffff);
                uint32_t mask_hi = pci_read_config_32(host, pdev->bus,
                    pdev->slot, pdev->func, bar_hi);
                pci_write_config_32(host, pdev->bus, pdev->slot,
                    pdev->func, bar_hi, orig_hi);

                uint64_t full_mask = ((uint64_t)mask_hi << 32) |
                                     (mask & ~0xfu);
                uint64_t size64 = ~full_mask + 1;
                pdev->bar[i] = ((uint64_t)orig_hi << 32) | (orig & ~0xfu);
                pdev->bar_size[i] = size64;
                /* Skip the upper-half BAR slot */
                i++;
                pdev->bar[i] = 0;
                pdev->bar_size[i] = 0;
            } else {
                /* 32-bit BAR */
                uint32_t size = ~(mask & ~0xfu) + 1;
                pdev->bar[i] = orig & ~0xfu;
                pdev->bar_size[i] = size;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  PCI class name helper                                              */
/* ------------------------------------------------------------------ */

static const char *pci_class_name(uint8_t base_class, uint8_t sub_class)
{
    if (base_class == 0x06 && sub_class == 0x00)
        return "host-bridge";
    if (base_class == 0x06)
        return "bridge";
    if (base_class == 0x02)
        return "network";
    if (base_class == 0x01)
        return "storage";
    if (base_class == 0x03)
        return "display";
    if (base_class == 0x04)
        return "multimedia";
    if (base_class == 0x0c)
        return "serial-bus";
    return "device";
}

/* ------------------------------------------------------------------ */
/*  pci_scan_bus — enumerate all devices on the PCI bus                */
/* ------------------------------------------------------------------ */

int pci_scan_bus(struct pci_host *host)
{
    int count = 0;

    pr_info("pci: scanning bus %d-%d\n", host->bus_start, host->bus_end);

    for (int b = host->bus_start; b <= host->bus_end; b++) {
        for (int s = 0; s < 32; s++) {
            int max_func = 1;
            for (int f = 0; f < max_func; f++) {
                uint16_t vendor = pci_read_config_16(
                    host, (uint8_t)b, (uint8_t)s, (uint8_t)f, PCI_VENDOR_ID);
                if (vendor == 0xffff)
                    continue;

                uint16_t device = pci_read_config_16(
                    host, (uint8_t)b, (uint8_t)s, (uint8_t)f, PCI_DEVICE_ID);
                uint32_t class_rev = pci_read_config_32(
                    host, (uint8_t)b, (uint8_t)s, (uint8_t)f,
                    PCI_CLASS_REVISION);
                uint8_t hdr_type = pci_read_config_8(
                    host, (uint8_t)b, (uint8_t)s, (uint8_t)f,
                    PCI_HEADER_TYPE);

                /* Check multi-function on func 0 */
                if (f == 0 && (hdr_type & PCI_HEADER_MULTI_FUNC))
                    max_func = 8;

                uint8_t base_class = (uint8_t)(class_rev >> 24);
                uint8_t sub_class = (uint8_t)(class_rev >> 16);
                uint8_t irq_pin = pci_read_config_8(
                    host, (uint8_t)b, (uint8_t)s, (uint8_t)f, PCI_IRQ_PIN);

                struct pci_device *pdev = kzalloc(sizeof(*pdev));
                if (!pdev)
                    return -ENOMEM;

                pdev->vendor_id = vendor;
                pdev->device_id = device;
                pdev->bus = (uint8_t)b;
                pdev->slot = (uint8_t)s;
                pdev->func = (uint8_t)f;
                pdev->class_code = class_rev >> 8;
                pdev->irq_pin = irq_pin;

                /* INTx IRQ: swizzle based on slot + pin */
                if (irq_pin > 0)
                    pdev->irq_line = (uint8_t)(host->irq_base +
                                     ((s + irq_pin - 1) % 4));

                /* Decode BARs (type 0 header only) */
                if ((hdr_type & PCI_HEADER_TYPE_MASK) == 0x00)
                    pci_decode_bars(host, pdev, PCI_MAX_BAR);

                /* Register with device model */
                snprintf(pdev->dev.name, sizeof(pdev->dev.name),
                         "pci-%02x:%02x.%x", b, s, f);
                pdev->dev.bus = &pci_bus_type;

                pr_info("pci: %02x:%02x.%x %04x:%04x class %06x (%s)\n",
                        b, s, f, vendor, device,
                        pdev->class_code, pci_class_name(base_class, sub_class));

                device_register(&pdev->dev);
                count++;
            }
        }
    }

    pr_info("pci: %d device(s) found\n", count);
    return count;
}

/* ------------------------------------------------------------------ */
/*  Bus type, match, probe, init, register, enumerate                  */
/* ------------------------------------------------------------------ */

static int pci_bus_match(struct device *dev, struct driver *drv)
{
    struct pci_device *pdev = to_pci_device(dev);
    struct pci_driver *pdrv = to_pci_driver(drv);

    bool vendor_ok =
        (pdrv->vendor_id == PCI_ANY_ID || pdrv->vendor_id == pdev->vendor_id);
    bool device_ok =
        (pdrv->device_id == PCI_ANY_ID || pdrv->device_id == pdev->device_id);
    return vendor_ok && device_ok;
}

static int pci_drv_probe(struct device *dev)
{
    struct pci_device *pdev = to_pci_device(dev);
    struct pci_driver *pdrv = to_pci_driver(dev->driver);
    if (!pdrv->probe)
        return -EINVAL;
    return pdrv->probe(pdev);
}

struct bus_type pci_bus_type = {
    .name = "pci",
    .match = pci_bus_match,
};

int pci_bus_init(void)
{
    int ret = bus_register(&pci_bus_type);
    if (ret == 0)
        pr_info("pci: core initialized\n");
    return ret;
}

int pci_register_driver(struct pci_driver *pdrv)
{
    if (!pdrv)
        return -EINVAL;
    pdrv->drv.bus = &pci_bus_type;
    pdrv->drv.probe = pci_drv_probe;
    return driver_register(&pdrv->drv);
}

int pci_enumerate(void)
{
    struct pci_host host = {0};
    int ret = arch_pci_host_init(&host);
    if (ret < 0)
        return ret;
    return pci_scan_bus(&host);
}
