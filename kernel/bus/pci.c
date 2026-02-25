/**
 * kernel/bus/pci.c - PCI bus with ECAM enumeration
 */

#include <kairos/pci.h>
#include <kairos/arch.h>
#include <kairos/io.h>
#include <kairos/mm.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/string.h>

static struct pci_host global_pci_host;
static bool global_pci_host_ready;

/* ------------------------------------------------------------------ */
/*  Weak arch hook — overridden by arch/riscv64/pci.c                 */
/* ------------------------------------------------------------------ */

__attribute__((weak)) int arch_pci_host_init(struct pci_host *host)
{
    (void)host;
    return -ENODEV;
}

__attribute__((weak)) int arch_pci_msi_setup(const struct pci_device *pdev,
                                             struct pci_msi_msg *msg)
{
    (void)pdev;
    (void)msg;
    return -EOPNOTSUPP;
}

__attribute__((weak)) int arch_pci_msi_affinity_msg(const struct pci_device *pdev,
                                                    uint8_t irq,
                                                    uint32_t cpu_mask,
                                                    struct pci_msi_msg *msg)
{
    (void)pdev;
    (void)irq;
    (void)cpu_mask;
    (void)msg;
    return -EOPNOTSUPP;
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

static int pci_read_cap_status_ptr(const struct pci_device *pdev, uint8_t *ptr)
{
    if (!pdev || !ptr)
        return -EINVAL;

    uint16_t status = 0;
    int ret = pci_dev_read_config_16(pdev, PCI_STATUS, &status);
    if (ret < 0)
        return ret;
    if (!(status & PCI_STATUS_CAP_LIST))
        return -ENOENT;

    ret = pci_dev_read_config_8(pdev, PCI_CAP_PTR, ptr);
    if (ret < 0)
        return ret;
    *ptr &= 0xfcU;
    return (*ptr >= 0x40) ? 0 : -ENOENT;
}

int pci_find_next_capability(const struct pci_device *pdev, uint8_t start_ptr,
                             uint8_t cap_id, uint8_t *cap_ptr)
{
    if (!pdev || !cap_ptr)
        return -EINVAL;

    uint8_t ptr = start_ptr;
    int guard = 0;
    if (ptr == 0) {
        int ret = pci_read_cap_status_ptr(pdev, &ptr);
        if (ret < 0)
            return ret;
    } else {
        ptr &= 0xfcU;
    }

    while (ptr >= 0x40 && guard++ < 64) {
        uint8_t id = 0;
        uint8_t next = 0;
        int ret = pci_dev_read_config_8(pdev, ptr, &id);
        if (ret < 0)
            return ret;
        ret = pci_dev_read_config_8(pdev, (uint16_t)(ptr + 1), &next);
        if (ret < 0)
            return ret;
        next &= 0xfcU;

        if (id == cap_id) {
            *cap_ptr = ptr;
            return 0;
        }
        if (!next || next == ptr)
            break;
        ptr = next;
    }
    return -ENOENT;
}

int pci_find_capability(const struct pci_device *pdev, uint8_t cap_id,
                        uint8_t *cap_ptr)
{
    return pci_find_next_capability(pdev, 0, cap_id, cap_ptr);
}

static int pci_msix_read_layout(const struct pci_device *pdev, uint8_t cap,
                                uint16_t *table_size, uint8_t *table_bir,
                                uint32_t *table_off, uint8_t *pba_bir,
                                uint32_t *pba_off)
{
    if (!pdev || !table_size || !table_bir || !table_off || !pba_bir || !pba_off)
        return -EINVAL;

    uint16_t ctrl = 0;
    int ret = pci_dev_read_config_16(pdev, (uint16_t)(cap + PCI_MSIX_FLAGS), &ctrl);
    if (ret < 0)
        return ret;

    uint16_t size = (uint16_t)((ctrl & PCI_MSIX_FLAGS_QSIZE) + 1U);
    if (!size)
        return -EINVAL;

    uint32_t table_info = 0;
    ret = pci_dev_read_config_32(pdev, (uint16_t)(cap + PCI_MSIX_TABLE), &table_info);
    if (ret < 0)
        return ret;
    uint8_t t_bir = (uint8_t)(table_info & 0x7U);
    uint32_t t_off = table_info & ~0x7U;

    uint32_t pba_info = 0;
    ret = pci_dev_read_config_32(pdev, (uint16_t)(cap + PCI_MSIX_PBA), &pba_info);
    if (ret < 0)
        return ret;
    uint8_t p_bir = (uint8_t)(pba_info & 0x7U);
    uint32_t p_off = pba_info & ~0x7U;

    if (t_bir >= PCI_MAX_BAR || p_bir >= PCI_MAX_BAR)
        return -EINVAL;
    if (!pdev->bar[t_bir] || !pdev->bar_size[t_bir])
        return -EINVAL;
    if (!pdev->bar[p_bir] || !pdev->bar_size[p_bir])
        return -EINVAL;

    uint64_t table_need = (uint64_t)t_off + ((uint64_t)size * PCI_MSIX_ENTRY_SIZE);
    if (table_need > pdev->bar_size[t_bir])
        return -EINVAL;

    uint64_t pba_bytes = (uint64_t)((size + 63U) / 64U) * 8U;
    if (((uint64_t)p_off + pba_bytes) > pdev->bar_size[p_bir])
        return -EINVAL;

    *table_size = size;
    *table_bir = t_bir;
    *table_off = t_off;
    *pba_bir = p_bir;
    *pba_off = p_off;
    return 0;
}

static void pci_toggle_intx(struct pci_device *pdev, bool disable)
{
    if (!pdev)
        return;
    uint16_t cmd = 0;
    if (pci_dev_read_config_16(pdev, PCI_COMMAND, &cmd) < 0)
        return;
    if (disable)
        cmd |= PCI_COMMAND_INTX_DISABLE;
    else
        cmd &= ~PCI_COMMAND_INTX_DISABLE;
    (void)pci_dev_write_config_16(pdev, PCI_COMMAND, cmd);
}

int pci_enable_msi(struct pci_device *pdev)
{
    if (!pdev)
        return -EINVAL;
    if (pdev->msix_enabled)
        return -EBUSY;
    if (pdev->msi_enabled)
        return 0;

    uint8_t cap = 0;
    int ret = pci_find_capability(pdev, PCI_CAP_ID_MSI, &cap);
    if (ret < 0)
        return ret;

    uint16_t ctrl = 0;
    ret = pci_dev_read_config_16(pdev, (uint16_t)(cap + PCI_MSI_FLAGS), &ctrl);
    if (ret < 0)
        return ret;

    struct pci_msi_msg msg = {0};
    ret = arch_pci_msi_setup(pdev, &msg);
    if (ret < 0)
        return ret;
    if (!msg.irq)
        return -EINVAL;

    ret = pci_dev_write_config_32(pdev, (uint16_t)(cap + 4), msg.address_lo);
    if (ret < 0)
        return ret;
    uint16_t data_off = (ctrl & PCI_MSI_FLAGS_64BIT) ? 12 : 8;
    if (ctrl & PCI_MSI_FLAGS_64BIT) {
        ret = pci_dev_write_config_32(pdev, (uint16_t)(cap + 8), msg.address_hi);
        if (ret < 0)
            return ret;
    }
    ret = pci_dev_write_config_16(pdev, (uint16_t)(cap + data_off), msg.data);
    if (ret < 0)
        return ret;

    ctrl &= ~PCI_MSI_FLAGS_QMASK;
    ctrl |= PCI_MSI_FLAGS_ENABLE;
    ret = pci_dev_write_config_16(pdev, (uint16_t)(cap + PCI_MSI_FLAGS), ctrl);
    if (ret < 0)
        return ret;

    arch_irq_set_type((int)msg.irq, IRQ_FLAG_TRIGGER_EDGE);
    pci_toggle_intx(pdev, true);

    pdev->msi_cap = cap;
    pdev->irq_line = msg.irq;
    pdev->msi_enabled = true;
    return 0;
}

int pci_disable_msi(struct pci_device *pdev)
{
    if (!pdev)
        return -EINVAL;
    if (!pdev->msi_enabled || pdev->msi_cap < 0x40)
        return 0;

    uint16_t ctrl = 0;
    int ret = pci_dev_read_config_16(
        pdev, (uint16_t)(pdev->msi_cap + PCI_MSI_FLAGS), &ctrl);
    if (ret < 0)
        return ret;
    ctrl &= ~PCI_MSI_FLAGS_ENABLE;
    ret = pci_dev_write_config_16(pdev,
                                  (uint16_t)(pdev->msi_cap + PCI_MSI_FLAGS),
                                  ctrl);
    if (ret < 0)
        return ret;

    if (!pdev->msix_enabled)
        pci_toggle_intx(pdev, false);

    pdev->irq_line = pdev->intx_irq_line;
    pdev->msi_enabled = false;
    return 0;
}

int pci_enable_msix_nvec(struct pci_device *pdev, uint16_t nvec)
{
    if (!pdev)
        return -EINVAL;
    if (pdev->msi_enabled)
        return -EBUSY;
    if (!nvec)
        return -EINVAL;
    if (pdev->msix_enabled) {
        if (pdev->msix_nvec >= nvec)
            return 0;
        return -EBUSY;
    }

    uint8_t cap = 0;
    int ret = pci_find_capability(pdev, PCI_CAP_ID_MSIX, &cap);
    if (ret < 0)
        return ret;

    uint16_t table_size = 0;
    uint8_t table_bir = 0;
    uint32_t table_off = 0;
    uint8_t pba_bir = 0;
    uint32_t pba_off = 0;
    ret = pci_msix_read_layout(pdev, cap, &table_size, &table_bir, &table_off,
                               &pba_bir, &pba_off);
    if (ret < 0)
        return ret;
    if (nvec > table_size)
        return -ENOSPC;

    uint8_t *irqs = kzalloc(nvec);
    if (!irqs)
        return -ENOMEM;

    size_t map_len = (size_t)nvec * PCI_MSIX_ENTRY_SIZE;
    volatile uint8_t *table = (volatile uint8_t *)ioremap(
        (paddr_t)(pdev->bar[table_bir] + table_off), map_len);
    if (!table) {
        kfree(irqs);
        return -ENOMEM;
    }

    uint16_t ctrl = 0;
    ret = pci_dev_read_config_16(pdev, (uint16_t)(cap + PCI_MSIX_FLAGS), &ctrl);
    if (ret < 0) {
        iounmap((void *)table);
        kfree(irqs);
        return ret;
    }

    uint16_t masked_ctrl = (uint16_t)(ctrl | PCI_MSIX_FLAGS_MASKALL);
    ret = pci_dev_write_config_16(pdev, (uint16_t)(cap + PCI_MSIX_FLAGS),
                                  masked_ctrl);
    if (ret < 0) {
        iounmap((void *)table);
        kfree(irqs);
        return ret;
    }

    for (uint16_t i = 0; i < nvec; i++) {
        struct pci_msi_msg msg = {0};
        ret = arch_pci_msi_setup(pdev, &msg);
        if (ret < 0 || !msg.irq) {
            ret = (ret < 0) ? ret : -EINVAL;
            goto msix_fail;
        }
        irqs[i] = msg.irq;
        arch_irq_set_type((int)msg.irq, IRQ_FLAG_TRIGGER_EDGE);

        volatile uint8_t *entry = table + ((size_t)i * PCI_MSIX_ENTRY_SIZE);
        uint64_t addr = ((uint64_t)msg.address_hi << 32) | msg.address_lo;

        writel(PCI_MSIX_CTRL_MASKBIT, (void *)(entry + 12));
        writeq(addr, (void *)(entry + 0));
        writel((uint32_t)msg.data, (void *)(entry + 8));
        writel(0, (void *)(entry + 12));
    }

    {
        uint16_t enable_ctrl =
            (uint16_t)((ctrl | PCI_MSIX_FLAGS_ENABLE) & ~PCI_MSIX_FLAGS_MASKALL);
        ret = pci_dev_write_config_16(pdev, (uint16_t)(cap + PCI_MSIX_FLAGS),
                                      enable_ctrl);
    }
    iounmap((void *)table);
    if (ret < 0) {
        kfree(irqs);
        return ret;
    }

    pci_toggle_intx(pdev, true);
    pdev->irq_line = irqs[0];
    pdev->msix_cap = cap;
    pdev->msix_enabled = true;
    pdev->msix_table_size = table_size;
    pdev->msix_nvec = nvec;
    pdev->msix_table_bir = table_bir;
    pdev->msix_table_off = table_off;
    pdev->msix_pba_bir = pba_bir;
    pdev->msix_pba_off = pba_off;
    pdev->msix_irq = irqs;
    return 0;

msix_fail:
    (void)pci_dev_write_config_16(pdev, (uint16_t)(cap + PCI_MSIX_FLAGS),
                                  (uint16_t)((ctrl & ~PCI_MSIX_FLAGS_ENABLE) |
                                             PCI_MSIX_FLAGS_MASKALL));
    iounmap((void *)table);
    kfree(irqs);
    return ret;
}

int pci_enable_msix(struct pci_device *pdev)
{
    return pci_enable_msix_nvec(pdev, 1);
}

int pci_enable_msix_range(struct pci_device *pdev, uint16_t min_vec,
                          uint16_t max_vec, uint16_t *granted_vec)
{
    if (!pdev || !min_vec || !max_vec || min_vec > max_vec)
        return -EINVAL;

    if (pdev->msix_enabled) {
        if (pdev->msix_nvec < min_vec)
            return -EBUSY;
        if (granted_vec)
            *granted_vec = pdev->msix_nvec;
        return 0;
    }

    for (uint16_t req = max_vec;; req--) {
        int ret = pci_enable_msix_nvec(pdev, req);
        if (ret == 0) {
            if (granted_vec)
                *granted_vec = pdev->msix_nvec;
            return 0;
        }
        if (ret != -ENOSPC)
            return ret;
        if (req == min_vec)
            break;
    }

    return -ENOSPC;
}

int pci_msix_vector_irq(const struct pci_device *pdev, uint16_t index,
                        uint8_t *irq)
{
    if (!pdev || !irq)
        return -EINVAL;
    if (!pdev->msix_enabled || !pdev->msix_irq)
        return -EINVAL;
    if (index >= pdev->msix_nvec)
        return -EINVAL;

    *irq = pdev->msix_irq[index];
    return 0;
}

int pci_msix_set_vector_mask(struct pci_device *pdev, uint16_t index,
                             bool masked)
{
    if (!pdev || !pdev->msix_enabled || !pdev->msix_irq)
        return -EINVAL;
    if (index >= pdev->msix_nvec)
        return -EINVAL;
    if (pdev->msix_table_bir >= PCI_MAX_BAR)
        return -EINVAL;

    uint64_t bar_base = pdev->bar[pdev->msix_table_bir];
    uint64_t bar_size = pdev->bar_size[pdev->msix_table_bir];
    uint64_t ctrl_off = (uint64_t)pdev->msix_table_off +
                        ((uint64_t)index * PCI_MSIX_ENTRY_SIZE) + 12U;
    if (!bar_base || !bar_size || (ctrl_off + 4U) > bar_size)
        return -EINVAL;

    volatile uint32_t *ctrl_reg = (volatile uint32_t *)ioremap(
        (paddr_t)(bar_base + ctrl_off), sizeof(uint32_t));
    if (!ctrl_reg)
        return -ENOMEM;
    uint32_t ctrl = readl((void *)ctrl_reg);
    if (masked)
        ctrl |= PCI_MSIX_CTRL_MASKBIT;
    else
        ctrl &= ~PCI_MSIX_CTRL_MASKBIT;
    writel(ctrl, (void *)ctrl_reg);
    iounmap((void *)ctrl_reg);
    return 0;
}

int pci_msix_vector_pending(const struct pci_device *pdev, uint16_t index,
                            bool *pending)
{
    if (!pdev || !pending)
        return -EINVAL;
    if (!pdev->msix_enabled)
        return -EINVAL;
    if (index >= pdev->msix_table_size || pdev->msix_pba_bir >= PCI_MAX_BAR)
        return -EINVAL;

    uint64_t bar_base = pdev->bar[pdev->msix_pba_bir];
    uint64_t bar_size = pdev->bar_size[pdev->msix_pba_bir];
    uint64_t word_off = (uint64_t)pdev->msix_pba_off + (((uint64_t)index / 64U) * 8U);
    if (!bar_base || !bar_size || (word_off + 8U) > bar_size)
        return -EINVAL;

    volatile uint64_t *pba_word = (volatile uint64_t *)ioremap(
        (paddr_t)(bar_base + word_off), sizeof(uint64_t));
    if (!pba_word)
        return -ENOMEM;
    uint64_t bits = readq((void *)pba_word);
    iounmap((void *)pba_word);

    *pending = (bits & (1ULL << (index % 64U))) != 0;
    return 0;
}

int pci_msix_pending_bitmap(const struct pci_device *pdev, uint64_t *bitmap_words,
                            size_t word_count)
{
    if (!pdev || !bitmap_words)
        return -EINVAL;
    if (!pdev->msix_enabled)
        return -EINVAL;
    if (pdev->msix_pba_bir >= PCI_MAX_BAR)
        return -EINVAL;

    size_t need_words = (size_t)((pdev->msix_table_size + 63U) / 64U);
    if (word_count < need_words)
        return -ENOSPC;
    if (need_words == 0)
        return 0;

    uint64_t bar_base = pdev->bar[pdev->msix_pba_bir];
    uint64_t bar_size = pdev->bar_size[pdev->msix_pba_bir];
    uint64_t pba_bytes = (uint64_t)need_words * sizeof(uint64_t);
    if (!bar_base || !bar_size || ((uint64_t)pdev->msix_pba_off + pba_bytes) > bar_size)
        return -EINVAL;

    volatile uint64_t *pba = (volatile uint64_t *)ioremap(
        (paddr_t)(bar_base + pdev->msix_pba_off), (size_t)pba_bytes);
    if (!pba)
        return -ENOMEM;

    for (size_t i = 0; i < need_words; i++)
        bitmap_words[i] = readq((void *)&pba[i]);
    iounmap((void *)pba);

    uint32_t tail = pdev->msix_table_size % 64U;
    if (tail != 0) {
        uint64_t mask = (1ULL << tail) - 1ULL;
        bitmap_words[need_words - 1] &= mask;
    }
    return 0;
}

int pci_msix_set_affinity(struct pci_device *pdev, uint16_t index,
                          uint32_t cpu_mask)
{
    uint8_t irq = 0;
    int ret = pci_msix_vector_irq(pdev, index, &irq);
    if (ret < 0)
        return ret;
    if (!cpu_mask)
        return -EINVAL;

    struct pci_msi_msg msg = {0};
    ret = arch_pci_msi_affinity_msg(pdev, irq, cpu_mask, &msg);
    if (ret == -EOPNOTSUPP || ret == -ENOENT) {
        arch_irq_set_affinity((int)irq, cpu_mask);
        return 0;
    }
    if (ret < 0)
        return ret;
    if (msg.irq != irq)
        return -EOPNOTSUPP;
    if (pdev->msix_table_bir >= PCI_MAX_BAR)
        return -EINVAL;

    uint64_t bar_base = pdev->bar[pdev->msix_table_bir];
    uint64_t bar_size = pdev->bar_size[pdev->msix_table_bir];
    uint64_t entry_off =
        (uint64_t)pdev->msix_table_off + ((uint64_t)index * PCI_MSIX_ENTRY_SIZE);
    if (!bar_base || !bar_size || (entry_off + PCI_MSIX_ENTRY_SIZE) > bar_size)
        return -EINVAL;

    volatile uint8_t *entry = (volatile uint8_t *)ioremap(
        (paddr_t)(bar_base + entry_off), PCI_MSIX_ENTRY_SIZE);
    if (!entry)
        return -ENOMEM;

    uint32_t ctrl = readl((void *)(entry + 12));
    writel(ctrl | PCI_MSIX_CTRL_MASKBIT, (void *)(entry + 12));
    uint64_t addr = ((uint64_t)msg.address_hi << 32) | msg.address_lo;
    writeq(addr, (void *)(entry + 0));
    writel((uint32_t)msg.data, (void *)(entry + 8));
    writel(ctrl, (void *)(entry + 12));
    iounmap((void *)entry);

    arch_irq_set_affinity((int)irq, cpu_mask);
    return 0;
}

int pci_msix_set_affinity_spread(struct pci_device *pdev, uint32_t cpu_mask)
{
    if (!pdev || !pdev->msix_enabled || !pdev->msix_irq)
        return -EINVAL;
    if (!cpu_mask)
        return -EINVAL;

    uint32_t cpus[32];
    uint32_t cpu_count = 0;
    for (uint32_t cpu = 0; cpu < 32U; cpu++) {
        if ((cpu_mask & (1U << cpu)) != 0)
            cpus[cpu_count++] = cpu;
    }
    if (!cpu_count)
        return -EINVAL;

    int first_err = 0;
    for (uint16_t i = 0; i < pdev->msix_nvec; i++) {
        uint32_t cpu = cpus[i % cpu_count];
        int ret = pci_msix_set_affinity(pdev, i, 1U << cpu);
        if (ret < 0 && first_err == 0)
            first_err = ret;
    }
    return first_err;
}

int pci_disable_msix(struct pci_device *pdev)
{
    if (!pdev)
        return -EINVAL;
    if (!pdev->msix_enabled || pdev->msix_cap < 0x40)
        return 0;

    uint16_t ctrl = 0;
    int ret = pci_dev_read_config_16(
        pdev, (uint16_t)(pdev->msix_cap + PCI_MSIX_FLAGS), &ctrl);
    if (ret < 0)
        return ret;

    ctrl &= ~PCI_MSIX_FLAGS_ENABLE;
    ctrl |= PCI_MSIX_FLAGS_MASKALL;
    ret = pci_dev_write_config_16(pdev,
                                  (uint16_t)(pdev->msix_cap + PCI_MSIX_FLAGS),
                                  ctrl);
    if (ret < 0)
        return ret;

    if (!pdev->msi_enabled)
        pci_toggle_intx(pdev, false);

    kfree(pdev->msix_irq);
    pdev->msix_irq = NULL;
    pdev->msix_nvec = 0;
    pdev->irq_line = pdev->intx_irq_line;
    pdev->msix_enabled = false;
    return 0;
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
                pdev->intx_irq_line = pdev->irq_line;
                pdev->msi_cap = 0;
                pdev->msix_cap = 0;
                pdev->msi_enabled = false;
                pdev->msix_enabled = false;
                pdev->msix_table_size = 0;
                pdev->msix_nvec = 0;
                pdev->msix_table_bir = 0;
                pdev->msix_pba_bir = 0;
                pdev->msix_table_off = 0;
                pdev->msix_pba_off = 0;
                pdev->msix_irq = NULL;

                /* Decode BARs (type 0 header only) */
                if ((hdr_type & PCI_HEADER_TYPE_MASK) == 0x00)
                    pci_decode_bars(host, pdev, PCI_MAX_BAR);

                uint8_t msi_cap = 0;
                if (pci_find_capability(pdev, PCI_CAP_ID_MSI, &msi_cap) == 0)
                    pdev->msi_cap = msi_cap;
                uint8_t msix_cap = 0;
                if (pci_find_capability(pdev, PCI_CAP_ID_MSIX, &msix_cap) == 0) {
                    uint16_t table_size = 0;
                    uint8_t table_bir = 0;
                    uint32_t table_off = 0;
                    uint8_t pba_bir = 0;
                    uint32_t pba_off = 0;
                    if (pci_msix_read_layout(pdev, msix_cap, &table_size, &table_bir,
                                             &table_off, &pba_bir, &pba_off) == 0) {
                        pdev->msix_cap = msix_cap;
                        pdev->msix_table_size = table_size;
                        pdev->msix_table_bir = table_bir;
                        pdev->msix_table_off = table_off;
                        pdev->msix_pba_bir = pba_bir;
                        pdev->msix_pba_off = pba_off;
                    }
                }

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

int pci_dev_read_config_8(const struct pci_device *pdev, uint16_t off,
                          uint8_t *val) {
    if (!pdev || !val || !global_pci_host_ready)
        return -EINVAL;
    *val = pci_read_config_8(&global_pci_host, pdev->bus, pdev->slot,
                             pdev->func, off);
    return 0;
}

int pci_dev_read_config_16(const struct pci_device *pdev, uint16_t off,
                           uint16_t *val) {
    if (!pdev || !val || !global_pci_host_ready)
        return -EINVAL;
    *val = pci_read_config_16(&global_pci_host, pdev->bus, pdev->slot,
                              pdev->func, off);
    return 0;
}

int pci_dev_read_config_32(const struct pci_device *pdev, uint16_t off,
                           uint32_t *val) {
    if (!pdev || !val || !global_pci_host_ready)
        return -EINVAL;
    *val = pci_read_config_32(&global_pci_host, pdev->bus, pdev->slot,
                              pdev->func, off);
    return 0;
}

int pci_dev_write_config_8(const struct pci_device *pdev, uint16_t off,
                           uint8_t val) {
    if (!pdev || !global_pci_host_ready)
        return -EINVAL;
    pci_write_config_8(&global_pci_host, pdev->bus, pdev->slot,
                       pdev->func, off, val);
    return 0;
}

int pci_dev_write_config_16(const struct pci_device *pdev, uint16_t off,
                            uint16_t val) {
    if (!pdev || !global_pci_host_ready)
        return -EINVAL;
    pci_write_config_16(&global_pci_host, pdev->bus, pdev->slot,
                        pdev->func, off, val);
    return 0;
}

int pci_dev_write_config_32(const struct pci_device *pdev, uint16_t off,
                            uint32_t val) {
    if (!pdev || !global_pci_host_ready)
        return -EINVAL;
    pci_write_config_32(&global_pci_host, pdev->bus, pdev->slot,
                        pdev->func, off, val);
    return 0;
}

int pci_dev_enable_bus_master(struct pci_device *pdev) {
    if (!pdev)
        return -EINVAL;
    uint16_t cmd = 0;
    int ret = pci_dev_read_config_16(pdev, PCI_COMMAND, &cmd);
    if (ret < 0)
        return ret;
    cmd |= PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER;
    return pci_dev_write_config_16(pdev, PCI_COMMAND, cmd);
}

int pci_enumerate(void)
{
    struct pci_host host = {0};
    int ret = arch_pci_host_init(&host);
    if (ret < 0)
        return ret;
    global_pci_host = host;
    global_pci_host_ready = true;
    return pci_scan_bus(&global_pci_host);
}
