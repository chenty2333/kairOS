/**
 * kernel/firmware/fdt.c - Flattened Device Tree (FDT) parser
 */

#include <kairos/types.h>
#include <kairos/string.h>
#include <kairos/fdt.h>
#include <kairos/device.h>
#include <kairos/firmware.h>
#include <kairos/platform.h>
#include <kairos/mm.h>
#include <kairos/printk.h>

/* FDT header structure */
struct fdt_header {
    uint32_t magic;             /* 0xd00dfeed (big-endian) */
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};

#define FDT_BEGIN_NODE  0x00000001
#define FDT_END_NODE    0x00000002
#define FDT_PROP        0x00000003
#define FDT_NOP         0x00000004
#define FDT_END         0x00000009
#define FDT_MAGIC       0xd00dfeed

#define MAX_MEM_REGIONS 64
#define MAX_RESERVED_REGIONS 64
#define MAX_FDT_DEPTH 16

struct mem_region {
    paddr_t base;
    size_t size;
};

struct fdt_view {
    const void *base;
    const struct fdt_header *hdr;
    const char *strings;
    const char *end;
    const uint32_t *struct_blk;
    const char *struct_end;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};

struct fdt_iter {
    const uint32_t *p;
    int depth;
};

static struct mem_region mem_regions[MAX_MEM_REGIONS];
static struct mem_region reserved_regions[MAX_RESERVED_REGIONS];
static int num_mem_regions;
static int num_reserved_regions;

static inline uint32_t fdt_be32(uint32_t val) {
    return ((val & 0xff000000) >> 24) | ((val & 0x00ff0000) >> 8) |
           ((val & 0x0000ff00) << 8) | ((val & 0x000000ff) << 24);
}

static inline uint64_t fdt_be64(uint64_t val) {
    return ((uint64_t)fdt_be32((uint32_t)(val >> 32)) & 0xffffffffULL) |
           ((uint64_t)fdt_be32((uint32_t)val) << 32);
}

static inline uintptr_t fdt_align(uintptr_t val) {
    return (val + 3) & ~3;
}

static int fdt_init_view(const void *fdt, struct fdt_view *view) {
    if (!fdt || !view)
        return -EINVAL;

    const struct fdt_header *hdr = fdt;
    if (fdt_be32(hdr->magic) != FDT_MAGIC)
        return -EINVAL;

    uint32_t totalsize = fdt_be32(hdr->totalsize);
    uint32_t off_dt_struct = fdt_be32(hdr->off_dt_struct);
    uint32_t off_dt_strings = fdt_be32(hdr->off_dt_strings);
    uint32_t off_mem_rsvmap = fdt_be32(hdr->off_mem_rsvmap);
    uint32_t size_dt_strings = fdt_be32(hdr->size_dt_strings);
    uint32_t size_dt_struct = fdt_be32(hdr->size_dt_struct);

    if (totalsize < sizeof(*hdr))
        return -EINVAL;
    if (off_dt_struct >= totalsize || off_dt_strings >= totalsize ||
        off_mem_rsvmap >= totalsize)
        return -EINVAL;
    if (off_dt_struct + size_dt_struct > totalsize ||
        off_dt_strings + size_dt_strings > totalsize)
        return -EINVAL;

    view->base = fdt;
    view->hdr = hdr;
    view->end = (const char *)fdt + totalsize;
    view->strings = (const char *)fdt + off_dt_strings;
    view->struct_blk = (const uint32_t *)((const char *)fdt + off_dt_struct);
    view->struct_end = (const char *)view->struct_blk + size_dt_struct;
    view->size_dt_strings = size_dt_strings;
    view->size_dt_struct = size_dt_struct;
    return 0;
}

static int fdt_next_token(struct fdt_view *view, struct fdt_iter *it,
                          uint32_t *token, const char **node_name,
                          const char **prop_name, const void **prop_data,
                          uint32_t *prop_len) {
    if (!view || !it || !token || it->p == NULL)
        return -EINVAL;
    if ((const char *)it->p >= view->struct_end)
        return -EINVAL;

    uint32_t raw = *it->p++;
    uint32_t tok = fdt_be32(raw);
    *token = tok;

    if (node_name)
        *node_name = NULL;
    if (prop_name)
        *prop_name = NULL;
    if (prop_data)
        *prop_data = NULL;
    if (prop_len)
        *prop_len = 0;

    switch (tok) {
    case FDT_BEGIN_NODE: {
        const char *name = (const char *)it->p;
        const char *limit = view->struct_end;
        const char *nul = memchr(name, '\0', (size_t)(limit - name));
        if (!nul)
            return -EINVAL;
        if (node_name)
            *node_name = name;
        it->p = (const uint32_t *)((const char *)name + fdt_align((uintptr_t)(nul - name + 1)));
        if (it->depth >= MAX_FDT_DEPTH - 1)
            return -EINVAL;
        it->depth++;
        break;
    }
    case FDT_END_NODE:
        if (it->depth <= 0)
            return -EINVAL;
        it->depth--;
        break;
    case FDT_PROP: {
        if ((const char *)it->p + 8 > view->struct_end)
            return -EINVAL;
        uint32_t len = fdt_be32(*it->p++);
        uint32_t nameoff = fdt_be32(*it->p++);
        if (nameoff >= view->size_dt_strings)
            return -EINVAL;
        const char *pname = view->strings + nameoff;
        size_t maxlen = view->size_dt_strings - nameoff;
        if (!memchr(pname, '\0', maxlen))
            return -EINVAL;
        const void *pdata = it->p;
        const char *next = (const char *)pdata + fdt_align(len);
        if (next > view->struct_end)
            return -EINVAL;
        it->p = (const uint32_t *)next;
        if (prop_name)
            *prop_name = pname;
        if (prop_data)
            *prop_data = pdata;
        if (prop_len)
            *prop_len = len;
        break;
    }
    case FDT_END:
    case FDT_NOP:
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static int fdt_read_reg(const uint32_t *reg, uint32_t reg_len,
                        uint32_t address_cells, uint32_t size_cells,
                        paddr_t *base, size_t *size) {
    if (!reg || !base || !size)
        return -EINVAL;
    if (address_cells == 0 || size_cells == 0)
        return -EINVAL;
    uint32_t entry_size = (address_cells + size_cells) * 4;
    if (reg_len < entry_size)
        return -EINVAL;

    uint64_t base64 = 0;
    uint64_t size64 = 0;
    for (uint32_t i = 0; i < address_cells; i++)
        base64 = (base64 << 32) | fdt_be32(*reg++);
    for (uint32_t i = 0; i < size_cells; i++)
        size64 = (size64 << 32) | fdt_be32(*reg++);
    if (size64 > (uint64_t)((size_t)-1))
        return -EINVAL;

    *base = (paddr_t)base64;
    *size = (size_t)size64;
    return 0;
}

static bool fdt_is_memory_node(const char *name) {
    if (!name)
        return false;
    if (strcmp(name, "memory") == 0)
        return true;
    return strncmp(name, "memory@", 7) == 0;
}

static int fdt_parse_reserved(const struct fdt_view *view) {
    const char *base = (const char *)view->base;
    uint32_t off_mem_rsvmap = fdt_be32(view->hdr->off_mem_rsvmap);
    const char *p = base + off_mem_rsvmap;
    num_reserved_regions = 0;

    while (p + sizeof(uint64_t) * 2 <= view->end) {
        uint64_t addr_be = *(const uint64_t *)p;
        uint64_t size_be = *(const uint64_t *)(p + sizeof(uint64_t));
        uint64_t addr = fdt_be64(addr_be);
        uint64_t size = fdt_be64(size_be);
        p += sizeof(uint64_t) * 2;
        if (addr == 0 && size == 0)
            return 0;
        if (size > (uint64_t)((size_t)-1))
            return -EINVAL;
        if (num_reserved_regions < MAX_RESERVED_REGIONS) {
            reserved_regions[num_reserved_regions].base = (paddr_t)addr;
            reserved_regions[num_reserved_regions].size = (size_t)size;
            num_reserved_regions++;
        }
    }
    return -EINVAL;
}

int fdt_parse(const void *fdt) {
    struct fdt_view view;
    if (fdt_init_view(fdt, &view))
        return -EINVAL;

    num_mem_regions = 0;
    num_reserved_regions = 0;

    if (fdt_parse_reserved(&view))
        return -EINVAL;

    uint32_t addr_cells_stack[MAX_FDT_DEPTH] = { 0 };
    uint32_t size_cells_stack[MAX_FDT_DEPTH] = { 0 };
    addr_cells_stack[0] = 2;
    size_cells_stack[0] = 1;

    struct fdt_iter it = { .p = view.struct_blk, .depth = 0 };
    bool in_memory = false;
    int memory_depth = -1;

    while (1) {
        uint32_t token = 0;
        const char *node_name = NULL;
        const char *prop_name = NULL;
        const void *prop_data = NULL;
        uint32_t prop_len = 0;

        int ret = fdt_next_token(&view, &it, &token, &node_name,
                                 &prop_name, &prop_data, &prop_len);
        if (ret)
            return ret;

        switch (token) {
        case FDT_BEGIN_NODE: {
            uint32_t parent = (it.depth > 0) ? (uint32_t)(it.depth - 1) : 0;
            addr_cells_stack[it.depth] = addr_cells_stack[parent];
            size_cells_stack[it.depth] = size_cells_stack[parent];
            if (fdt_is_memory_node(node_name)) {
                in_memory = true;
                memory_depth = it.depth;
            }
            break;
        }
        case FDT_END_NODE:
            if (in_memory && it.depth < memory_depth) {
                in_memory = false;
                memory_depth = -1;
            }
            break;
        case FDT_PROP:
            if (strcmp(prop_name, "#address-cells") == 0 && prop_len >= 4) {
                addr_cells_stack[it.depth] = fdt_be32(*(const uint32_t *)prop_data);
            } else if (strcmp(prop_name, "#size-cells") == 0 && prop_len >= 4) {
                size_cells_stack[it.depth] = fdt_be32(*(const uint32_t *)prop_data);
            } else if (in_memory && strcmp(prop_name, "reg") == 0) {
                if (it.depth <= 0)
                    break;
                uint32_t address_cells = addr_cells_stack[it.depth - 1];
                uint32_t size_cells = size_cells_stack[it.depth - 1];
                uint32_t entry_size = (address_cells + size_cells) * 4;
                if (entry_size == 0)
                    break;
                uint32_t num_entries = prop_len / entry_size;
                const uint32_t *reg = prop_data;
                for (uint32_t i = 0; i < num_entries && num_mem_regions < MAX_MEM_REGIONS; i++) {
                    paddr_t base = 0;
                    size_t size = 0;
                    if (fdt_read_reg(reg, prop_len - (i * entry_size),
                                     address_cells, size_cells, &base, &size) == 0) {
                        mem_regions[num_mem_regions].base = base;
                        mem_regions[num_mem_regions].size = size;
                        num_mem_regions++;
                    }
                    reg += entry_size / 4;
                }
            }
            break;
        case FDT_END:
            return 0;
        case FDT_NOP:
            break;
        default:
            return -EINVAL;
        }
    }
}

int fdt_get_memory(int index, paddr_t *base, size_t *size) {
    if (index < 0 || index >= num_mem_regions)
        return -1;
    *base = mem_regions[index].base;
    *size = mem_regions[index].size;
    return 0;
}

int fdt_memory_count(void) {
    return num_mem_regions;
}

int fdt_get_reserved(int index, paddr_t *base, size_t *size) {
    if (index < 0 || index >= num_reserved_regions)
        return -1;
    *base = reserved_regions[index].base;
    *size = reserved_regions[index].size;
    return 0;
}

int fdt_reserved_count(void) {
    return num_reserved_regions;
}

struct fdt_node_ctx {
    char name[64];
    const char *compatible;
    uint32_t compatible_len;
    const uint32_t *reg;
    uint32_t reg_len;
    const uint32_t *irq;
    uint32_t address_cells;
    uint32_t size_cells;
};

static bool fdt_compat_has(const char *compat, uint32_t len, const char *needle) {
    if (!compat || !needle || len == 0)
        return false;
    size_t needle_len = strlen(needle);
    const char *p = compat;
    const char *end = compat + len;
    while (p < end) {
        size_t slen = strnlen(p, (size_t)(end - p));
        if (slen == needle_len && strncmp(p, needle, slen) == 0)
            return true;
        p += slen + 1;
    }
    return false;
}

static void fdt_handle_virtio_mmio(const struct fdt_node_ctx *ctx) {
    if (!ctx)
        return;
    if (!fdt_compat_has(ctx->compatible, ctx->compatible_len, "virtio,mmio"))
        return;
    if (!ctx->reg || ctx->reg_len < (ctx->address_cells + ctx->size_cells) * 4)
        return;

    paddr_t base = 0;
    size_t size = 0;
    if (fdt_read_reg(ctx->reg, ctx->reg_len, ctx->address_cells,
                     ctx->size_cells, &base, &size))
        return;

    int irq = ctx->irq ? (int)fdt_be32(*ctx->irq) : 0;

    struct fw_device_desc *desc = kzalloc(sizeof(*desc));
    struct platform_device_info *info = kzalloc(sizeof(*info));
    size_t num_res = irq ? 2 : 1;
    struct resource *res = kzalloc(num_res * sizeof(*res));
    if (desc && info && res && size) {
        strncpy(desc->name, ctx->name, sizeof(desc->name) - 1);
        strncpy(desc->compatible, "virtio,mmio",
                sizeof(desc->compatible) - 1);

        info->base = base;
        info->size = size;
        info->irq = irq;
        strncpy(info->compatible, "virtio,mmio",
                sizeof(info->compatible) - 1);

        res[0].start = base;
        res[0].end = base + size - 1;
        res[0].flags = IORESOURCE_MEM;
        if (irq) {
            res[1].start = (uint64_t)irq;
            res[1].end = (uint64_t)irq;
            res[1].flags = IORESOURCE_IRQ;
        }

        desc->resources = res;
        desc->num_resources = num_res;
        desc->fw_data = info;

        pr_info("fdt: found virtio-mmio @ %p (irq %d)\n",
                (void *)base, irq);
        fw_register_desc(desc);
    } else {
        kfree(desc);
        kfree(info);
        kfree(res);
    }
}

static void fdt_handle_pci_ecam(const struct fdt_node_ctx *ctx) {
    if (!ctx)
        return;
    if (!fdt_compat_has(ctx->compatible, ctx->compatible_len,
                        "pci-host-ecam-generic"))
        return;
    if (!ctx->reg || ctx->reg_len < (ctx->address_cells + ctx->size_cells) * 4)
        return;

    paddr_t base = 0;
    size_t size = 0;
    if (fdt_read_reg(ctx->reg, ctx->reg_len, ctx->address_cells,
                     ctx->size_cells, &base, &size))
        return;

    /* Default INTx IRQ base for QEMU virt: PLIC IRQ 32 */
    uint32_t irq_base = ctx->irq ? fdt_be32(*ctx->irq) : 32;

    struct fw_device_desc *desc = kzalloc(sizeof(*desc));
    struct resource *res = kzalloc(2 * sizeof(*res));
    if (!desc || !res) {
        kfree(desc);
        kfree(res);
        return;
    }

    strncpy(desc->name, ctx->name, sizeof(desc->name) - 1);
    strncpy(desc->compatible, "pci-host-ecam-generic",
            sizeof(desc->compatible) - 1);

    /* Resource 0: ECAM MMIO region */
    res[0].start = base;
    res[0].end = base + size - 1;
    res[0].flags = IORESOURCE_MEM;

    /* Resource 1: IRQ base for INTx swizzle */
    res[1].start = (uint64_t)irq_base;
    res[1].end = (uint64_t)(irq_base + 3);
    res[1].flags = IORESOURCE_IRQ;

    desc->resources = res;
    desc->num_resources = 2;

    pr_info("fdt: found pci-host-ecam-generic @ %p size 0x%lx irq_base %u\n",
            (void *)base, (unsigned long)size, irq_base);
    fw_register_desc(desc);
}

int fdt_scan_devices(const void *fdt) {
    struct fdt_view view;
    if (fdt_init_view(fdt, &view))
        return -EINVAL;

    uint32_t addr_cells_stack[MAX_FDT_DEPTH] = { 0 };
    uint32_t size_cells_stack[MAX_FDT_DEPTH] = { 0 };
    addr_cells_stack[0] = 2;
    size_cells_stack[0] = 2;

    struct fdt_iter it = { .p = view.struct_blk, .depth = 0 };
    struct fdt_node_ctx ctx = { 0 };

    while (1) {
        uint32_t token = 0;
        const char *node_name = NULL;
        const char *prop_name = NULL;
        const void *prop_data = NULL;
        uint32_t prop_len = 0;

        int ret = fdt_next_token(&view, &it, &token, &node_name,
                                 &prop_name, &prop_data, &prop_len);
        if (ret)
            return ret;

        switch (token) {
        case FDT_BEGIN_NODE: {
            uint32_t parent = (it.depth > 0) ? (uint32_t)(it.depth - 1) : 0;
            addr_cells_stack[it.depth] = addr_cells_stack[parent];
            size_cells_stack[it.depth] = size_cells_stack[parent];

            strncpy(ctx.name, node_name, sizeof(ctx.name) - 1);
            ctx.name[sizeof(ctx.name) - 1] = '\0';
            ctx.compatible = NULL;
            ctx.compatible_len = 0;
            ctx.reg = NULL;
            ctx.reg_len = 0;
            ctx.irq = NULL;
            ctx.address_cells = addr_cells_stack[parent];
            ctx.size_cells = size_cells_stack[parent];
            break;
        }
        case FDT_END_NODE:
            fdt_handle_virtio_mmio(&ctx);
            fdt_handle_pci_ecam(&ctx);
            ctx.compatible = NULL;
            ctx.compatible_len = 0;
            ctx.reg = NULL;
            ctx.reg_len = 0;
            ctx.irq = NULL;
            ctx.name[0] = '\0';
            break;
        case FDT_PROP:
            if (strcmp(prop_name, "#address-cells") == 0 && prop_len >= 4) {
                addr_cells_stack[it.depth] = fdt_be32(*(const uint32_t *)prop_data);
            } else if (strcmp(prop_name, "#size-cells") == 0 && prop_len >= 4) {
                size_cells_stack[it.depth] = fdt_be32(*(const uint32_t *)prop_data);
            } else if (strcmp(prop_name, "compatible") == 0) {
                ctx.compatible = prop_data;
                ctx.compatible_len = prop_len;
            } else if (strcmp(prop_name, "reg") == 0) {
                ctx.reg = prop_data;
                ctx.reg_len = prop_len;
            } else if (strcmp(prop_name, "interrupts") == 0) {
                ctx.irq = prop_data;
            }
            break;
        case FDT_END:
            return 0;
        case FDT_NOP:
            break;
        default:
            return -EINVAL;
        }
    }
}
