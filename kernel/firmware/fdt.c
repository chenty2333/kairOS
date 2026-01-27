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

static inline uint32_t be32_to_cpu(uint32_t val) {
    return ((val & 0xff000000) >> 24) | ((val & 0x00ff0000) >> 8) |
           ((val & 0x0000ff00) << 8) | ((val & 0x000000ff) << 24);
}

static inline uintptr_t fdt_align(uintptr_t val) { return (val + 3) & ~3; }

#define MAX_MEM_REGIONS 64
struct mem_region { paddr_t base; size_t size; };
static struct mem_region mem_regions[MAX_MEM_REGIONS];
static int num_mem_regions;
static int num_reserved_regions;

int fdt_parse(void *fdt) {
    struct fdt_header *hdr = fdt;
    if (!fdt || be32_to_cpu(hdr->magic) != FDT_MAGIC) return -EINVAL;

    uint32_t totalsize = be32_to_cpu(hdr->totalsize);
    const char *fdt_end = (const char *)fdt + totalsize;
    const char *strings = (const char *)fdt + be32_to_cpu(hdr->off_dt_strings);
    uint32_t *p = (uint32_t *)((char *)fdt + be32_to_cpu(hdr->off_dt_struct));

    num_mem_regions = 0;
    num_reserved_regions = 0;

    int depth = 0, in_memory = 0;
    uint32_t address_cells = 2, size_cells = 1;

    while ((char *)p < fdt_end) {
        uint32_t token = be32_to_cpu(*p++);
        switch (token) {
        case FDT_BEGIN_NODE: {
            const char *name = (const char *)p;
            p = (uint32_t *)((char *)p + fdt_align(strlen(name) + 1));
            if (depth == 1 && (strcmp(name, "memory") == 0 || strncmp(name, "memory@", 7) == 0)) in_memory = 1;
            depth++;
            break;
        }
        case FDT_END_NODE:
            depth--;
            if (depth == 1) in_memory = 0;
            break;
        case FDT_PROP: {
            uint32_t len = be32_to_cpu(*p++);
            uint32_t nameoff = be32_to_cpu(*p++);
            const char *propname = strings + nameoff;
            void *data = p;
            p = (uint32_t *)((char *)p + fdt_align(len));

            if (depth == 1) {
                if (strcmp(propname, "#address-cells") == 0) address_cells = be32_to_cpu(*(uint32_t *)data);
                else if (strcmp(propname, "#size-cells") == 0) size_cells = be32_to_cpu(*(uint32_t *)data);
            }
            if (in_memory && strcmp(propname, "reg") == 0) {
                uint32_t *reg = data;
                uint32_t entry_size = (address_cells + size_cells) * 4;
                uint32_t num_entries = len / entry_size;
                for (uint32_t i = 0; i < num_entries && num_mem_regions < MAX_MEM_REGIONS; i++) {
                    paddr_t base = 0; size_t size = 0;
                    for (uint32_t j = 0; j < address_cells; j++) base = (base << 32) | be32_to_cpu(*reg++);
                    for (uint32_t j = 0; j < size_cells; j++) size = (size << 32) | be32_to_cpu(*reg++);
                    mem_regions[num_mem_regions].base = base;
                    mem_regions[num_mem_regions].size = size;
                    num_mem_regions++;
                }
            }
            break;
        }
        case FDT_END: return 0;
        case FDT_NOP: break;
        default: return -EINVAL;
        }
    }
    return -EINVAL;
}

int fdt_get_memory(int index, paddr_t *base, size_t *size) {
    if (index < 0 || index >= num_mem_regions) return -1;
    *base = mem_regions[index].base; *size = mem_regions[index].size; return 0;
}

int fdt_memory_count(void) { return num_mem_regions; }

/**
 * Scanning context for fdt_scan_devices
 */
struct scan_ctx {
    uint32_t address_cells;
    uint32_t size_cells;
    const char *compatible;
    uint32_t *reg;
    uint32_t reg_len;
    uint32_t *irq;
    char node_name[64];
};

static void fdt_process_node(struct scan_ctx *ctx) {
    if (ctx->compatible && strstr(ctx->compatible, "virtio,mmio")) {
        if (ctx->reg && ctx->reg_len >= (ctx->address_cells + ctx->size_cells) * 4) {
            paddr_t base = 0; size_t size = 0;
            uint32_t *rp = ctx->reg;
            for (uint32_t i = 0; i < ctx->address_cells; i++) base = (base << 32) | be32_to_cpu(*rp++);
            for (uint32_t i = 0; i < ctx->size_cells; i++) size = (size << 32) | be32_to_cpu(*rp++);

            int irq = ctx->irq ? (int)be32_to_cpu(*ctx->irq) : 0;

            struct fw_device_desc *desc = kzalloc(sizeof(*desc));
            struct platform_device_info *info = kzalloc(sizeof(*info));
            size_t num_res = irq ? 2 : 1;
            struct resource *res = kzalloc(num_res * sizeof(*res));
            if (desc && info && res && size) {
                strncpy(desc->name, ctx->node_name, sizeof(desc->name) - 1);
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
    }
    /* Reset context for next node */
    ctx->compatible = NULL; ctx->reg = NULL; ctx->irq = NULL; ctx->reg_len = 0;
}

int fdt_scan_devices(void *fdt) {
    struct fdt_header *hdr = fdt;
    if (!fdt || be32_to_cpu(hdr->magic) != FDT_MAGIC) return -EINVAL;

    uint32_t totalsize = be32_to_cpu(hdr->totalsize);
    const char *fdt_end = (const char *)fdt + totalsize;
    const char *strings = (const char *)fdt + be32_to_cpu(hdr->off_dt_strings);
    uint32_t *p = (uint32_t *)((char *)fdt + be32_to_cpu(hdr->off_dt_struct));

    struct scan_ctx ctx = { .address_cells = 2, .size_cells = 2 };
    int depth = 0;

    while ((char *)p < fdt_end) {
        uint32_t token = be32_to_cpu(*p++);
        switch (token) {
        case FDT_BEGIN_NODE: {
            const char *name = (const char *)p;
            strncpy(ctx.node_name, name, sizeof(ctx.node_name) - 1);
            p = (uint32_t *)((char *)p + fdt_align(strlen(name) + 1));
            depth++;
            ctx.compatible = NULL; ctx.reg = NULL; ctx.irq = NULL; ctx.reg_len = 0;
            break;
        }
        case FDT_END_NODE:
            fdt_process_node(&ctx);
            depth--;
            break;
        case FDT_PROP: {
            uint32_t len = be32_to_cpu(*p++);
            uint32_t nameoff = be32_to_cpu(*p++);
            const char *propname = strings + nameoff;
            void *data = p;
            p = (uint32_t *)((char *)p + fdt_align(len));
            if (depth == 1) {
                if (strcmp(propname, "#address-cells") == 0) ctx.address_cells = be32_to_cpu(*(uint32_t *)data);
                if (strcmp(propname, "#size-cells") == 0) ctx.size_cells = be32_to_cpu(*(uint32_t *)data);
            }
            if (strcmp(propname, "compatible") == 0) ctx.compatible = data;
            else if (strcmp(propname, "reg") == 0) { ctx.reg = data; ctx.reg_len = len; }
            else if (strcmp(propname, "interrupts") == 0) ctx.irq = data;
            break;
        }
        case FDT_END: return 0;
        case FDT_NOP: break;
        default: return -EINVAL;
        }
    }
    return 0;
}
