/**
 * kernel/firmware/fdt.c - Flattened Device Tree (FDT) parser
 */

#include <kairos/types.h>
#include <kairos/string.h>
#include <kairos/fdt.h>
#include <kairos/device.h>
#include <kairos/firmware.h>
#include <kairos/platform.h>
#include <kairos/platform_core.h>
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
#define FDT_NODE_PATH_MAX 128
#define FDT_ALIAS_MAX 32
#define FDT_ALIAS_NAME_MAX 32
#define FDT_IRQ_DOMAIN_MAX 64

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

#define FDT_ROOT_COMPAT_MAX 64

static struct mem_region mem_regions[MAX_MEM_REGIONS];
static struct mem_region reserved_regions[MAX_RESERVED_REGIONS];
static int num_mem_regions;
static int num_reserved_regions;
static char root_compatible[FDT_ROOT_COMPAT_MAX];

struct fdt_alias_entry {
    char name[FDT_ALIAS_NAME_MAX];
    char path[FDT_NODE_PATH_MAX];
};

struct fdt_irq_domain_entry {
    uint32_t phandle;
    uint32_t irq_cells;
};

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

static int fdt_read_addr(const uint32_t *reg, uint32_t reg_len,
                         uint32_t address_cells, uint64_t *addr) {
    if (!reg || !addr)
        return -EINVAL;
    if (address_cells == 0)
        return -EINVAL;
    if (reg_len < address_cells * 4)
        return -EINVAL;

    uint64_t out = 0;
    for (uint32_t i = 0; i < address_cells; i++)
        out = (out << 32) | fdt_be32(reg[i]);
    *addr = out;
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
    root_compatible[0] = '\0';

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
            } else if (it.depth == 1 && strcmp(prop_name, "compatible") == 0 &&
                       prop_len > 0 && !root_compatible[0]) {
                size_t len = strnlen(prop_data, prop_len);
                if (len >= FDT_ROOT_COMPAT_MAX)
                    len = FDT_ROOT_COMPAT_MAX - 1;
                memcpy(root_compatible, prop_data, len);
                root_compatible[len] = '\0';
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

const char *fdt_root_compatible(void)
{
    return root_compatible[0] ? root_compatible : NULL;
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

int fdt_get_cpus(const void *fdt, uint64_t *cpu_ids, uint32_t max_ids,
                 uint32_t *out_count) {
    if (!fdt || !cpu_ids || !out_count || max_ids == 0)
        return -EINVAL;

    struct fdt_view view;
    if (fdt_init_view(fdt, &view))
        return -EINVAL;

    uint32_t addr_cells_stack[MAX_FDT_DEPTH] = { 0 };
    uint32_t size_cells_stack[MAX_FDT_DEPTH] = { 0 };
    addr_cells_stack[0] = 2;
    size_cells_stack[0] = 1;

    struct fdt_iter it = { .p = view.struct_blk, .depth = 0 };
    bool in_cpus = false;
    int cpus_depth = -1;
    bool in_cpu_node = false;
    int cpu_depth = -1;
    bool cpu_is_cpu = false;
    bool cpu_has_reg = false;
    uint64_t cpu_reg = 0;
    uint32_t cpu_addr_cells = 1;

    *out_count = 0;

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

            if (it.depth == 2 && strcmp(node_name, "cpus") == 0) {
                in_cpus = true;
                cpus_depth = it.depth;
            }

            if (in_cpus && it.depth == cpus_depth + 1) {
                in_cpu_node = true;
                cpu_depth = it.depth;
                cpu_is_cpu = strncmp(node_name, "cpu@", 4) == 0;
                cpu_has_reg = false;
                cpu_reg = 0;
                cpu_addr_cells = addr_cells_stack[parent];
            }
            break;
        }
        case FDT_END_NODE:
            if (in_cpu_node && it.depth < cpu_depth) {
                if (cpu_is_cpu && cpu_has_reg && *out_count < max_ids) {
                    cpu_ids[*out_count] = cpu_reg;
                    (*out_count)++;
                }
                in_cpu_node = false;
            }
            if (in_cpus && it.depth < cpus_depth) {
                in_cpus = false;
                cpus_depth = -1;
            }
            break;
        case FDT_PROP:
            if (strcmp(prop_name, "#address-cells") == 0 && prop_len >= 4) {
                addr_cells_stack[it.depth] =
                    fdt_be32(*(const uint32_t *)prop_data);
            } else if (strcmp(prop_name, "#size-cells") == 0 && prop_len >= 4) {
                size_cells_stack[it.depth] =
                    fdt_be32(*(const uint32_t *)prop_data);
            } else if (in_cpu_node && strcmp(prop_name, "device_type") == 0 &&
                       prop_len >= 3 && strncmp(prop_data, "cpu", 3) == 0) {
                cpu_is_cpu = true;
            } else if (in_cpu_node && strcmp(prop_name, "reg") == 0) {
                if (fdt_read_addr((const uint32_t *)prop_data, prop_len,
                                  cpu_addr_cells, &cpu_reg) == 0)
                    cpu_has_reg = true;
            }
            break;
        case FDT_END:
            return (*out_count > 0) ? 0 : -ENODEV;
        case FDT_NOP:
            break;
        default:
            return -EINVAL;
        }
    }
}

static bool fdt_prop_has_compat(const void *prop, uint32_t prop_len,
                                const char *prefix) {
    if (!prop || !prefix || prop_len == 0)
        return false;

    const char *s = (const char *)prop;
    const char *end = s + prop_len;
    size_t plen = strlen(prefix);
    while (s < end) {
        size_t left = (size_t)(end - s);
        const char *nul = memchr(s, '\0', left);
        if (!nul)
            break;
        size_t len = (size_t)(nul - s);
        if (len >= plen && strncmp(s, prefix, plen) == 0)
            return true;
        s = nul + 1;
    }
    return false;
}

int fdt_get_psci_method(const void *fdt, char *method, size_t method_len) {
    if (!fdt || !method || method_len < 2)
        return -EINVAL;

    struct fdt_view view;
    if (fdt_init_view(fdt, &view))
        return -EINVAL;

    struct fdt_iter it = { .p = view.struct_blk, .depth = 0 };
    bool in_node = false;
    int node_depth = -1;
    bool node_psci = false;
    const char *found = NULL;
    uint32_t found_len = 0;

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
        case FDT_BEGIN_NODE:
            in_node = true;
            node_depth = it.depth;
            node_psci = (strcmp(node_name, "psci") == 0);
            found = NULL;
            found_len = 0;
            break;
        case FDT_END_NODE:
            if (in_node && it.depth < node_depth) {
                if (node_psci && found) {
                    size_t copy_len = found_len;
                    if (copy_len >= method_len)
                        copy_len = method_len - 1;
                    memcpy(method, found, copy_len);
                    method[copy_len] = '\0';
                    return 0;
                }
                in_node = false;
                node_depth = -1;
                node_psci = false;
                found = NULL;
                found_len = 0;
            }
            break;
        case FDT_PROP:
            if (!in_node)
                break;
            if (strcmp(prop_name, "compatible") == 0 &&
                fdt_prop_has_compat(prop_data, prop_len, "arm,psci")) {
                node_psci = true;
            } else if (strcmp(prop_name, "method") == 0 && prop_len > 0) {
                const char *nul = memchr(prop_data, '\0', prop_len);
                if (nul) {
                    found = (const char *)prop_data;
                    found_len = (uint32_t)(nul - (const char *)prop_data);
                }
            }
            break;
        case FDT_END:
            return -ENODEV;
        case FDT_NOP:
            break;
        default:
            return -EINVAL;
        }
    }
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

struct fdt_uart_scan_ctx {
    const char *compatible;
    uint32_t compatible_len;
    const uint32_t *reg;
    uint32_t reg_len;
    const uint32_t *interrupts;
    uint32_t interrupts_len;
    const uint32_t *interrupts_extended;
    uint32_t interrupts_extended_len;
    uint32_t address_cells;
    uint32_t size_cells;
    uint32_t irq_parent;
    uint32_t irq_cells_hint;
};

static void fdt_path_push(const char *parent, const char *node, char *out,
                          size_t out_len) {
    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!node)
        return;
    if (node[0] == '\0') {
        if (out_len >= 2) {
            out[0] = '/';
            out[1] = '\0';
        }
        return;
    }

    size_t pos = 0;
    if (!parent || parent[0] == '\0' ||
        (parent[0] == '/' && parent[1] == '\0')) {
        if (out_len < 2)
            return;
        out[pos++] = '/';
    } else {
        size_t parent_len = strnlen(parent, out_len - 1);
        memcpy(out, parent, parent_len);
        pos = parent_len;
        if (pos < out_len - 1 && out[pos - 1] != '/')
            out[pos++] = '/';
    }

    if (pos >= out_len - 1) {
        out[out_len - 1] = '\0';
        return;
    }

    size_t node_len = strnlen(node, out_len - pos - 1);
    memcpy(out + pos, node, node_len);
    pos += node_len;
    out[pos] = '\0';
}

static int fdt_copy_prop_string(const void *prop, uint32_t prop_len, char *out,
                                size_t out_len) {
    if (!prop || !out || out_len == 0 || prop_len == 0)
        return -EINVAL;
    const char *nul = memchr(prop, '\0', prop_len);
    if (!nul)
        return -EINVAL;
    size_t len = (size_t)(nul - (const char *)prop);
    if (len == 0)
        return -EINVAL;
    if (len >= out_len)
        len = out_len - 1;
    memcpy(out, prop, len);
    out[len] = '\0';
    return 0;
}

static void fdt_strip_path_opts(char *path) {
    if (!path)
        return;
    char *colon = strchr(path, ':');
    if (colon)
        *colon = '\0';
}

static void fdt_copy_first_compat(const char *compat, uint32_t len, char *out,
                                  size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (!compat || len == 0)
        return;
    size_t slen = strnlen(compat, len);
    if (slen >= out_len)
        slen = out_len - 1;
    memcpy(out, compat, slen);
    out[slen] = '\0';
}

static const char *fdt_find_alias_path(const struct fdt_alias_entry *aliases,
                                       size_t alias_count,
                                       const char *alias_name) {
    if (!aliases || !alias_name)
        return NULL;
    for (size_t i = 0; i < alias_count; i++) {
        if (strcmp(aliases[i].name, alias_name) == 0)
            return aliases[i].path;
    }
    return NULL;
}

static bool fdt_compat_matches_any(const char *compat, uint32_t compat_len,
                                   const char *const *compat_list,
                                   size_t compat_count) {
    if (!compat || compat_len == 0)
        return false;
    if (!compat_list || compat_count == 0) {
        return fdt_prop_has_compat(compat, compat_len, "uart") ||
               fdt_prop_has_compat(compat, compat_len, "serial");
    }
    for (size_t i = 0; i < compat_count; i++) {
        const char *needle = compat_list[i];
        if (needle && fdt_compat_has(compat, compat_len, needle))
            return true;
    }
    return false;
}

static uint32_t fdt_irq_domain_lookup(
    const struct fdt_irq_domain_entry *irq_domains, size_t irq_domain_count,
    uint32_t phandle) {
    if (!irq_domains || !phandle)
        return 0;
    for (size_t i = 0; i < irq_domain_count; i++) {
        if (irq_domains[i].phandle == phandle)
            return irq_domains[i].irq_cells;
    }
    return 0;
}

static int fdt_parse_irq_spec(const uint32_t *spec, uint32_t cells) {
    if (!spec || cells == 0)
        return 0;

    uint32_t c0 = fdt_be32(spec[0]);
    if (cells >= 3 && (c0 == 0U || c0 == 1U)) {
        uint32_t irq_num = fdt_be32(spec[1]);
        if (c0 == 0U)
            return (int)(irq_num + 32U); /* GIC SPI */
        return (int)(irq_num + 16U);     /* GIC PPI */
    }

    if (cells >= 2)
        return (int)fdt_be32(spec[1]);
    return (int)c0;
}

static int fdt_irq_to_virq(int irq)
{
    if (irq <= 0)
        return irq;
    const struct platform_desc *plat = platform_get();
    if (!plat || !plat->irqchip)
        return irq;
    int virq = platform_irq_domain_map(plat->irqchip, (uint32_t)irq);
    if (virq < 0)
        return irq;
    return virq;
}

static int fdt_parse_uart_irq(
    const uint32_t *interrupts, uint32_t interrupts_len,
    const uint32_t *interrupts_extended, uint32_t interrupts_extended_len,
    uint32_t irq_parent, uint32_t irq_cells_hint,
    const struct fdt_irq_domain_entry *irq_domains, size_t irq_domain_count) {
    if (interrupts_extended && interrupts_extended_len >= 8) {
        uint32_t total_cells = interrupts_extended_len / 4;
        uint32_t idx = 0;
        while (idx + 1 < total_cells) {
            uint32_t parent = fdt_be32(interrupts_extended[idx++]);
            uint32_t spec_cells = fdt_irq_domain_lookup(
                irq_domains, irq_domain_count, parent);
            if (spec_cells == 0 || idx + spec_cells > total_cells)
                break;
            int irq = fdt_parse_irq_spec(interrupts_extended + idx, spec_cells);
            if (irq > 0)
                return fdt_irq_to_virq(irq);
            idx += spec_cells;
        }
    }

    if (interrupts && interrupts_len >= 4) {
        uint32_t spec_cells = fdt_irq_domain_lookup(
            irq_domains, irq_domain_count, irq_parent);
        if (spec_cells == 0)
            spec_cells = irq_cells_hint;
        if (spec_cells == 0)
            spec_cells = interrupts_len / 4;
        uint32_t available = interrupts_len / 4;
        if (spec_cells > available)
            spec_cells = available;
        int irq = fdt_parse_irq_spec(interrupts, spec_cells);
        if (irq > 0)
            return fdt_irq_to_virq(irq);
    }

    return 0;
}

static int fdt_collect_stdout_context(
    struct fdt_view *view, char *stdout_target, size_t stdout_target_len,
    struct fdt_alias_entry *aliases, size_t *alias_count,
    struct fdt_irq_domain_entry *irq_domains, size_t *irq_domain_count) {
    if (!view || !alias_count || !irq_domain_count)
        return -EINVAL;

    *alias_count = 0;
    *irq_domain_count = 0;
    if (stdout_target && stdout_target_len > 0)
        stdout_target[0] = '\0';

    struct fdt_iter it = { .p = view->struct_blk, .depth = 0 };
    char path_stack[MAX_FDT_DEPTH][FDT_NODE_PATH_MAX] = { { 0 } };
    uint32_t node_phandle[MAX_FDT_DEPTH] = { 0 };
    uint32_t node_irq_cells[MAX_FDT_DEPTH] = { 0 };

    while (1) {
        uint32_t token = 0;
        const char *node_name = NULL;
        const char *prop_name = NULL;
        const void *prop_data = NULL;
        uint32_t prop_len = 0;

        int ret = fdt_next_token(view, &it, &token,
                                 &node_name, &prop_name, &prop_data, &prop_len);
        if (ret)
            return ret;

        switch (token) {
        case FDT_BEGIN_NODE: {
            uint32_t parent = (it.depth > 0) ? (uint32_t)(it.depth - 1) : 0;
            const char *parent_path =
                (it.depth > 1) ? path_stack[parent] : NULL;
            fdt_path_push(parent_path, node_name, path_stack[it.depth],
                          sizeof(path_stack[it.depth]));
            node_phandle[it.depth] = 0;
            node_irq_cells[it.depth] = 0;
            break;
        }
        case FDT_END_NODE: {
            int ended_depth = it.depth + 1;
            if (ended_depth > 0 && ended_depth < MAX_FDT_DEPTH &&
                node_phandle[ended_depth] && node_irq_cells[ended_depth] &&
                irq_domains && *irq_domain_count < FDT_IRQ_DOMAIN_MAX) {
                bool seen = false;
                for (size_t i = 0; i < *irq_domain_count; i++) {
                    if (irq_domains[i].phandle == node_phandle[ended_depth]) {
                        irq_domains[i].irq_cells = node_irq_cells[ended_depth];
                        seen = true;
                        break;
                    }
                }
                if (!seen) {
                    irq_domains[*irq_domain_count].phandle =
                        node_phandle[ended_depth];
                    irq_domains[*irq_domain_count].irq_cells =
                        node_irq_cells[ended_depth];
                    (*irq_domain_count)++;
                }
            }
            if (ended_depth > 0 && ended_depth < MAX_FDT_DEPTH) {
                path_stack[ended_depth][0] = '\0';
                node_phandle[ended_depth] = 0;
                node_irq_cells[ended_depth] = 0;
            }
            break;
        }
        case FDT_PROP:
            if (it.depth <= 0 || it.depth >= MAX_FDT_DEPTH)
                break;
            if ((strcmp(prop_name, "phandle") == 0 ||
                 strcmp(prop_name, "linux,phandle") == 0) &&
                prop_len >= 4) {
                node_phandle[it.depth] = fdt_be32(*(const uint32_t *)prop_data);
            } else if (strcmp(prop_name, "#interrupt-cells") == 0 &&
                       prop_len >= 4) {
                node_irq_cells[it.depth] =
                    fdt_be32(*(const uint32_t *)prop_data);
            }

            if (stdout_target && stdout_target[0] == '\0' &&
                strcmp(path_stack[it.depth], "/chosen") == 0 &&
                (strcmp(prop_name, "stdout-path") == 0 ||
                 strcmp(prop_name, "linux,stdout-path") == 0) &&
                fdt_copy_prop_string(prop_data, prop_len, stdout_target,
                                     stdout_target_len) == 0) {
                fdt_strip_path_opts(stdout_target);
            } else if (aliases && strcmp(path_stack[it.depth], "/aliases") == 0) {
                if (*alias_count >= FDT_ALIAS_MAX)
                    break;
                char alias_path[FDT_NODE_PATH_MAX];
                if (fdt_copy_prop_string(prop_data, prop_len, alias_path,
                                         sizeof(alias_path)) != 0)
                    break;
                fdt_strip_path_opts(alias_path);
                if (alias_path[0] != '/')
                    break;

                bool seen = false;
                for (size_t i = 0; i < *alias_count; i++) {
                    if (strcmp(aliases[i].name, prop_name) == 0) {
                        strncpy(aliases[i].path, alias_path,
                                sizeof(aliases[i].path) - 1);
                        aliases[i].path[sizeof(aliases[i].path) - 1] = '\0';
                        seen = true;
                        break;
                    }
                }
                if (!seen) {
                    struct fdt_alias_entry *entry = &aliases[*alias_count];
                    strncpy(entry->name, prop_name, sizeof(entry->name) - 1);
                    entry->name[sizeof(entry->name) - 1] = '\0';
                    strncpy(entry->path, alias_path, sizeof(entry->path) - 1);
                    entry->path[sizeof(entry->path) - 1] = '\0';
                    (*alias_count)++;
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

static int fdt_resolve_stdout_path(const char *stdout_target,
                                   const struct fdt_alias_entry *aliases,
                                   size_t alias_count, char *resolved,
                                   size_t resolved_len) {
    if (!stdout_target || !stdout_target[0] || !resolved || resolved_len == 0)
        return -ENODEV;
    if (stdout_target[0] == '/') {
        strncpy(resolved, stdout_target, resolved_len - 1);
        resolved[resolved_len - 1] = '\0';
        return 0;
    }
    const char *alias_path =
        fdt_find_alias_path(aliases, alias_count, stdout_target);
    if (!alias_path)
        return -ENODEV;
    strncpy(resolved, alias_path, resolved_len - 1);
    resolved[resolved_len - 1] = '\0';
    return 0;
}

static int fdt_find_uart_node(
    struct fdt_view *view, const char *preferred_path,
    const char *const *compat_list, size_t compat_count,
    const struct fdt_irq_domain_entry *irq_domains, size_t irq_domain_count,
    struct fdt_uart_info *out) {
    if (!view || !out)
        return -EINVAL;

    struct fdt_iter it = { .p = view->struct_blk, .depth = 0 };
    uint32_t addr_cells_stack[MAX_FDT_DEPTH] = { 0 };
    uint32_t size_cells_stack[MAX_FDT_DEPTH] = { 0 };
    uint32_t irq_parent_stack[MAX_FDT_DEPTH] = { 0 };
    uint32_t irq_cells_stack[MAX_FDT_DEPTH] = { 0 };
    char path_stack[MAX_FDT_DEPTH][FDT_NODE_PATH_MAX] = { { 0 } };
    struct fdt_uart_scan_ctx node_stack[MAX_FDT_DEPTH] = { { 0 } };
    struct fdt_uart_info fallback = { 0 };
    bool have_fallback = false;

    addr_cells_stack[0] = 2;
    size_cells_stack[0] = 2;
    irq_cells_stack[0] = 1;

    while (1) {
        uint32_t token = 0;
        const char *node_name = NULL;
        const char *prop_name = NULL;
        const void *prop_data = NULL;
        uint32_t prop_len = 0;

        int ret = fdt_next_token(view, &it, &token,
                                 &node_name, &prop_name, &prop_data, &prop_len);
        if (ret)
            return ret;

        switch (token) {
        case FDT_BEGIN_NODE: {
            uint32_t parent = (it.depth > 0) ? (uint32_t)(it.depth - 1) : 0;
            const char *parent_path =
                (it.depth > 1) ? path_stack[parent] : NULL;
            fdt_path_push(parent_path, node_name, path_stack[it.depth],
                          sizeof(path_stack[it.depth]));
            addr_cells_stack[it.depth] = addr_cells_stack[parent];
            size_cells_stack[it.depth] = size_cells_stack[parent];
            irq_parent_stack[it.depth] = irq_parent_stack[parent];
            irq_cells_stack[it.depth] = irq_cells_stack[parent];

            struct fdt_uart_scan_ctx *ctx = &node_stack[it.depth];
            memset(ctx, 0, sizeof(*ctx));
            ctx->address_cells = addr_cells_stack[parent];
            ctx->size_cells = size_cells_stack[parent];
            ctx->irq_parent = irq_parent_stack[parent];
            ctx->irq_cells_hint = irq_cells_stack[parent];
            break;
        }
        case FDT_END_NODE: {
            int ended_depth = it.depth + 1;
            if (ended_depth > 0 && ended_depth < MAX_FDT_DEPTH) {
                struct fdt_uart_scan_ctx *ctx = &node_stack[ended_depth];
                if (fdt_compat_matches_any(ctx->compatible, ctx->compatible_len,
                                           compat_list, compat_count) &&
                    ctx->reg &&
                    ctx->reg_len >=
                        (ctx->address_cells + ctx->size_cells) * 4) {
                    struct fdt_uart_info candidate = { 0 };
                    if (fdt_read_reg(ctx->reg, ctx->reg_len, ctx->address_cells,
                                     ctx->size_cells, &candidate.base,
                                     &candidate.size) == 0 &&
                        candidate.size > 0) {
                        candidate.irq = fdt_parse_uart_irq(
                            ctx->interrupts, ctx->interrupts_len,
                            ctx->interrupts_extended,
                            ctx->interrupts_extended_len, ctx->irq_parent,
                            ctx->irq_cells_hint, irq_domains, irq_domain_count);
                        strncpy(candidate.path, path_stack[ended_depth],
                                sizeof(candidate.path) - 1);
                        candidate.path[sizeof(candidate.path) - 1] = '\0';
                        fdt_copy_first_compat(ctx->compatible, ctx->compatible_len,
                                              candidate.compatible,
                                              sizeof(candidate.compatible));
                        if (preferred_path &&
                            strcmp(candidate.path, preferred_path) == 0) {
                            *out = candidate;
                            return 0;
                        }
                        if (!have_fallback) {
                            fallback = candidate;
                            have_fallback = true;
                        }
                    }
                }
                memset(ctx, 0, sizeof(*ctx));
                path_stack[ended_depth][0] = '\0';
            }
            break;
        }
        case FDT_PROP:
            if (it.depth <= 0 || it.depth >= MAX_FDT_DEPTH)
                break;
            if (strcmp(prop_name, "#address-cells") == 0 && prop_len >= 4) {
                addr_cells_stack[it.depth] =
                    fdt_be32(*(const uint32_t *)prop_data);
            } else if (strcmp(prop_name, "#size-cells") == 0 && prop_len >= 4) {
                size_cells_stack[it.depth] =
                    fdt_be32(*(const uint32_t *)prop_data);
            } else if (strcmp(prop_name, "#interrupt-cells") == 0 &&
                       prop_len >= 4) {
                irq_cells_stack[it.depth] =
                    fdt_be32(*(const uint32_t *)prop_data);
            } else if (strcmp(prop_name, "interrupt-parent") == 0 &&
                       prop_len >= 4) {
                uint32_t parent = fdt_be32(*(const uint32_t *)prop_data);
                irq_parent_stack[it.depth] = parent;
                node_stack[it.depth].irq_parent = parent;
            } else if (strcmp(prop_name, "compatible") == 0) {
                node_stack[it.depth].compatible = prop_data;
                node_stack[it.depth].compatible_len = prop_len;
            } else if (strcmp(prop_name, "reg") == 0) {
                node_stack[it.depth].reg = prop_data;
                node_stack[it.depth].reg_len = prop_len;
            } else if (strcmp(prop_name, "interrupts") == 0) {
                node_stack[it.depth].interrupts = prop_data;
                node_stack[it.depth].interrupts_len = prop_len;
            } else if (strcmp(prop_name, "interrupts-extended") == 0) {
                node_stack[it.depth].interrupts_extended = prop_data;
                node_stack[it.depth].interrupts_extended_len = prop_len;
            }
            break;
        case FDT_END:
            if (have_fallback) {
                *out = fallback;
                return 0;
            }
            return -ENODEV;
        case FDT_NOP:
            break;
        default:
            return -EINVAL;
        }
    }
}

int fdt_get_stdout_uart(const void *fdt, const char *const *compat_list,
                        size_t compat_count, struct fdt_uart_info *out) {
    if (!fdt || !out)
        return -EINVAL;

    struct fdt_view view;
    if (fdt_init_view(fdt, &view))
        return -EINVAL;

    memset(out, 0, sizeof(*out));

    char stdout_target[FDT_NODE_PATH_MAX] = { 0 };
    char preferred_path[FDT_NODE_PATH_MAX] = { 0 };
    struct fdt_alias_entry aliases[FDT_ALIAS_MAX] = { { 0 } };
    struct fdt_irq_domain_entry irq_domains[FDT_IRQ_DOMAIN_MAX] = { { 0 } };
    size_t alias_count = 0;
    size_t irq_domain_count = 0;

    int ret = fdt_collect_stdout_context(&view, stdout_target,
                                         sizeof(stdout_target), aliases,
                                         &alias_count, irq_domains,
                                         &irq_domain_count);
    if (ret)
        return ret;

    const char *preferred = NULL;
    if (fdt_resolve_stdout_path(stdout_target, aliases, alias_count,
                                preferred_path, sizeof(preferred_path)) == 0) {
        preferred = preferred_path;
    }

    return fdt_find_uart_node(&view, preferred, compat_list, compat_count,
                              irq_domains, irq_domain_count, out);
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

    int irq = ctx->irq ? fdt_irq_to_virq((int)fdt_be32(*ctx->irq)) : 0;

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
    int virq_base = fdt_irq_to_virq((int)irq_base);
    if (virq_base > 0)
        irq_base = (uint32_t)virq_base;

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
