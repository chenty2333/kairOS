/**
 * fdt.c - Flattened Device Tree (FDT) parser
 *
 * Minimal DTB parser to extract memory information.
 * Optimized to use kernel string functions and enforce bounds checking.
 * Reference: https://devicetree-specification.readthedocs.io/
 */

#include <kairos/types.h>
#include <kairos/string.h>

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

/* FDT tokens */
#define FDT_BEGIN_NODE  0x00000001
#define FDT_END_NODE    0x00000002
#define FDT_PROP        0x00000003
#define FDT_NOP         0x00000004
#define FDT_END         0x00000009

#define FDT_MAGIC       0xd00dfeed

/* Big-endian to host conversion */
static inline uint32_t be32_to_cpu(uint32_t val)
{
    return ((val & 0xff000000) >> 24) |
           ((val & 0x00ff0000) >> 8) |
           ((val & 0x0000ff00) << 8) |
           ((val & 0x000000ff) << 24);
}

static inline uint64_t be64_to_cpu(uint64_t val)
{
    return ((uint64_t)be32_to_cpu(val & 0xffffffff) << 32) |
           be32_to_cpu(val >> 32);
}

/* Align to 4 bytes */
static inline uintptr_t fdt_align(uintptr_t val)
{
    return (val + 3) & ~3;
}

/* Memory region storage - Increased limit for complex SoCs */
#define MAX_MEM_REGIONS 64

struct mem_region {
    paddr_t base;
    size_t size;
};

static struct mem_region mem_regions[MAX_MEM_REGIONS];
static int num_mem_regions;

/* Reserved memory */
static struct mem_region reserved_regions[MAX_MEM_REGIONS];
static int num_reserved_regions;

/**
 * fdt_parse - Parse FDT to extract memory information
 * @fdt: Pointer to FDT blob
 *
 * Returns 0 on success, negative on error.
 */
int fdt_parse(void *fdt)
{
    struct fdt_header *hdr = fdt;
    
    /* Basic validation */
    if (!fdt || be32_to_cpu(hdr->magic) != FDT_MAGIC) {
        return -EINVAL;
    }

    uint32_t totalsize = be32_to_cpu(hdr->totalsize);
    const char *fdt_end = (const char *)fdt + totalsize;

    /* Get string table and structure block */
    uint32_t off_dt_strings = be32_to_cpu(hdr->off_dt_strings);
    uint32_t off_dt_struct = be32_to_cpu(hdr->off_dt_struct);
    
    if (off_dt_strings >= totalsize || off_dt_struct >= totalsize) {
        return -EINVAL;
    }

    const char *strings = (const char *)fdt + off_dt_strings;
    uint32_t *p = (uint32_t *)((char *)fdt + off_dt_struct);

    num_mem_regions = 0;
    num_reserved_regions = 0;

    /* Parse memory reservation block */
    uint32_t off_mem_rsvmap = be32_to_cpu(hdr->off_mem_rsvmap);
    if (off_mem_rsvmap < totalsize) {
        uint64_t *memrsv = (uint64_t *)((char *)fdt + off_mem_rsvmap);
        
        while ((char *)memrsv < fdt_end) {
            uint64_t addr = be64_to_cpu(memrsv[0]);
            uint64_t size = be64_to_cpu(memrsv[1]);
            
            if (addr == 0 && size == 0) {
                break;
            }
            if (num_reserved_regions < MAX_MEM_REGIONS) {
                reserved_regions[num_reserved_regions].base = addr;
                reserved_regions[num_reserved_regions].size = size;
                num_reserved_regions++;
            }
            memrsv += 2;
        }
    }

    /* Parse structure block */
    int depth = 0;
    int in_memory = 0;
    uint32_t address_cells = 2; // Default for root
    uint32_t size_cells = 1;    // Default for root

    while ((char *)p < fdt_end) {
        uint32_t token = be32_to_cpu(*p++);

        switch (token) {
        case FDT_BEGIN_NODE: {
            const char *name = (const char *)p;
            size_t name_len = strlen(name);
            
            p = (uint32_t *)((char *)p + fdt_align(name_len + 1));
            
            /* Check memory node: "memory" or "memory@..." */
            if (depth == 1 && (strcmp(name, "memory") == 0 || strncmp(name, "memory@", 7) == 0)) {
                in_memory = 1;
            }
            depth++;
            break;
        }

        case FDT_END_NODE:
            depth--;
            if (depth == 1) {
                in_memory = 0;
            }
            if (depth < 0) return -EINVAL;
            break;

        case FDT_PROP: {
            if ((char *)p + 8 > fdt_end) return -EINVAL;
            
            uint32_t len = be32_to_cpu(*p++);
            uint32_t nameoff = be32_to_cpu(*p++);
            
            if ((const char *)strings + nameoff >= fdt_end) return -EINVAL;
            const char *propname = strings + nameoff;
            
            void *data = p;
            p = (uint32_t *)((char *)p + fdt_align(len));
            
            if ((char *)p > fdt_end) return -EINVAL;

            /* Root node properties */
            if (depth == 1) {
                if (strcmp(propname, "#address-cells") == 0) {
                    if (len >= 4) address_cells = be32_to_cpu(*(uint32_t *)data);
                } else if (strcmp(propname, "#size-cells") == 0) {
                    if (len >= 4) size_cells = be32_to_cpu(*(uint32_t *)data);
                }
            }

            /* Memory node reg property */
            if (in_memory && strcmp(propname, "reg") == 0) {
                uint32_t *reg = data;
                uint32_t entry_size = (address_cells + size_cells) * 4;
                if (entry_size == 0) break; 
                
                uint32_t num_entries = len / entry_size;

                for (uint32_t i = 0; i < num_entries && num_mem_regions < MAX_MEM_REGIONS; i++) {
                    paddr_t base = 0;
                    size_t size = 0;

                    /* Read base address */
                    for (uint32_t j = 0; j < address_cells; j++) {
                        base = (base << 32) | be32_to_cpu(*reg++);
                    }
                    /* Read size */
                    for (uint32_t j = 0; j < size_cells; j++) {
                        size = (size << 32) | be32_to_cpu(*reg++);
                    }

                    mem_regions[num_mem_regions].base = base;
                    mem_regions[num_mem_regions].size = size;
                    num_mem_regions++;
                }
            }
            break;
        }

        case FDT_NOP:
            break;

        case FDT_END:
            return 0;

        default:
            /* Unknown token - stop to be safe */
            return -EINVAL;
        }
    }
    
    return -EINVAL; /* Should hit FDT_END */
}

/**
 * fdt_get_memory - Get memory region by index
 * @index: Region index
 * @base: Output base address
 * @size: Output size
 *
 * Returns 0 on success, -1 if index out of range.
 */
int fdt_get_memory(int index, paddr_t *base, size_t *size)
{
    if (index < 0 || index >= num_mem_regions) {
        return -1;
    }
    *base = mem_regions[index].base;
    *size = mem_regions[index].size;
    return 0;
}

/**
 * fdt_memory_count - Get number of memory regions
 */
int fdt_memory_count(void)
{
    return num_mem_regions;
}

/**
 * fdt_get_reserved - Get reserved region by index
 */
int fdt_get_reserved(int index, paddr_t *base, size_t *size)
{
    if (index < 0 || index >= num_reserved_regions) {
        return -1;
    }
    *base = reserved_regions[index].base;
    *size = reserved_regions[index].size;
    return 0;
}

int fdt_reserved_count(void)
{
    return num_reserved_regions;
}