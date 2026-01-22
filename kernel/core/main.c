/**
 * main.c - Kernel main entry point
 */

#include <kairos/types.h>
#include <kairos/printk.h>
#include <kairos/arch.h>
#include <kairos/mm.h>

/* FDT functions */
int fdt_parse(void *fdt);
int fdt_get_memory(int index, paddr_t *base, size_t *size);
int fdt_memory_count(void);

/* Kernel version */
#define KAIROS_VERSION_MAJOR    0
#define KAIROS_VERSION_MINOR    1
#define KAIROS_VERSION_PATCH    0

/* External symbols from linker script */
extern char _kernel_start[];
extern char _kernel_end[];
extern char _bss_start[];
extern char _bss_end[];

/**
 * kernel_main - Main kernel entry point
 * @hartid: Hardware thread ID (CPU ID)
 * @dtb: Pointer to device tree blob
 *
 * Called from boot.S after basic setup is complete.
 */
void kernel_main(unsigned long hartid, void *dtb)
{
    (void)hartid;
    (void)dtb;

    /* Print boot banner */
    printk("\n");
    printk("===========================================\n");
    printk("  Kairos Kernel v%d.%d.%d\n",
           KAIROS_VERSION_MAJOR, KAIROS_VERSION_MINOR, KAIROS_VERSION_PATCH);
    printk("  A hobby operating system for RISC-V\n");
    printk("===========================================\n");
    printk("\n");

    /* Print boot info */
    printk("Boot CPU: hart %lu\n", hartid);
    printk("DTB location: %p\n", dtb);
    printk("\n");

    /* Print memory layout */
    printk("Memory layout:\n");
    printk("  Kernel start: %p\n", _kernel_start);
    printk("  Kernel end:   %p\n", _kernel_end);
    printk("  BSS start:    %p\n", _bss_start);
    printk("  BSS end:      %p\n", _bss_end);
    printk("  Kernel size:  %lu KB\n",
           ((unsigned long)_kernel_end - (unsigned long)_kernel_start) / 1024);
    printk("\n");

    /* Parse device tree */
    printk("Parsing device tree...\n");
    if (fdt_parse(dtb) < 0) {
        panic("Failed to parse DTB");
    }

    /* Find memory */
    paddr_t mem_base;
    size_t mem_size;
    if (fdt_get_memory(0, &mem_base, &mem_size) < 0) {
        panic("No memory found in DTB");
    }
    printk("Memory: base=%p, size=%lu MB\n",
           (void *)mem_base, mem_size >> 20);

    /* Initialize physical memory manager */
    /* Skip first 2MB (OpenSBI) and kernel */
    paddr_t pmm_start = (paddr_t)_kernel_end;
    paddr_t pmm_end = mem_base + mem_size;
    pmm_init(pmm_start, pmm_end);

    /* Test page allocation */
    printk("\nTesting page allocator:\n");

    /* Allocate some pages */
    paddr_t pages[10];
    for (int i = 0; i < 10; i++) {
        pages[i] = pmm_alloc_page();
        if (pages[i] == 0) {
            panic("Failed to allocate page %d", i);
        }
    }
    printk("  Allocated 10 pages: %p - %p\n",
           (void *)pages[0], (void *)pages[9]);
    printk("  Free pages: %lu\n", pmm_get_free_pages());

    /* Free them */
    for (int i = 0; i < 10; i++) {
        pmm_free_page(pages[i]);
    }
    printk("  After free: %lu pages\n", pmm_get_free_pages());

    /* Allocate contiguous pages */
    paddr_t contig = pmm_alloc_pages(16);
    if (contig == 0) {
        panic("Failed to allocate 16 contiguous pages");
    }
    printk("  Allocated 16 contiguous pages at %p\n", (void *)contig);
    pmm_free_pages(contig, 16);
    printk("  After free: %lu pages\n", pmm_get_free_pages());

    printk("\n");
    pr_info("Phase 0 complete! Memory management working.\n");
    printk("\n");

    /* Halt for now - more initialization will come in later phases */
    printk("Halting...\n");
    while (1) {
        arch_cpu_halt();
    }
}
