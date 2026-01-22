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
 * test_buddy_allocator - Test buddy allocator functionality
 */
static void test_buddy_allocator(void)
{
    printk("\nTesting buddy allocator:\n");

    /* Test single page allocation */
    struct page *pages[10];
    for (int i = 0; i < 10; i++) {
        pages[i] = alloc_page();
        if (!pages[i]) {
            panic("Failed to allocate page %d", i);
        }
    }
    printk("  Allocated 10 single pages\n");
    printk("  Free pages: %lu\n", pmm_num_free_pages());

    /* Free them */
    for (int i = 0; i < 10; i++) {
        free_page(pages[i]);
    }
    printk("  After free: %lu pages\n", pmm_num_free_pages());

    /* Test order-2 allocation (4 pages) */
    struct page *block = alloc_pages(2);
    if (!block) {
        panic("Failed to allocate 4-page block");
    }
    paddr_t block_pa = page_to_phys(block);
    printk("  Allocated 4-page block at %p\n", (void *)block_pa);
    free_pages(block, 2);
    printk("  After free: %lu pages\n", pmm_num_free_pages());

    /* Test order-4 allocation (16 pages) */
    block = alloc_pages(4);
    if (!block) {
        panic("Failed to allocate 16-page block");
    }
    block_pa = page_to_phys(block);
    printk("  Allocated 16-page block at %p\n", (void *)block_pa);
    free_pages(block, 4);
    printk("  After free: %lu pages\n", pmm_num_free_pages());

    printk("  Buddy allocator tests passed!\n");
}

/**
 * test_kmalloc - Test kernel heap allocator
 */
static void test_kmalloc(void)
{
    printk("\nTesting kmalloc:\n");

    /* Small allocations */
    void *ptr1 = kmalloc(32);
    void *ptr2 = kmalloc(64);
    void *ptr3 = kmalloc(128);
    if (!ptr1 || !ptr2 || !ptr3) {
        panic("kmalloc failed for small allocation");
    }
    printk("  Allocated 32, 64, 128 bytes at %p, %p, %p\n", ptr1, ptr2, ptr3);

    /* Free them */
    kfree(ptr1);
    kfree(ptr2);
    kfree(ptr3);
    printk("  Freed small allocations\n");

    /* Larger allocation */
    void *big = kmalloc(4096);
    if (!big) {
        panic("kmalloc failed for 4KB allocation");
    }
    printk("  Allocated 4KB at %p\n", big);
    kfree(big);
    printk("  Freed 4KB allocation\n");

    /* Test kzalloc */
    uint8_t *zeroed = kzalloc(256);
    if (!zeroed) {
        panic("kzalloc failed");
    }
    bool all_zero = true;
    for (int i = 0; i < 256; i++) {
        if (zeroed[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (!all_zero) {
        panic("kzalloc did not zero memory");
    }
    printk("  kzalloc correctly zeroes memory\n");
    kfree(zeroed);

    printk("  kmalloc tests passed!\n");
}

/**
 * test_mmu - Test MMU functionality
 */
static void test_mmu(void)
{
    printk("\nTesting MMU:\n");

    paddr_t current = arch_mmu_current();
    printk("  Current page table: %p\n", (void *)current);

    /* Test translation of kernel address */
    paddr_t pa = arch_mmu_translate(current, (vaddr_t)_kernel_start);
    printk("  _kernel_start (%p) -> %p\n",
           (void *)_kernel_start, (void *)pa);

    /* Create a new page table */
    paddr_t new_table = arch_mmu_create_table();
    if (new_table == 0) {
        panic("Failed to create page table");
    }
    printk("  Created new page table at %p\n", (void *)new_table);

    /* Destroy it */
    arch_mmu_destroy_table(new_table);
    printk("  Destroyed page table\n");

    printk("  MMU tests passed!\n");
}

/**
 * test_vmm - Test virtual memory manager
 */
static void test_vmm(void)
{
    printk("\nTesting virtual memory manager:\n");

    /* Create an address space */
    struct mm_struct *mm = mm_create();
    if (!mm) {
        panic("Failed to create address space");
    }
    printk("  Created address space with pgdir at %p\n", (void *)mm->pgdir);

    /* Test mmap */
    vaddr_t mapped = mm_mmap(mm, 0, 4096, VM_READ | VM_WRITE, 0, NULL, 0);
    if (mapped == 0) {
        panic("mmap failed");
    }
    printk("  mmap'd anonymous page at %p\n", (void *)mapped);

    /* Test brk */
    vaddr_t new_brk = mm_brk(mm, mm->brk + 4096);
    printk("  brk extended to %p\n", (void *)new_brk);

    /* Destroy address space */
    mm_destroy(mm);
    printk("  Destroyed address space\n");

    printk("  VMM tests passed!\n");
}

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

    /*
     * Phase 1: Memory Management Initialization
     */
    printk("\n=== Phase 1: Memory Management ===\n");

    /* Initialize physical memory manager (buddy allocator) */
    paddr_t pmm_start = (paddr_t)_kernel_end;
    paddr_t pmm_end = mem_base + mem_size;
    pmm_init(pmm_start, pmm_end);

    /* Initialize kernel heap allocator */
    kmalloc_init();

    /* Initialize MMU and enable paging */
    arch_mmu_init();

    /* Initialize virtual memory manager */
    vmm_init();

    printk("\nPhase 1 initialization complete!\n");

    /*
     * Run tests
     */
    test_buddy_allocator();
    test_kmalloc();
    test_mmu();
    test_vmm();

    printk("\n");
    pr_info("All Phase 1 tests passed!\n");
    printk("\n");

    /* Print final memory statistics */
    printk("Final memory statistics:\n");
    printk("  Total pages: %lu (%lu MB)\n",
           pmm_total_pages(),
           (pmm_total_pages() * 4096) >> 20);
    printk("  Free pages:  %lu (%lu MB)\n",
           pmm_num_free_pages(),
           (pmm_num_free_pages() * 4096) >> 20);

    /* Halt for now - more initialization will come in later phases */
    printk("\nHalting...\n");
    while (1) {
        arch_cpu_halt();
    }
}
