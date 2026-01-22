/**
 * main.c - Kernel main entry point
 */

#include <kairos/types.h>
#include <kairos/printk.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/syscall.h>

/* FDT functions */
int fdt_parse(void *fdt);
int fdt_get_memory(int index, paddr_t *base, size_t *size);
int fdt_memory_count(void);

/* Timer tick counter (defined in timer.c) */
extern volatile uint64_t system_ticks;

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
 * test_syscall - Test system call mechanism
 *
 * Note: ecall from S-mode goes to OpenSBI (M-mode), not our trap handler.
 * Real syscalls will come from U-mode in later phases.
 * For now, we test by calling syscall_dispatch directly.
 */
static void test_syscall(void)
{
    printk("\nTesting syscalls (direct dispatch):\n");

    /* Test SYS_write by direct call */
    const char *msg = "  Hello from syscall!\n";
    int64_t ret = syscall_dispatch(SYS_write, 1, (uint64_t)msg, 22, 0, 0, 0);
    printk("  sys_write returned: %ld\n", (long)ret);

    /* Test SYS_getpid */
    ret = syscall_dispatch(SYS_getpid, 0, 0, 0, 0, 0, 0);
    printk("  sys_getpid returned: %ld (expected 1)\n", (long)ret);

    /* Test SYS_yield */
    ret = syscall_dispatch(SYS_yield, 0, 0, 0, 0, 0, 0);
    printk("  sys_yield returned: %ld (expected 0)\n", (long)ret);

    /* Test invalid syscall */
    ret = syscall_dispatch(999, 0, 0, 0, 0, 0, 0);
    printk("  invalid syscall returned: %ld (expected -38 ENOSYS)\n", (long)ret);

    printk("  Syscall tests passed!\n");
}

/**
 * test_timer - Test timer interrupts
 */
static void test_timer(void)
{
    printk("\nTesting timer interrupts:\n");
    printk("  Waiting for 3 seconds of timer ticks...\n");

    /* Enable interrupts */
    arch_irq_enable();

    /* Wait for ~3 seconds worth of ticks (at 100 Hz) */
    uint64_t start_ticks = system_ticks;
    while (system_ticks < start_ticks + 300) {
        arch_cpu_halt();  /* Wait for interrupt */
    }

    /* Disable interrupts */
    arch_irq_disable();

    printk("  Received %lu ticks (expected ~300)\n",
           system_ticks - start_ticks);
    printk("  Timer tests passed!\n");
}

/**
 * test_breakpoint - Test breakpoint exception
 */
static void test_breakpoint(void)
{
    printk("\nTesting breakpoint exception:\n");
    printk("  Triggering ebreak...\n");

    __asm__ __volatile__("ebreak");

    printk("  Breakpoint handled correctly!\n");
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
     * Phase 1: Memory Management
     */
    printk("\n=== Phase 1: Memory Management ===\n");

    paddr_t pmm_start = (paddr_t)_kernel_end;
    paddr_t pmm_end = mem_base + mem_size;
    pmm_init(pmm_start, pmm_end);
    kmalloc_init();
    arch_mmu_init();
    vmm_init();

    printk("Phase 1 complete!\n");

    /*
     * Phase 2: Trap Handling
     */
    printk("\n=== Phase 2: Trap Handling ===\n");

    /* Initialize syscall table */
    syscall_init();

    /* Initialize trap handling */
    arch_trap_init();

    /* Initialize timer */
    arch_timer_init(100);  /* 100 Hz */

    printk("Phase 2 initialization complete!\n");

    /*
     * Run Phase 2 tests
     */
    test_breakpoint();
    test_syscall();
    test_timer();

    printk("\n");
    pr_info("All Phase 2 tests passed!\n");
    printk("\n");

    /* Print final statistics */
    printk("Final statistics:\n");
    printk("  Total timer ticks: %lu\n", system_ticks);
    printk("  Free pages: %lu (%lu MB)\n",
           pmm_num_free_pages(),
           (pmm_num_free_pages() * 4096) >> 20);

    /* Halt for now */
    printk("\nHalting...\n");
    while (1) {
        arch_cpu_halt();
    }
}
