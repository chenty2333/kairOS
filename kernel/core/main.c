/**
 * main.c - Kernel main entry point
 */

#include <kairos/types.h>
#include <kairos/printk.h>
#include <kairos/arch.h>
#include <kairos/mm.h>
#include <kairos/syscall.h>
#include <kairos/process.h>
#include <kairos/sched.h>

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
 * Test kernel thread A
 */
static volatile int thread_a_count = 0;
static volatile int thread_b_count = 0;
static volatile bool threads_done = false;

static int test_thread_a(void *arg)
{
    (void)arg;
    for (int i = 0; i < 5; i++) {
        printk("  Thread A: iteration %d\n", i);
        thread_a_count++;
        proc_yield();
    }
    printk("  Thread A: done\n");
    return 0;
}

/**
 * Test kernel thread B
 */
static int test_thread_b(void *arg)
{
    (void)arg;
    for (int i = 0; i < 5; i++) {
        printk("  Thread B: iteration %d\n", i);
        thread_b_count++;
        proc_yield();
    }
    printk("  Thread B: done\n");
    threads_done = true;
    return 0;
}

/**
 * test_kthreads - Test kernel thread creation and scheduling
 */
static void test_kthreads(void)
{
    printk("\nTesting kernel threads:\n");

    /* Create two kernel threads */
    struct process *p1 = kthread_create(test_thread_a, NULL, "test_a");
    struct process *p2 = kthread_create(test_thread_b, NULL, "test_b");

    if (!p1 || !p2) {
        printk("  ERROR: Failed to create kernel threads\n");
        return;
    }

    printk("  Created thread A (pid %d) and thread B (pid %d)\n",
           p1->pid, p2->pid);

    /* Add threads to run queue */
    sched_enqueue(p1);
    sched_enqueue(p2);

    /* Enable interrupts and let threads run */
    arch_irq_enable();

    /* Wait for threads to complete */
    while (!threads_done) {
        schedule();
    }

    arch_irq_disable();

    printk("  Thread A ran %d times, Thread B ran %d times\n",
           thread_a_count, thread_b_count);

    if (thread_a_count == 5 && thread_b_count == 5) {
        printk("  Kernel thread tests passed!\n");
    } else {
        printk("  ERROR: Thread counts incorrect!\n");
    }
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

    /*
     * Phase 3: Process Management
     */
    printk("\n=== Phase 3: Process Management ===\n");

    /* Initialize scheduler */
    sched_init();

    /* Initialize process subsystem */
    proc_init();

    /* Create idle process (pid 0) */
    proc_idle_init();

    printk("Phase 3 initialization complete!\n");

    /*
     * Run Phase 3 tests
     */
    test_kthreads();

    printk("\n");
    pr_info("All Phase 3 tests passed!\n");
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
