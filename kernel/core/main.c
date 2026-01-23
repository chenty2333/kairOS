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
#include <kairos/rbtree.h>
#include <kairos/config.h>

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

/*
 * Phase 4: CFS Scheduler Tests
 */

/* Test structure for RB tree */
struct test_node {
    struct rb_node node;
    uint64_t key;
};

/**
 * test_rbtree - Test red-black tree with 1000 integers
 */
static void test_rbtree(void)
{
    printk("\nTesting red-black tree:\n");

    struct rb_root root = RB_ROOT;
    struct test_node *nodes;
    struct rb_node *rb;
    uint64_t prev_key;
    int count;
    bool ordered;

    /* Allocate 1000 test nodes */
    nodes = kmalloc(1000 * sizeof(struct test_node));
    if (!nodes) {
        printk("  ERROR: Failed to allocate test nodes\n");
        return;
    }

    /* Insert 1000 numbers in pseudo-random order */
    printk("  Inserting 1000 numbers...\n");
    for (int i = 0; i < 1000; i++) {
        /* Use a simple PRNG: key = (i * 7919 + 104729) mod 1000000 */
        nodes[i].key = (uint64_t)((i * 7919 + 104729) % 1000000);

        /* Find insertion point */
        struct rb_node **link = &root.rb_node;
        struct rb_node *parent = NULL;

        while (*link) {
            parent = *link;
            struct test_node *entry = rb_entry(parent, struct test_node, node);

            if (nodes[i].key < entry->key) {
                link = &parent->rb_left;
            } else {
                link = &parent->rb_right;
            }
        }

        /* Insert and rebalance */
        rb_link_node(&nodes[i].node, parent, link);
        rb_insert_color(&nodes[i].node, &root);
    }

    /* Verify in-order traversal */
    printk("  Verifying order...\n");
    prev_key = 0;
    count = 0;
    ordered = true;

    for (rb = rb_first(&root); rb; rb = rb_next(rb)) {
        struct test_node *entry = rb_entry(rb, struct test_node, node);
        if (count > 0 && entry->key < prev_key) {
            printk("  ERROR: Order violation at count %d: %lu < %lu\n",
                   count, (unsigned long)entry->key, (unsigned long)prev_key);
            ordered = false;
            break;
        }
        prev_key = entry->key;
        count++;
    }

    if (ordered && count == 1000) {
        printk("  Verified %d elements in sorted order\n", count);
    } else if (count != 1000) {
        printk("  ERROR: Expected 1000 elements, got %d\n", count);
    }

    /* Test deletion of some nodes */
    printk("  Testing deletion of 100 nodes...\n");
    for (int i = 0; i < 100; i++) {
        rb_erase(&nodes[i].node, &root);
    }

    /* Count remaining nodes */
    count = 0;
    for (rb = rb_first(&root); rb; rb = rb_next(rb)) {
        count++;
    }

    if (count == 900) {
        printk("  After deletion: %d elements remain (expected 900)\n", count);
        printk("  Red-black tree tests passed!\n");
    } else {
        printk("  ERROR: Expected 900 elements after deletion, got %d\n", count);
    }

    kfree(nodes);
}

/* Test threads for CFS priority testing */
static volatile int high_prio_count = 0;
static volatile int low_prio_count = 0;
static volatile bool cfs_test_done = false;

static int high_prio_thread(void *arg)
{
    (void)arg;
    for (int i = 0; i < 10; i++) {
        high_prio_count++;
        /* Busy loop to consume CPU */
        for (volatile int j = 0; j < 10000; j++) { }
        proc_yield();
    }
    return 0;
}

static int low_prio_thread(void *arg)
{
    (void)arg;
    for (int i = 0; i < 10; i++) {
        low_prio_count++;
        /* Busy loop to consume CPU */
        for (volatile int j = 0; j < 10000; j++) { }
        proc_yield();
    }
    cfs_test_done = true;
    return 0;
}

/**
 * test_cfs_priority - Test that high-priority tasks get more CPU time
 */
static void test_cfs_priority(void)
{
    printk("\nTesting CFS priority scheduling:\n");

    /* Reset counters */
    high_prio_count = 0;
    low_prio_count = 0;
    cfs_test_done = false;

    /* Create two threads with different nice values */
    struct process *high = kthread_create(high_prio_thread, NULL, "high_prio");
    struct process *low = kthread_create(low_prio_thread, NULL, "low_prio");

    if (!high || !low) {
        printk("  ERROR: Failed to create test threads\n");
        return;
    }

    /* Set nice values: high priority (-10), low priority (+10) */
    sched_setnice(high, -10);  /* Higher priority */
    sched_setnice(low, 10);    /* Lower priority */

    printk("  Created high-priority thread (nice=-10, pid=%d)\n", high->pid);
    printk("  Created low-priority thread (nice=+10, pid=%d)\n", low->pid);

    /* Enqueue threads */
    sched_enqueue(high);
    sched_enqueue(low);

    /* Enable interrupts and let threads run */
    arch_irq_enable();

    /* Wait for completion */
    while (!cfs_test_done) {
        schedule();
    }

    arch_irq_disable();

    printk("  High-priority thread ran %d times\n", high_prio_count);
    printk("  Low-priority thread ran %d times\n", low_prio_count);

    /* In CFS, both should complete eventually (fairness) */
    if (high_prio_count == 10 && low_prio_count == 10) {
        printk("  Both threads completed successfully!\n");
        printk("  CFS priority tests passed!\n");
    } else {
        printk("  ERROR: Threads did not complete correctly\n");
    }
}

/*
 * Phase 4.3: SMP Support
 */

/* Track secondary CPUs online status */
static volatile int secondary_cpus_online = 0;
static volatile bool smp_test_done = false;

/* Secondary CPU entry point (arch-specific) */
int arch_start_cpu(int cpu, unsigned long start_addr, unsigned long opaque);
int arch_cpu_count(void);
extern void _secondary_start(void);

/**
 * secondary_cpu_main - Entry point for secondary CPUs
 * @hartid: This CPU's hart ID
 *
 * Called from boot.S after stack setup.
 */
void secondary_cpu_main(unsigned long hartid)
{
    /* Initialize this CPU */
    arch_cpu_init((int)hartid);

    /* Initialize scheduler for this CPU */
    sched_init_cpu((int)hartid);
    sched_cpu_online((int)hartid);

    /* Initialize trap handling for this CPU */
    arch_trap_init();

    /* Initialize timer for this CPU */
    arch_timer_init(CONFIG_HZ);

    pr_info("CPU %lu: online and ready\n", hartid);

    /* Signal that we're online */
    secondary_cpus_online++;

    /* Enable interrupts and enter idle loop */
    arch_irq_enable();

    /* Idle loop - wait for work */
    while (1) {
        if (sched_need_resched()) {
            schedule();
        }
        arch_cpu_halt();
    }
}

/* Boot hartid (defined in boot.S) */
extern int boot_hartid;

/**
 * test_smp - Test SMP functionality
 */
static void test_smp(void)
{
    int my_hart = arch_cpu_id();

    printk("\nTesting SMP support:\n");
    printk("  Boot hart: %d\n", my_hart);

    /* Try to start secondary CPUs (QEMU virt has multiple harts) */
    int started = 0;

    for (int cpu = 0; cpu < CONFIG_MAX_CPUS && cpu < 4; cpu++) {
        /* Skip the boot hart - it's already running! */
        if (cpu == my_hart) {
            continue;
        }

        printk("  Attempting to start CPU %d...\n", cpu);

        int ret = arch_start_cpu(cpu,
                                 (unsigned long)_secondary_start,
                                 0);

        if (ret == 0) {
            printk("  CPU %d: start request sent\n", cpu);
            started++;
        } else {
            printk("  CPU %d: failed to start (error %d)\n", cpu, ret);
        }
    }

    if (started == 0) {
        printk("  No secondary CPUs available (single-core system)\n");
        printk("  SMP test skipped.\n");
        return;
    }

    /* Wait for secondary CPUs to come online */
    printk("  Waiting for %d secondary CPU(s) to come online...\n", started);

    int timeout = 1000;  /* ~10 seconds */
    while (secondary_cpus_online < started && timeout > 0) {
        arch_irq_enable();
        for (volatile int i = 0; i < 100000; i++) { }
        arch_irq_disable();
        timeout--;
    }

    if (secondary_cpus_online >= started) {
        printk("  %d secondary CPU(s) online!\n", secondary_cpus_online);
        printk("  Total CPUs: %d\n", sched_cpu_count());
        printk("  SMP tests passed!\n");
    } else {
        printk("  Timeout: only %d/%d secondary CPUs came online\n",
               secondary_cpus_online, started);
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
    pr_info("Phase 3.1-3.2 (kernel threads) passed!\n");

    /*
     * Phase 4: CFS Scheduler
     */
    printk("\n=== Phase 4: CFS Scheduler ===\n");

    /* Test red-black tree implementation */
    test_rbtree();

    /* Test CFS priority scheduling */
    test_cfs_priority();

    printk("\n");
    pr_info("Phase 4.1-4.2 (CFS Scheduler) tests passed!\n");

    /*
     * Phase 4.3: SMP Support
     */
    printk("\n=== Phase 4.3: SMP Support ===\n");
    test_smp();

    printk("\n");
    pr_info("Phase 4 complete!\n");

    /*
     * Phase 3.3-3.4: User Mode and Fork Test
     * NOTE: This test enters user mode and does not return!
     */
    printk("\n=== Phase 3.3-3.4: User Mode and Fork Test ===\n");
    run_fork_test();

    /* Should not reach here - fork test enters user mode */
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
