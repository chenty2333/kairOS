/**
 * main.c - Kernel main entry point
 */

#include <kairos/arch.h>
#include <kairos/blkdev.h>
#include <kairos/buf.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/rbtree.h>
#include <kairos/sched.h>
#include <kairos/syscall.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

/* FDT functions */
int fdt_parse(void *fdt);
int fdt_get_memory(int index, paddr_t *base, size_t *size);
int fdt_memory_count(void);

/* File system initialization functions */
void devfs_init(void);
void ext2_init(void);
void virtio_blk_probe(void);

/* Timer tick counter (defined in timer.c) */
extern volatile uint64_t system_ticks;

/* Kernel version */
#define KAIROS_VERSION_MAJOR 0
#define KAIROS_VERSION_MINOR 1
#define KAIROS_VERSION_PATCH 0

/* External symbols from linker script */
extern char _kernel_start[];
extern char _kernel_end[];
extern char _bss_start[];
extern char _bss_end[];

/**
 * test_syscall - Test system call mechanism
 *
 * Note: This test runs before proc_init(), so proc_current() returns NULL
 * and sys_getpid() returns 0. We test the dispatch mechanism here, not
 * the process-dependent syscalls.
 */
static void test_syscall(void) {
    int64_t ret;

    /* Test invalid syscall - should return -ENOSYS */
    ret = syscall_dispatch(999, 0, 0, 0, 0, 0, 0);
    if (ret != -ENOSYS) {
        pr_err("Syscall: invalid syscall FAILED\n");
        return;
    }

    pr_info("Syscall dispatch: passed\n");
}

/**
 * test_timer - Test timer interrupts (quick version)
 */
static void test_timer(void) {
    /* Enable interrupts */
    arch_irq_enable();

    /* Wait for a few ticks to verify timer is working */
    uint64_t start_ticks = system_ticks;
    while (system_ticks < start_ticks + 10) {
        arch_cpu_halt();
    }

    arch_irq_disable();
    pr_info("Timer: %lu ticks received\n", system_ticks - start_ticks);
}

/**
 * test_breakpoint - Test breakpoint exception
 */
static void test_breakpoint(void) {
    __asm__ __volatile__("ebreak");
    pr_info("Breakpoint exception: passed\n");
}

/**
 * Test kernel thread A
 */
static volatile int thread_a_count = 0;
static volatile int thread_b_count = 0;
static volatile bool threads_done = false;

static int test_thread_a(void *arg) {
    (void)arg;
    for (int i = 0; i < 5; i++) {
        thread_a_count++;
        proc_yield();
    }
    return 0;
}

/**
 * Test kernel thread B
 */
static int test_thread_b(void *arg) {
    (void)arg;
    for (int i = 0; i < 5; i++) {
        thread_b_count++;
        proc_yield();
    }
    threads_done = true;
    return 0;
}

/**
 * test_kthreads - Test kernel thread creation and scheduling
 */
static void test_kthreads(void) {
    struct process *p1 = kthread_create(test_thread_a, NULL, "test_a");
    struct process *p2 = kthread_create(test_thread_b, NULL, "test_b");

    if (!p1 || !p2) {
        pr_err("Failed to create kernel threads\n");
        return;
    }

    sched_enqueue(p1);
    sched_enqueue(p2);

    arch_irq_enable();
    while (!threads_done) {
        schedule();
    }
    arch_irq_disable();

    if (thread_a_count == 5 && thread_b_count == 5) {
        pr_info("Kernel threads: passed\n");
    } else {
        pr_err("Kernel threads: FAILED (A=%d, B=%d)\n", thread_a_count,
               thread_b_count);
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
static void test_rbtree(void) {
    struct rb_root root = RB_ROOT;
    struct test_node *nodes;
    struct rb_node *rb;
    uint64_t prev_key;
    int count;
    bool ordered;

    nodes = kmalloc(1000 * sizeof(struct test_node));
    if (!nodes) {
        pr_err("RB-tree: failed to allocate\n");
        return;
    }

    /* Insert 1000 numbers in pseudo-random order */
    for (int i = 0; i < 1000; i++) {
        nodes[i].key = (uint64_t)((i * 7919 + 104729) % 1000000);

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

        rb_link_node(&nodes[i].node, parent, link);
        rb_insert_color(&nodes[i].node, &root);
    }

    /* Verify in-order traversal */
    prev_key = 0;
    count = 0;
    ordered = true;

    for (rb = rb_first(&root); rb; rb = rb_next(rb)) {
        struct test_node *entry = rb_entry(rb, struct test_node, node);
        if (count > 0 && entry->key < prev_key) {
            ordered = false;
            break;
        }
        prev_key = entry->key;
        count++;
    }

    /* Test deletion */
    for (int i = 0; i < 100; i++) {
        rb_erase(&nodes[i].node, &root);
    }

    count = 0;
    for (rb = rb_first(&root); rb; rb = rb_next(rb)) {
        count++;
    }

    if (ordered && count == 900) {
        pr_info("RB-tree: passed\n");
    } else {
        pr_err("RB-tree: FAILED\n");
    }

    kfree(nodes);
}

/* Test threads for CFS priority testing */
static volatile int high_prio_count = 0;
static volatile int low_prio_count = 0;
static volatile bool cfs_test_done = false;

static int high_prio_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 10; i++) {
        high_prio_count++;
        /* Busy loop to consume CPU */
        for (volatile int j = 0; j < 10000; j++) {
        }
        proc_yield();
    }
    return 0;
}

static int low_prio_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 10; i++) {
        low_prio_count++;
        /* Busy loop to consume CPU */
        for (volatile int j = 0; j < 10000; j++) {
        }
        proc_yield();
    }
    cfs_test_done = true;
    return 0;
}

/**
 * test_cfs_priority - Test that high-priority tasks get more CPU time
 */
static void test_cfs_priority(void) {
    high_prio_count = 0;
    low_prio_count = 0;
    cfs_test_done = false;

    struct process *high = kthread_create(high_prio_thread, NULL, "high_prio");
    struct process *low = kthread_create(low_prio_thread, NULL, "low_prio");

    if (!high || !low) {
        pr_err("CFS: failed to create threads\n");
        return;
    }

    sched_setnice(high, -10);
    sched_setnice(low, 10);

    sched_enqueue(high);
    sched_enqueue(low);

    arch_irq_enable();
    while (!cfs_test_done) {
        schedule();
    }
    arch_irq_disable();

    if (high_prio_count == 10 && low_prio_count == 10) {
        pr_info("CFS scheduler: passed\n");
    } else {
        pr_err("CFS scheduler: FAILED\n");
    }
}

/*
 * Phase 4.3: SMP Support
 */

/* Track secondary CPUs online status */
static volatile int secondary_cpus_online = 0;

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
void secondary_cpu_main(unsigned long hartid) {
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
static void test_smp(void) {
    int my_hart = arch_cpu_id();
    int started = 0;

    for (int cpu = 0; cpu < CONFIG_MAX_CPUS && cpu < 4; cpu++) {
        if (cpu == my_hart) {
            continue;
        }

        int ret = arch_start_cpu(cpu, (unsigned long)_secondary_start, 0);
        if (ret == 0) {
            started++;
        }
    }

    if (started == 0) {
        pr_info("SMP: single-core system\n");
        return;
    }

    /* Wait for secondary CPUs to come online */
    int timeout = 1000;
    while (secondary_cpus_online < started && timeout > 0) {
        arch_irq_enable();
        for (volatile int i = 0; i < 100000; i++) {
        }
        arch_irq_disable();
        timeout--;
    }

    if (secondary_cpus_online >= started) {
        pr_info("SMP: %d CPUs online\n", sched_cpu_count());
    } else {
        pr_warn("SMP: only %d/%d CPUs online\n", secondary_cpus_online,
                started);
    }
}

/**
 * kernel_main - Main kernel entry point
 * @hartid: Hardware thread ID (CPU ID)
 * @dtb: Pointer to device tree blob
 *
 * Called from boot.S after basic setup is complete.
 */
void kernel_main(unsigned long hartid, void *dtb) {
    (void)hartid;
    (void)dtb;

    /* Print boot banner */
    printk("\n");
    printk("===========================================\n");
    printk("  Kairos Kernel v%d.%d.%d\n", KAIROS_VERSION_MAJOR,
           KAIROS_VERSION_MINOR, KAIROS_VERSION_PATCH);
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
    printk("Memory: base=%p, size=%lu MB\n", (void *)mem_base, mem_size >> 20);

    /*
     * Phase 1: Memory Management
     */
    printk("\n=== Phase 1: Memory Management ===\n");

    paddr_t pmm_start = (paddr_t)_kernel_end;
    paddr_t pmm_end = mem_base + mem_size;
    pmm_init(pmm_start, pmm_end);
    kmalloc_init();
    arch_mmu_init(mem_base, mem_size);
    vmm_init();

    printk("Phase 1 complete!\n");

    /*
     * Phase 2: Trap Handling
     */
    syscall_init();
    arch_trap_init();
    arch_timer_init(100); /* 100 Hz */

    test_breakpoint();
    test_syscall();
    test_timer();

    /*
     * Phase 3: Process Management
     */
    sched_init();
    proc_init();
    proc_idle_init();

    test_kthreads();

    /*
     * Phase 4: CFS Scheduler & SMP
     */
    test_rbtree();
    test_cfs_priority();
    test_smp();

    /*
     * Phase 5: File System
     */
    binit();
    vfs_init();
    devfs_init();
    ext2_init();
    virtio_blk_probe();

    int ret = vfs_mount(NULL, "/dev", "devfs", 0);
    if (ret < 0) {
        pr_warn("devfs mount failed: %d\n", ret);
    }

    ret = vfs_mount("vda", "/", "ext2", 0);
    if (ret < 0) {
        pr_info("ext2 root: not available (error %d)\n", ret);
    } else {
        pr_info("ext2 root: mounted\n");
    }

    /*
     * User Mode and Fork Test
     * NOTE: This test enters user mode and does not return!
     */
    pr_info("Starting fork test...\n");
    run_fork_test();

    /* Should not reach here - fork test enters user mode */
    printk("\n");

    /* Print final statistics */
    printk("Final statistics:\n");
    printk("  Total timer ticks: %lu\n", system_ticks);
    printk("  Free pages: %lu (%lu MB)\n", pmm_num_free_pages(),
           (pmm_num_free_pages() * 4096) >> 20);

    /* Halt for now */
    printk("\nHalting...\n");
    while (1) {
        arch_cpu_halt();
    }
}
