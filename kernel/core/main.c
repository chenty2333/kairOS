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
#include <kairos/fdt.h>
#include <kairos/device.h>
#include <kairos/firmware.h>
#include <kairos/futex.h>
#include <kairos/net.h>
#include <kairos/acpi.h>
#include <kairos/pci.h>
#include <kairos/platform.h>
#include <kairos/virtio.h>

/* Drivers */
extern struct driver virtio_mmio_driver;
extern struct virtio_driver virtio_blk_driver;
extern struct virtio_driver virtio_net_driver;

/* File system initialization functions */
void devfs_init(void);
void ext2_init(void);

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

/* Secondary CPU handling */
static volatile int secondary_cpus_online = 0;
int arch_start_cpu(int cpu, unsigned long start_addr, unsigned long opaque);
extern void _secondary_start(void);

void secondary_cpu_main(unsigned long hartid) {
    arch_cpu_init((int)hartid);
    sched_init_cpu((int)hartid);
    sched_cpu_online((int)hartid);
    arch_trap_init();
    arch_timer_init(CONFIG_HZ);
    proc_idle_init();
    __sync_fetch_and_add(&secondary_cpus_online, 1);
    pr_info("CPU %lu: online and ready\n", hartid);
    arch_irq_enable();
    while (1) schedule();
}

static void smp_init(void) {
    int started = 0, my_hart = (int)arch_cpu_id();
    pr_info("SMP: Booting secondary CPUs...\n");
    for (int cpu = 0; cpu < CONFIG_MAX_CPUS; cpu++) {
        if (cpu == my_hart) continue;
        if (arch_start_cpu(cpu, (unsigned long)_secondary_start, 0) == 0) started++;
    }
    if (started == 0) return;
    int timeout = 1000000;
    while (secondary_cpus_online < started && timeout-- > 0) arch_cpu_relax();
    pr_info("SMP: %d CPUs active\n", started + 1);
}

/**
 * kernel_main - Main kernel entry point
 */
void kernel_main(unsigned long hartid, void *dtb) {
    (void)hartid;

    printk("\n===========================================\n");
    printk("  Kairos Kernel v%d.%d.%d\n", KAIROS_VERSION_MAJOR, KAIROS_VERSION_MINOR, KAIROS_VERSION_PATCH);
    printk("  Modern Device Model & FDT Support\n");
    printk("===========================================\n\n");

    /* Core Initialization */
    if (fdt_parse(dtb) < 0) panic("Failed to parse DTB");
    
    paddr_t mem_base; size_t mem_size;
    fdt_get_memory(0, &mem_base, &mem_size);
    
    pmm_init((paddr_t)_kernel_end, mem_base + mem_size);
    kmalloc_init();
    arch_mmu_init(mem_base, mem_size);
    vmm_init();

    syscall_init();
    arch_trap_init();
    arch_timer_init(100);

    sched_init();
    proc_init();
    futex_init();
    net_init();
    proc_idle_init();

    /* Device Model and Driver Initialization */
    printk("\n=== Phase 5: Device Discovery ===\n");
    platform_bus_init();
    pci_bus_init();
    bus_register(&virtio_bus_type);
    
    driver_register(&virtio_mmio_driver);
    virtio_register_driver(&virtio_blk_driver);
    virtio_register_driver(&virtio_net_driver);
    
    fw_init();
    acpi_init();
    fdt_scan_devices(dtb);
    platform_bus_enumerate();
    pci_enumerate();

    /* File System Initialization */
    binit();
    vfs_init();
    devfs_init();
    ext2_init();

    int ret = vfs_mount("vda", "/", "ext2", 0);
    if (ret == 0) {
        pr_info("ext2 root: mounted\n");
        int mkret = vfs_mkdir("/dev", 0755);
        if (mkret < 0 && mkret != -EEXIST)
            pr_warn("devfs: failed to create /dev (ret=%d)\n", mkret);
        ret = vfs_mount(NULL, "/dev", "devfs", 0);
        if (ret < 0)
            pr_warn("devfs: mount failed (ret=%d)\n", ret);
    } else {
        pr_warn("ext2 root: mount failed (ret=%d)\n", ret);
    }

    smp_init();

    /* Tests and User Mode */
#if CONFIG_KERNEL_TESTS
    pr_info("Starting robustness test...\n");
    run_crash_test();

    arch_irq_enable();
    int status;
    while (proc_wait(-1, &status, 0) > 0)
        ;

    pr_info("Tests complete. Stopping system...\n");
    arch_cpu_shutdown();
    while (1) arch_cpu_halt();
#else
    struct process *initp = proc_start_init();
    if (!initp) {
        pr_warn("init: failed to start init thread\n");
    }
    arch_irq_enable();
    /* No test harness: keep the scheduler running. */
    while (1) {
        schedule();
    }
#endif
}
