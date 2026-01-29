/**
 * main.c - Kernel main entry point
 */

#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/config.h>
#include <kairos/futex.h>
#include <kairos/init.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/syscall.h>

/* Timer tick counter (defined in timer.c) */
extern volatile uint64_t system_ticks;

/* External symbols from linker script */
extern char _kernel_start[];
extern char _kernel_end[];
extern char _bss_start[];
extern char _bss_end[];

/* Secondary CPU handling */
static volatile int secondary_cpus_online = 0;
int arch_start_cpu(int cpu, unsigned long start_addr, unsigned long opaque);
extern void _secondary_start(void);

void secondary_cpu_main(unsigned long cpu_id) {
    arch_cpu_init((int)cpu_id);
    sched_init_cpu((int)cpu_id);
    sched_cpu_online((int)cpu_id);
    arch_trap_init();
    arch_timer_init(CONFIG_HZ);
    proc_idle_init();
    __sync_fetch_and_add(&secondary_cpus_online, 1);
    pr_info("CPU %lu: online and ready\n", cpu_id);
    arch_irq_enable();
    while (1) {
        schedule();
    }
}

static void smp_init(void) {
    int started = 0, my_hart = (int)arch_cpu_id();
    pr_info("SMP: Booting secondary CPUs...\n");
    for (int cpu = 0; cpu < CONFIG_MAX_CPUS; cpu++) {
        if (cpu == my_hart) {
            continue;
        }
        if (arch_start_cpu(cpu, (unsigned long)_secondary_start,
                           (unsigned long)cpu) == 0)
            started++;
    }
    if (started == 0) {
        return;
    }
    int timeout = 1000000;
    while (secondary_cpus_online < started && timeout-- > 0) {
        arch_cpu_relax();
    }
    pr_info("SMP: %d CPUs active\n", started + 1);
}

/**
 * kernel_main - Main kernel entry point
 */
void kernel_main(const struct boot_info *bi) {
    init_boot(bi);
    init_mm(bi);

    syscall_init();
    arch_trap_init();
    arch_timer_init(100);

    sched_init();
    proc_init();
    futex_init();
    proc_idle_init();

    init_devices();
    init_net();
    init_fs();

    smp_init();
    init_user();
}
