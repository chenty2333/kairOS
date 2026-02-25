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
#include <kairos/string.h>
#include <kairos/syscall.h>
#include <kairos/tick.h>

/* External symbols from linker script */
extern char _kernel_start[];
extern char _kernel_end[];
extern char _bss_start[];
extern char _bss_end[];

/* Secondary CPU handling */
static volatile int secondary_cpus_online = 0;
static volatile uint8_t secondary_cpu_online_map[CONFIG_MAX_CPUS];
int arch_start_cpu(int cpu, unsigned long start_addr, unsigned long opaque);
uint64_t arch_cpu_start_debug(int cpu);
extern void _secondary_start(void);

void secondary_cpu_main(unsigned long cpu_id) {
    arch_cpu_init((int)cpu_id);
#if defined(ARCH_riscv64)
    /* APs may still enter with Limine's temporary page tables. */
    paddr_t kernel_pgdir = arch_mmu_get_kernel_pgdir();
    if (kernel_pgdir && arch_mmu_current() != kernel_pgdir)
        arch_mmu_switch(kernel_pgdir);
#elif defined(ARCH_x86_64)
    paddr_t kernel_pgdir = arch_mmu_get_kernel_pgdir();
    if (kernel_pgdir && arch_mmu_current() != kernel_pgdir)
        arch_mmu_switch(kernel_pgdir);
#endif
    sched_init_cpu((int)cpu_id);
    sched_cpu_online((int)cpu_id);
    arch_trap_init();
    arch_timer_init(CONFIG_HZ);
    proc_idle_init();
    if ((int)cpu_id >= 0 && (int)cpu_id < CONFIG_MAX_CPUS)
        secondary_cpu_online_map[cpu_id] = 1;
    __sync_fetch_and_add(&secondary_cpus_online, 1);
    pr_info("CPU %lu: online and ready\n", cpu_id);
    arch_irq_enable();
    while (1) {
        schedule();
    }
}

static void smp_init(void) {
    const struct boot_info *bi = boot_info_get();
    int cpu_count = bi ? (int)bi->cpu_count : 1;
    int bsp_cpu = bi ? (int)bi->bsp_cpu_id : (int)arch_cpu_id();
    int started = 0;
    int start_fail = 0;
    bool requested[CONFIG_MAX_CPUS];

    if (cpu_count < 1)
        cpu_count = 1;
    if (cpu_count > CONFIG_MAX_CPUS)
        cpu_count = CONFIG_MAX_CPUS;

    secondary_cpus_online = 0;
    memset((void *)secondary_cpu_online_map, 0, sizeof(secondary_cpu_online_map));
    memset(requested, 0, sizeof(requested));

    pr_info("SMP: Booting secondary CPUs (bsp=%d total=%d)...\n",
            bsp_cpu, cpu_count);

    for (int cpu = 0; cpu < cpu_count; cpu++) {
        if (cpu == bsp_cpu) {
            continue;
        }
        int rc = arch_start_cpu(cpu, (unsigned long)_secondary_start,
                                (unsigned long)cpu);
        if (rc == 0) {
            started++;
            requested[cpu] = true;
            pr_info("SMP: cpu%d start requested\n", cpu);
        } else {
            start_fail++;
            pr_warn("SMP: cpu%d start failed rc=%d\n", cpu, rc);
        }
    }

    if (started == 0) {
        pr_info("SMP: 1 CPU active\n");
        sched_set_steal_enabled(false);
        return;
    }

    uint64_t wait_ns = 2ULL * 1000 * 1000 * 1000;
#if defined(ARCH_aarch64)
    if (started > 1) {
        uint64_t extra = (uint64_t)(started - 1) * 500ULL * 1000 * 1000;
        wait_ns += extra;
        if (wait_ns > 6ULL * 1000 * 1000 * 1000)
            wait_ns = 6ULL * 1000 * 1000 * 1000;
    }
#endif
    uint64_t wait_ticks = arch_timer_ns_to_ticks(wait_ns);
    if (wait_ticks == 0)
        wait_ticks = CONFIG_HZ;
    uint64_t deadline = arch_timer_ticks() + wait_ticks;

    while (secondary_cpus_online < started &&
           arch_timer_ticks() < deadline) {
        arch_cpu_relax();
    }

    int online = secondary_cpus_online + 1;
    if (online < 1)
        online = 1;
    int expected = cpu_count;
    if (expected < 1)
        expected = 1;
    if (secondary_cpus_online < started) {
        for (int cpu = 0; cpu < cpu_count; cpu++) {
            if (cpu == bsp_cpu)
                continue;
            if (requested[cpu] && !secondary_cpu_online_map[cpu])
                pr_warn("SMP: cpu%d did not reach online state\n", cpu);
            uint64_t dbg = arch_cpu_start_debug(cpu);
            if (dbg)
                pr_warn("SMP: cpu%d start debug=0x%lx\n",
                        cpu, (unsigned long)dbg);
        }
    }
    if (start_fail > 0) {
        pr_warn("SMP: %d CPU start requests failed\n", start_fail);
    }
    if (online < expected) {
        pr_warn("SMP: online shortfall expected=%d online=%d\n",
                expected, online);
    }
    pr_info("SMP: %d/%d CPUs active\n", online, expected);
    sched_set_steal_enabled(online > 1);
}

/**
 * kernel_main - Main kernel entry point
 */
void kernel_main(const struct boot_info *bi) {
    init_boot(bi);
    init_mm(bi);

    syscall_init();
    arch_trap_init();
    tick_policy_init(arch_cpu_id());
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
