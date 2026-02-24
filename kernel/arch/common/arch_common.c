/**
 * kernel/arch/common/arch_common.c - Shared architecture helpers
 */

#include "arch_common.h"

#include <boot/limine.h>
#include <kairos/arch.h>
#include <kairos/boot.h>

__attribute__((weak))
int arch_start_cpu_fallback(int cpu, unsigned long start_addr,
                            unsigned long opaque,
                            const struct boot_info *bi) {
    (void)cpu;
    (void)start_addr;
    (void)opaque;
    (void)bi;
    return -ENODEV;
}

__attribute__((weak))
uint64_t arch_cpu_start_debug(int cpu) {
    (void)cpu;
    return 0;
}

int arch_cpu_count(void) {
    const struct boot_info *bi = boot_info_get();
    if (bi && bi->cpu_count) {
        return (int)bi->cpu_count;
    }
    return 1;
}

int arch_start_cpu(int cpu, unsigned long start_addr, unsigned long opaque) {
    const struct boot_info *bi = boot_info_get();
    if (!bi || cpu >= (int)bi->cpu_count) {
        return -EINVAL;
    }

    struct limine_mp_info *info = (struct limine_mp_info *)bi->cpus[cpu].mp_info;
    if (!info) {
        return arch_start_cpu_fallback(cpu, start_addr, opaque, bi);
    }

    info->extra_argument = opaque;
    info->goto_address = (limine_goto_address)start_addr;
    return 0;
}

__attribute__((weak))
void arch_send_ipi_all(int type) {
    int self = arch_cpu_id();
    int count = arch_cpu_count();

    for (int i = 0; i < count; i++) {
        if (i == self) {
            continue;
        }
        arch_send_ipi(i, type);
    }
}
