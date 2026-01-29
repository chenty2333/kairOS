/**
 * kernel/arch/common/arch_common.c - Shared architecture helpers
 */

#include "arch_common.h"

#include <boot/limine.h>
#include <kairos/arch.h>
#include <kairos/boot.h>

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
        return -ENODEV;
    }

    info->extra_argument = opaque;
    info->goto_address = (limine_goto_address)start_addr;
    return 0;
}

#ifndef ARCH_riscv64
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
#endif
