/**
 * kernel/arch/riscv64/iommu.c - riscv64 IOMMU arch hook
 */

#include <kairos/types.h>

__attribute__((weak)) int arch_riscv64_iommu_native_init(void) {
    return -ENODEV;
}

int arch_iommu_init(void) {
    return arch_riscv64_iommu_native_init();
}
