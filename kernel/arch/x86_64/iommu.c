/**
 * kernel/arch/x86_64/iommu.c - x86_64 IOMMU arch hook
 */

#include <kairos/boot.h>
#include <kairos/types.h>

__attribute__((weak)) int arch_x86_64_iommu_native_init(void) {
    return -ENODEV;
}

int arch_iommu_init(void) {
    int ret = arch_x86_64_iommu_native_init();
    if (ret != -ENODEV)
        return ret;

    const struct boot_info *bi = boot_info_get();
    if (bi && bi->rsdp)
        return -ENOTSUP;
    return -ENODEV;
}
