/**
 * kernel/arch/aarch64/iommu.c - aarch64 IOMMU arch hook
 */

#include <kairos/boot.h>
#include <kairos/types.h>

__attribute__((weak)) int arch_aarch64_iommu_native_init(void) {
    return -ENODEV;
}

int arch_iommu_init(void) {
    int ret = arch_aarch64_iommu_native_init();
    if (ret != -ENODEV)
        return ret;

    const struct boot_info *bi = boot_info_get();
    if (bi && (bi->dtb || bi->rsdp))
        return -ENOTSUP;
    return -ENODEV;
}
