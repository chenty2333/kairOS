/**
 * kernel/boot/boot.c - Boot information accessors
 */

#include <kairos/boot.h>

static const struct boot_info *boot_info_ptr;

void boot_info_set(const struct boot_info *info) {
    boot_info_ptr = info;
}

const struct boot_info *boot_info_get(void) {
    return boot_info_ptr;
}

uint64_t boot_hhdm_offset(void) {
    return boot_info_ptr ? boot_info_ptr->hhdm_offset : 0;
}
