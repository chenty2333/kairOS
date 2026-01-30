/**
 * kernel/boot/boot.c - Boot information accessors
 */

#include <kairos/boot.h>
#include <kairos/string.h>

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

static bool boot_path_has_suffix(const char *path, const char *suffix) {
    if (!path || !suffix)
        return false;
    size_t plen = strlen(path);
    size_t slen = strlen(suffix);
    if (slen == 0 || plen < slen)
        return false;
    return memcmp(path + plen - slen, suffix, slen) == 0;
}

const struct boot_module *boot_find_module(const char *name) {
    if (!boot_info_ptr || !name || !name[0])
        return NULL;
    for (uint32_t i = 0; i < boot_info_ptr->module_count; i++) {
        const struct boot_module *mod = &boot_info_ptr->modules[i];
        if (mod->string && strcmp(mod->string, name) == 0)
            return mod;
    }
    for (uint32_t i = 0; i < boot_info_ptr->module_count; i++) {
        const struct boot_module *mod = &boot_info_ptr->modules[i];
        if (mod->path && boot_path_has_suffix(mod->path, name))
            return mod;
    }
    return NULL;
}
