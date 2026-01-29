/**
 * kernel/include/kairos/init.h - Kernel init stages
 */

#ifndef _KAIROS_INIT_H
#define _KAIROS_INIT_H

#include <kairos/boot.h>

void init_boot(const struct boot_info *bi);
const void *init_boot_dtb(void);
void init_mm(const struct boot_info *bi);
void init_devices(void);
void init_net(void);
void init_fs(void);
void init_user(void);

#endif
