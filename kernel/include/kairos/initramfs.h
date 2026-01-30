/**
 * kernel/include/kairos/initramfs.h - initramfs support
 */

#ifndef _KAIROS_INITRAMFS_H
#define _KAIROS_INITRAMFS_H

#include <kairos/types.h>

void initramfs_init(void);
void initramfs_set_image(const void *addr, size_t size);
bool initramfs_available(void);

#endif
