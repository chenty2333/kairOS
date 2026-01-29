/**
 * kernel/fs/fat32/fat32_diskio.c - FatFs disk I/O stubs
 */

#include <kairos/types.h>

#include "fat32_internal.h"

typedef uint8_t DSTATUS;
typedef uint8_t DRESULT;

#define RES_OK 0
#define RES_ERROR 1
#define RES_WRPRT 2
#define RES_NOTRDY 3
#define RES_PARERR 4

DSTATUS disk_initialize(uint8_t pdrv) {
    (void)pdrv;
    return RES_NOTRDY;
}

DSTATUS disk_status(uint8_t pdrv) {
    (void)pdrv;
    return RES_NOTRDY;
}

DRESULT disk_read(uint8_t pdrv, uint8_t *buff, uint32_t sector, uint32_t count) {
    (void)pdrv;
    (void)buff;
    (void)sector;
    (void)count;
    return RES_NOTRDY;
}

DRESULT disk_write(uint8_t pdrv, const uint8_t *buff, uint32_t sector,
                   uint32_t count) {
    (void)pdrv;
    (void)buff;
    (void)sector;
    (void)count;
    return RES_NOTRDY;
}

DRESULT disk_ioctl(uint8_t pdrv, uint8_t cmd, void *buff) {
    (void)pdrv;
    (void)cmd;
    (void)buff;
    return RES_NOTRDY;
}
