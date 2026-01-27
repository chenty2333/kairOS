/**
 * kernel/include/kairos/select.h - Select definitions
 */

#ifndef _KAIROS_SELECT_H
#define _KAIROS_SELECT_H

#include <kairos/types.h>

#define FD_SETSIZE 64

typedef struct {
    uint64_t bits;
} fd_set;

#endif
