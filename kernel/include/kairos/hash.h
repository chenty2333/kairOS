/**
 * kernel/include/kairos/hash.h - Hash mixing helpers
 */

#ifndef _KAIROS_HASH_H
#define _KAIROS_HASH_H

#include <kairos/types.h>

/*
 * Hash mix helpers for integer keys.
 * Not cryptographic; intended for hashtable bucket distribution.
 */
uint64_t khash_mix64(uint64_t key);

uint32_t khash_mix32(uint32_t key);

#endif
