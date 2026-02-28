/**
 * kernel/lib/hash.c - Hash mixing helpers
 */

#include <kairos/hash.h>

uint64_t khash_mix64(uint64_t key) {
    /* MurmurHash3 64-bit finalizer */
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccdULL;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53ULL;
    key ^= key >> 33;
    return key;
}

uint32_t khash_mix32(uint32_t key) {
    return (uint32_t)khash_mix64((uint64_t)key);
}
