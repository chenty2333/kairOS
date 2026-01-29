/* stdlib.h shim for lwIP - minimal definitions for freestanding kernel */
#ifndef _LWIP_COMPAT_STDLIB_H
#define _LWIP_COMPAT_STDLIB_H

#include <kairos/types.h>

/* lwIP uses strtol in some places */
static inline long strtol(const char *nptr, char **endptr, int base) {
    (void)base;
    long val = 0;
    int neg = 0;
    while (*nptr == ' ') nptr++;
    if (*nptr == '-') { neg = 1; nptr++; }
    else if (*nptr == '+') { nptr++; }
    while (*nptr >= '0' && *nptr <= '9') {
        val = val * 10 + (*nptr - '0');
        nptr++;
    }
    if (endptr) *endptr = (char *)nptr;
    return neg ? -val : val;
}

static inline int atoi(const char *s) {
    return (int)strtol(s, NULL, 10);
}

#endif
