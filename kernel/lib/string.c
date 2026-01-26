/**
 * string.c - String and memory manipulation functions
 *
 * Provides standard string/memory functions for the kernel.
 * Optimized for word-sized operations where possible.
 */

#include <kairos/string.h>
#include <kairos/types.h>

/* Define word size for optimizations */
typedef unsigned long word_t;
#define WORD_SIZE sizeof(word_t)
#define WORD_MASK (WORD_SIZE - 1)

/* Constants for zero-byte detection magic */
/* Works for both 32-bit and 64-bit provided word_t is correct */
#define ONES ((word_t) - 1 / 0xFF)
#define HIGHS (ONES * 0x80)

/*
 * HAS_ZERO(x) returns a non-zero value if any byte in the word 'x' is zero.
 * Algorithm: (x - 0x01...) & ~x & 0x80...
 */
#define HAS_ZERO(x) (((x) - ONES) & ~(x) & HIGHS)

/**
 * strlen - Calculate string length
 */
size_t strlen(const char *s) {
    const char *start = s;

    // Align to word boundary
    while ((uintptr_t)s & WORD_MASK) {
        if (*s == '\0') {
            return s - start;
        }
        s++;
    }

    // Scan words
    const word_t *w = (const word_t *)s;
    while (!HAS_ZERO(*w)) {
        w++;
    }

    // Find the exact zero byte in the found word
    s = (const char *)w;
    while (*s) {
        s++;
    }

    return s - start;
}

/**
 * strcmp - Compare two strings
 */
int strcmp(const char *s1, const char *s2) {
    // Try word-sized comparison if aligned
    if ((((uintptr_t)s1 | (uintptr_t)s2) & WORD_MASK) == 0) {
        const word_t *w1 = (const word_t *)s1;
        const word_t *w2 = (const word_t *)s2;

        while (*w1 == *w2) {
            if (HAS_ZERO(*w1)) {
                // Zero byte found inside identical words
                // We need to find exactly where the strings end,
                // but since words are identical, strings are equal up to here.
                return 0;
            }
            w1++;
            w2++;
        }

        // Difference found, fall back to byte comparison
        s1 = (const char *)w1;
        s2 = (const char *)w2;
    }

    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

/**
 * strncmp - Compare two strings up to n characters
 */
int strncmp(const char *s1, const char *s2, size_t n) {
    if (n == 0)
        return 0;

    // Optional: Add word optimization for large n (omitted for simplicity vs n
    // check overhead)

    while (n && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) {
        return 0;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

/**
 * strchr - Find first occurrence of character in string
 */
char *strchr(const char *s, int c) {
    while (*s != (char)c) {
        if (!*s++)
            return NULL;
    }
    return (char *)s;
}

/**
 * strrchr - Find last occurrence of character in string
 */
char *strrchr(const char *s, int c) {
    const char *last = NULL;
    do {
        if (*s == (char)c)
            last = s;
    } while (*s++);
    return (char *)last;
}

/**
 * strcpy - Copy a string
 */
char *strcpy(char *dest, const char *src) {
    char *d = dest;
    const char *s = src;

    // Try to align dest to word boundary if src has same alignment offset
    if (((uintptr_t)d & WORD_MASK) == ((uintptr_t)s & WORD_MASK)) {

        // Align
        while ((uintptr_t)d & WORD_MASK) {
            if ((*d++ = *s++) == '\0') {
                return dest;
            }
        }

        // Copy words
        word_t *wd = (word_t *)d;
        const word_t *ws = (const word_t *)s;

        while (!HAS_ZERO(*ws)) {
            *wd++ = *ws++;
        }

        // Handle the final word (containing '\0') byte-by-byte
        d = (char *)wd;
        s = (const char *)ws;
    }

    while ((*d++ = *s++))
        ;
    return dest;
}

/**
 * strncpy - Copy up to n characters of a string
 */
char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;

    // Standard implementation (optimizing this is complex due to zero-padding
    // requirement)
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

/**
 * strcat - Concatenate two strings
 */
char *strcat(char *dest, const char *src) {
    // Leverage optimized strlen and strcpy
    char *p = dest + strlen(dest);
    strcpy(p, src);
    return dest;
}

/**
 * memcpy - Copy memory area
 */
void *memcpy(void *dest, const void *src, size_t n) {
    char *d = dest;
    const char *s = src;

    if (n >= WORD_SIZE &&
        ((uintptr_t)d & WORD_MASK) == ((uintptr_t)s & WORD_MASK)) {

        while ((uintptr_t)d & WORD_MASK) {
            *d++ = *s++;
            n--;
        }

        word_t *wd = (word_t *)d;
        const word_t *ws = (const word_t *)s;

        while (n >= WORD_SIZE) {
            *wd++ = *ws++;
            n -= WORD_SIZE;
        }

        d = (char *)wd;
        s = (const char *)ws;
    }

    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

/**
 * memset - Fill memory with a constant byte
 */
void *memset(void *s, int c, size_t n) {
    char *p = s;

    if (n < WORD_SIZE) {
        while (n--) {
            *p++ = (char)c;
        }
        return s;
    }

    while ((uintptr_t)p & WORD_MASK) {
        *p++ = (char)c;
        n--;
    }

    word_t *wp = (word_t *)p;
    word_t val = (unsigned char)c;

    val |= val << 8;
    val |= val << 16;
    if (WORD_SIZE > 4) {
        val |= val << 32;
    }

    while (n >= WORD_SIZE) {
        *wp++ = val;
        n -= WORD_SIZE;
    }

    p = (char *)wp;
    while (n--) {
        *p++ = (char)c;
    }

    return s;
}

/**
 * memmove - Copy memory area (handles overlapping)
 */
void *memmove(void *dest, const void *src, size_t n) {
    char *d = dest;
    const char *s = src;

    if (d == s || n == 0) {
        return dest;
    }

    if (d < s) {
        return memcpy(dest, src, n);
    }

    d += n;
    s += n;

    if (n >= WORD_SIZE &&
        ((uintptr_t)d & WORD_MASK) == ((uintptr_t)s & WORD_MASK)) {

        while ((uintptr_t)d & WORD_MASK) {
            *--d = *--s;
            n--;
        }

        word_t *wd = (word_t *)d;
        const word_t *ws = (const word_t *)s;

        while (n >= WORD_SIZE) {
            *--wd = *--ws;
            n -= WORD_SIZE;
        }

        d = (char *)wd;
        s = (const char *)ws;
    }

    while (n--) {
        *--d = *--s;
    }

    return dest;
}

/**
 * memcmp - Compare memory areas
 */
int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;

    if (n >= WORD_SIZE &&
        ((uintptr_t)p1 & WORD_MASK) == ((uintptr_t)p2 & WORD_MASK)) {

        while ((uintptr_t)p1 & WORD_MASK) {
            if (*p1 != *p2)
                return *p1 - *p2;
            p1++;
            p2++;
            n--;
        }

        const word_t *w1 = (const word_t *)p1;
        const word_t *w2 = (const word_t *)p2;

        while (n >= WORD_SIZE) {
            if (*w1 != *w2) {
                break; // Found difference, fallback to bytes to locate it
            }
            w1++;
            w2++;
            n -= WORD_SIZE;
        }

        p1 = (const unsigned char *)w1;
        p2 = (const unsigned char *)w2;
    }

    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

/**
 * strstr - Find first occurrence of a substring in a string
 */
char *strstr(const char *haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    if (!needle_len) {
        return (char *)haystack;
    }

    while (*haystack) {
        if (strncmp(haystack, needle, needle_len) == 0) {
            return (char *)haystack;
        }
        haystack++;
    }
    return NULL;
}
