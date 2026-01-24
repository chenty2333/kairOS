/**
 * string.c - String and memory manipulation functions
 *
 * Provides standard string/memory functions for the kernel.
 */

#include <kairos/string.h>

/**
 * strlen - Calculate string length
 */
size_t strlen(const char *s)
{
    size_t len = 0;
    while (*s++) {
        len++;
    }
    return len;
}

/**
 * strcmp - Compare two strings
 */
int strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

/**
 * strncmp - Compare two strings up to n characters
 */
int strncmp(const char *s1, const char *s2, size_t n)
{
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
 * strcpy - Copy a string
 */
char *strcpy(char *dest, const char *src)
{
    char *ret = dest;
    while ((*dest++ = *src++));
    return ret;
}

/**
 * strncpy - Copy up to n characters of a string
 */
char *strncpy(char *dest, const char *src, size_t n)
{
    size_t i;
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
char *strcat(char *dest, const char *src)
{
    char *ret = dest;
    while (*dest) {
        dest++;
    }
    while ((*dest++ = *src++));
    return ret;
}

/**
 * memcpy - Copy memory area
 */
void *memcpy(void *dest, const void *src, size_t n)
{
    char *d = dest;
    const char *s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

/**
 * memset - Fill memory with a constant byte
 */
void *memset(void *s, int c, size_t n)
{
    unsigned char *p = s;
    while (n--) {
        *p++ = (unsigned char)c;
    }
    return s;
}

/**
 * memmove - Copy memory area (handles overlapping)
 */
void *memmove(void *dest, const void *src, size_t n)
{
    char *d = dest;
    const char *s = src;

    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    } else {
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    return dest;
}

/**
 * memcmp - Compare memory areas
 */
int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;

    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}
