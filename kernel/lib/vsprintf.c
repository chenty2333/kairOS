/**
 * vsprintf.c - String formatting functions
 *
 * Implements a minimal printf-style formatting for kernel use.
 * Supported format specifiers:
 *   %d, %i  - signed decimal
 *   %u      - unsigned decimal
 *   %x, %X  - hexadecimal (lowercase/uppercase)
 *   %p      - pointer (like %016lx)
 *   %s      - string
 *   %c      - character
 *   %%      - literal percent
 *
 * Supported flags:
 *   0       - zero-pad
 *   -       - left-align
 *   width   - minimum field width
 *   l, ll   - long, long long modifier
 */

#include <kairos/types.h>
#include <stdarg.h>

/* Output a single character to buffer */
static int putchar_buf(char *buf, size_t size, size_t pos, char c)
{
    if (pos < size) {
        buf[pos] = c;
    }
    return 1;
}

/* Output a string to buffer */
static int puts_buf(char *buf, size_t size, size_t pos, const char *s)
{
    int written = 0;
    while (*s) {
        written += putchar_buf(buf, size, pos + written, *s++);
    }
    return written;
}

/* Convert unsigned integer to string */
static int format_uint(char *buf, size_t size, size_t pos,
                       unsigned long long val, int base, int width,
                       int zero_pad, int uppercase)
{
    char tmp[24];
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    int i = 0;
    int written = 0;

    /* Generate digits in reverse */
    if (val == 0) {
        tmp[i++] = '0';
    } else {
        while (val > 0) {
            tmp[i++] = digits[val % base];
            val /= base;
        }
    }

    /* Padding */
    char pad = zero_pad ? '0' : ' ';
    while (width > i) {
        written += putchar_buf(buf, size, pos + written, pad);
        width--;
    }

    /* Output digits in correct order */
    while (i > 0) {
        written += putchar_buf(buf, size, pos + written, tmp[--i]);
    }

    return written;
}

/* Convert signed integer to string */
static int format_int(char *buf, size_t size, size_t pos,
                      long long val, int width, int zero_pad)
{
    int written = 0;

    if (val < 0) {
        written += putchar_buf(buf, size, pos + written, '-');
        val = -val;
        if (width > 0) {
            width--;
        }
    }

    written += format_uint(buf, size, pos + written,
                           (unsigned long long)val, 10, width, zero_pad, 0);
    return written;
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
    size_t pos = 0;
    int written;

    while (*fmt) {
        if (*fmt != '%') {
            pos += putchar_buf(buf, size, pos, *fmt++);
            continue;
        }

        fmt++; /* Skip '%' */

        /* Handle %% */
        if (*fmt == '%') {
            pos += putchar_buf(buf, size, pos, '%');
            fmt++;
            continue;
        }

        /* Parse flags */
        int zero_pad = 0;
        int left_align = 0;

        while (*fmt == '0' || *fmt == '-') {
            if (*fmt == '0') {
                zero_pad = 1;
            }
            if (*fmt == '-') {
                left_align = 1;
            }
            fmt++;
        }
        (void)left_align; /* TODO: implement left alignment */

        /* Parse width */
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
        }

        /* Parse length modifier */
        int length = 0; /* 0=int, 1=long, 2=long long */
        while (*fmt == 'l') {
            length++;
            fmt++;
        }
        if (*fmt == 'z') {
            length = 1; /* size_t = unsigned long on 64-bit */
            fmt++;
        }

        /* Parse conversion specifier */
        switch (*fmt) {
        case 'd':
        case 'i': {
            long long val;
            if (length >= 2) {
                val = va_arg(ap, long long);
            } else if (length == 1) {
                val = va_arg(ap, long);
            } else {
                val = va_arg(ap, int);
            }
            written = format_int(buf, size, pos, val, width, zero_pad);
            pos += written;
            break;
        }

        case 'u': {
            unsigned long long val;
            if (length >= 2) {
                val = va_arg(ap, unsigned long long);
            } else if (length == 1) {
                val = va_arg(ap, unsigned long);
            } else {
                val = va_arg(ap, unsigned int);
            }
            written = format_uint(buf, size, pos, val, 10, width, zero_pad, 0);
            pos += written;
            break;
        }

        case 'x':
        case 'X': {
            unsigned long long val;
            if (length >= 2) {
                val = va_arg(ap, unsigned long long);
            } else if (length == 1) {
                val = va_arg(ap, unsigned long);
            } else {
                val = va_arg(ap, unsigned int);
            }
            written = format_uint(buf, size, pos, val, 16, width, zero_pad, *fmt == 'X');
            pos += written;
            break;
        }

        case 'p': {
            void *ptr = va_arg(ap, void *);
            pos += puts_buf(buf, size, pos, "0x");
            written = format_uint(buf, size, pos, (unsigned long long)(uintptr_t)ptr,
                                  16, 16, 1, 0);
            pos += written;
            break;
        }

        case 's': {
            const char *s = va_arg(ap, const char *);
            if (s == NULL) {
                s = "(null)";
            }
            written = puts_buf(buf, size, pos, s);
            pos += written;
            break;
        }

        case 'c': {
            char c = (char)va_arg(ap, int);
            pos += putchar_buf(buf, size, pos, c);
            break;
        }

        default:
            /* Unknown specifier, output as-is */
            pos += putchar_buf(buf, size, pos, '%');
            pos += putchar_buf(buf, size, pos, *fmt);
            break;
        }

        fmt++;
    }

    /* Null terminate */
    if (size > 0) {
        buf[pos < size ? pos : size - 1] = '\0';
    }

    return (int)pos;
}

int vsprintf(char *buf, const char *fmt, va_list ap)
{
    return vsnprintf(buf, (size_t)-1, fmt, ap);
}

int snprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vsnprintf(buf, size, fmt, ap);
    va_end(ap);

    return ret;
}

int sprintf(char *buf, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vsprintf(buf, fmt, ap);
    va_end(ap);

    return ret;
}
