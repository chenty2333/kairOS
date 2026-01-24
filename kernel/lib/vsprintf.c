/**
 * vsprintf.c - String formatting functions
 *
 * Implements a minimal printf-style formatting for kernel use.
 * Optimized for performance and standards compliance.
 *
 * Features:
 *  - Hex optimization (shifts vs division)
 *  - Batch string copy (memcpy)
 *  - Full alignment support ('-', width)
 *  - Precision support ('%.N') for integers and strings
 *  - Correct signed integer handling
 */

#include <kairos/types.h>
#include <kairos/string.h>
#include <stdarg.h>

struct buf_state {
    char *ptr;
    size_t size;
    size_t pos;
};

static void emit_char(struct buf_state *state, char c)
{
    if (state->pos < state->size) {
        state->ptr[state->pos] = c;
    }
    state->pos++;
}

static void emit_str_len(struct buf_state *state, const char *s, size_t len)
{
    if (state->pos < state->size) {
        size_t copy_len = len;
        size_t remain = state->size - state->pos;
        
        if (copy_len > remain) {
            copy_len = remain;
        }
        
        memcpy(state->ptr + state->pos, s, copy_len);
    }
    state->pos += len;
}

static void emit_pad(struct buf_state *state, int len, char pad_char)
{
    while (len-- > 0) {
        emit_char(state, pad_char);
    }
}

static void format_number(struct buf_state *state, unsigned long long val, 
                          int base, int width, int precision, int flags)
{
    char tmp[66];
    const char *digits = (flags & 2) ? "0123456789ABCDEF" : "0123456789abcdef";
    int i = 0;
    int left_align = (flags & 4);
    
    /* 
     * Flag logic according to standard:
     * - '0' (zero pad) is ignored if '-' (left align) is present.
     * - '0' (zero pad) is ignored if precision is specified (for integers).
     */
    int zero_pad = (flags & 1) && !left_align && (precision == -1);

    /* Convert number */
    if (val == 0) {
        /* "%.0d" of 0 prints nothing */
        if (precision != 0) {
            tmp[i++] = '0';
        }
    } else if (base == 16) {
        while (val != 0) {
            tmp[i++] = digits[val & 0xF];
            val >>= 4;
        }
    } else {
        while (val != 0) {
            tmp[i++] = digits[val % base];
            val /= base;
        }
    }

    int len = i;
    int zeros = 0;

    /* Calculate explicit precision zeros */
    if (precision > len) {
        zeros = precision - len;
    } else if (precision == -1 && zero_pad) {
        /* If no precision but zero_pad set, treat width as "precision" basically */
        if (width > len) {
            zeros = width - len;
        }
    }
    
    /* Total characters to output (excluding external padding spaces) */
    int total_len = len + zeros;
    
    /* Calculate padding spaces */
    int padding = width - total_len;
    if (padding < 0) padding = 0;

    /* Output: [Spaces] [Zeros] [Digits] [Spaces(if left)] */

    if (!left_align) {
        emit_pad(state, padding, ' ');
    }

    emit_pad(state, zeros, '0');

    while (i > 0) {
        emit_char(state, tmp[--i]);
    }

    if (left_align) {
        emit_pad(state, padding, ' ');
    }
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
    struct buf_state state = { buf, size, 0 };
    
    while (*fmt) {
        if (*fmt != '%') {
            const char *start = fmt;
            while (*fmt && *fmt != '%') {
                fmt++;
            }
            emit_str_len(&state, start, fmt - start);
            continue;
        }

        fmt++; /* Skip '%' */

        if (*fmt == '%') {
            emit_char(&state, '%');
            fmt++;
            continue;
        }

        /* Parse flags */
        int flags = 0; // 1=zero_pad, 2=upper, 4=left
        while (1) {
            if (*fmt == '0') flags |= 1;
            else if (*fmt == '-') flags |= 4;
            else break;
            fmt++;
        }
        
        /* Parse width */
        int width = 0;
        if (*fmt == '*') {
            width = va_arg(ap, int);
            if (width < 0) {
                width = -width;
                flags |= 4;
            }
            fmt++;
        } else {
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }
        }

        /* Parse precision */
        int precision = -1;
        if (*fmt == '.') {
            fmt++;
            precision = 0;
            if (*fmt == '*') {
                precision = va_arg(ap, int);
                if (precision < 0) precision = -1; // Negative precision = ignore
                fmt++;
            } else {
                while (*fmt >= '0' && *fmt <= '9') {
                    precision = precision * 10 + (*fmt - '0');
                    fmt++;
                }
            }
        }

        /* Parse length modifier */
        int length = 0; /* 0=int, 1=long, 2=long long */
        while (*fmt == 'l') {
            length++;
            fmt++;
        }
        if (*fmt == 'z') {
            length = 1;
            fmt++;
        }

        /* Parse conversion specifier */
        switch (*fmt) {
        case 'd':
        case 'i': {
            long long val;
            if (length >= 2) val = va_arg(ap, long long);
            else if (length == 1) val = va_arg(ap, long);
            else val = va_arg(ap, int);

            /* Handle sign manually */
            if (val < 0) {
                emit_char(&state, '-');
                if (width > 0) width--;
                format_number(&state, (unsigned long long)-(val + 1) + 1, 10, width, precision, flags);
            } else {
                format_number(&state, (unsigned long long)val, 10, width, precision, flags);
            }
            break;
        }

        case 'u': {
            unsigned long long val;
            if (length >= 2) val = va_arg(ap, unsigned long long);
            else if (length == 1) val = va_arg(ap, unsigned long);
            else val = va_arg(ap, unsigned int);
            format_number(&state, val, 10, width, precision, flags);
            break;
        }

        case 'x':
        case 'X': {
            unsigned long long val;
            if (length >= 2) val = va_arg(ap, unsigned long long);
            else if (length == 1) val = va_arg(ap, unsigned long);
            else val = va_arg(ap, unsigned int);
            
            if (*fmt == 'X') flags |= 2;
            format_number(&state, val, 16, width, precision, flags);
            break;
        }

        case 'p': {
            void *ptr = va_arg(ap, void *);
            emit_str_len(&state, "0x", 2);
            /* %p implies 16 hex digits (usually), zero padded if we treat width/precision implicitly
               But strict standard says implementation defined. 
               We use width=16, precision=-1 (default), zero_pad=1 for nice pointer output. */
            format_number(&state, (unsigned long long)(uintptr_t)ptr, 16, 16, -1, flags | 1);
            break;
        }

        case 's': {
            const char *s = va_arg(ap, const char *);
            if (s == NULL) s = "(null)";
            
            /* Strlen logic with precision */
            size_t len = 0;
            const char *p = s;
            while (*p && (precision == -1 || len < (size_t)precision)) {
                len++;
                p++;
            }
            
            int padding = width - (int)len;
            
            if (!(flags & 4) && padding > 0) emit_pad(&state, padding, ' ');
            emit_str_len(&state, s, len);
            if ((flags & 4) && padding > 0) emit_pad(&state, padding, ' ');
            
            break;
        }

        case 'c': {
            char c = (char)va_arg(ap, int);
            int padding = width - 1;
             if (!(flags & 4) && padding > 0) emit_pad(&state, padding, ' ');
            emit_char(&state, c);
             if ((flags & 4) && padding > 0) emit_pad(&state, padding, ' ');
            break;
        }

        default:
            emit_char(&state, '%');
            emit_char(&state, *fmt);
            break;
        }

        if (*fmt) fmt++;
    }

    if (state.size > 0) {
        if (state.pos < state.size) {
            state.ptr[state.pos] = '\0';
        } else {
            state.ptr[state.size - 1] = '\0';
        }
    }

    return (int)state.pos;
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
