/**
 * printk.c - Kernel logging
 */

#include <kairos/printk.h>
#include <kairos/arch.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <stdarg.h>

int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);

#define LOG_BUF_SHIFT 14
#define LOG_BUF_LEN (1 << LOG_BUF_SHIFT)
#define LOG_BUF_MASK (LOG_BUF_LEN - 1)

static char log_buf[LOG_BUF_LEN];
static unsigned long log_head = 0;
static unsigned long log_read_pos = 0;

#define PRINTK_BUF_SIZE 1024
static char printk_buf[PRINTK_BUF_SIZE];

static spinlock_t log_lock = SPINLOCK_INIT;

static void puts_early(const char *s)
{
    while (*s) {
        if (*s == '\n') {
            arch_early_putchar('\r');
        }
        arch_early_putchar(*s++);
    }
}

static void log_store(const char *s, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        log_buf[log_head & LOG_BUF_MASK] = s[i];
        log_head++;
    }
}

int vprintk(const char *fmt, va_list args)
{
    char small_buf[128];
    char *buf = small_buf;
    size_t buf_size = sizeof(small_buf);
    int len;

    va_list args_copy;
    va_copy(args_copy, args);
    len = vsnprintf(small_buf, sizeof(small_buf), fmt, args_copy);
    va_end(args_copy);

    bool flags;
    spin_lock_irqsave(&log_lock, &flags);

    if (len >= (int)sizeof(small_buf)) {
        buf = printk_buf;
        buf_size = PRINTK_BUF_SIZE;
        len = vsnprintf(printk_buf, PRINTK_BUF_SIZE, fmt, args);
    }

    if (len > 0) {
        if ((size_t)len > buf_size - 1) {
             len = buf_size - 1;
        }
        log_store(buf, len);
        puts_early(buf);
    }

    spin_unlock_irqrestore(&log_lock, flags);

    return len;
}

int printk(const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vprintk(fmt, args);
    va_end(args);

    return ret;
}

ssize_t klog_read(char *buf, size_t len, bool clear)
{
    bool flags;
    spin_lock_irqsave(&log_lock, &flags);
    unsigned long avail = log_head - log_read_pos;
    if (avail > LOG_BUF_LEN) {
        avail = LOG_BUF_LEN;
        log_read_pos = log_head - LOG_BUF_LEN;
    }
    size_t to_copy = (len < avail) ? len : avail;
    unsigned long start = log_read_pos & LOG_BUF_MASK;
    for (size_t i = 0; i < to_copy; i++) {
        buf[i] = log_buf[(start + i) & LOG_BUF_MASK];
    }
    if (clear || to_copy > 0) {
        log_read_pos += to_copy;
    }
    spin_unlock_irqrestore(&log_lock, flags);
    return (ssize_t)to_copy;
}

ssize_t klog_read_all(char *buf, size_t len)
{
    bool flags;
    spin_lock_irqsave(&log_lock, &flags);
    unsigned long avail = (log_head > LOG_BUF_LEN) ? LOG_BUF_LEN : log_head;
    size_t to_copy = (len < avail) ? len : avail;
    unsigned long start = (log_head - avail) & LOG_BUF_MASK;
    for (size_t i = 0; i < to_copy; i++) {
        buf[i] = log_buf[(start + i) & LOG_BUF_MASK];
    }
    spin_unlock_irqrestore(&log_lock, flags);
    return (ssize_t)to_copy;
}

void klog_clear(void)
{
    bool flags;
    spin_lock_irqsave(&log_lock, &flags);
    log_read_pos = log_head;
    spin_unlock_irqrestore(&log_lock, flags);
}

size_t klog_size_unread(void)
{
    bool flags;
    spin_lock_irqsave(&log_lock, &flags);
    unsigned long avail = log_head - log_read_pos;
    if (avail > LOG_BUF_LEN) {
        avail = LOG_BUF_LEN;
    }
    spin_unlock_irqrestore(&log_lock, flags);
    return avail;
}

size_t klog_size_buffer(void)
{
    return LOG_BUF_LEN;
}

static volatile int panic_in_progress = 0;

noreturn void panic(const char *fmt, ...)
{
    va_list args;

    arch_irq_disable();

    if (__sync_lock_test_and_set(&panic_in_progress, 1)) {
        while (1) arch_cpu_halt();
    }

    arch_send_ipi_all(IPI_STOP);

    spin_trylock(&log_lock);

    puts_early("\n\n*** KERNEL PANIC ***\n");

    va_start(args, fmt);
    vsnprintf(printk_buf, PRINTK_BUF_SIZE, fmt, args);
    va_end(args);

    puts_early(printk_buf);
    puts_early("\n\n");

    while (1) {
        arch_cpu_halt();
    }
}
