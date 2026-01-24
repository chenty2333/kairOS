/**
 * printk.c - Kernel logging implementation
 *
 * Features:
 *  - Ring buffer for dmesg-style history (in-memory logging).
 *  - Stack-based formatting for small messages (reduces lock contention).
 *  - Early console output.
 */

#include <kairos/printk.h>
#include <kairos/arch.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <stdarg.h>

/* Forward declaration */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);

/* 
 * Log Buffer (Ring Buffer)
 * Stores a copy of all kernel messages for debugging/dmesg.
 */
#define LOG_BUF_SHIFT 14
#define LOG_BUF_LEN (1 << LOG_BUF_SHIFT) /* 16KB */
#define LOG_BUF_MASK (LOG_BUF_LEN - 1)

static char log_buf[LOG_BUF_LEN];
static unsigned long log_head = 0; /* Index for next write */

/* 
 * Global formatting buffer for large messages.
 * Protected by printk_lock.
 */
#define PRINTK_BUF_SIZE 1024
static char printk_buf[PRINTK_BUF_SIZE];

/* Simple spinlock */
static volatile int printk_lock = 0;

static void lock_printk(void)
{
    while (__atomic_exchange_n(&printk_lock, 1, __ATOMIC_ACQUIRE)) {
        arch_cpu_relax();
    }
}

static void unlock_printk(void)
{
    __atomic_store_n(&printk_lock, 0, __ATOMIC_RELEASE);
}

/* Output string to early console */
static void puts_early(const char *s)
{
    while (*s) {
        if (*s == '\n') {
            arch_early_putchar('\r');
        }
        arch_early_putchar(*s++);
    }
}

/* Write to the kernel log ring buffer */
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
    /* 
     * Optimization: Use a small stack buffer for most messages.
     * This avoids acquiring the global lock just for formatting,
     * significantly reducing contention on multicore systems.
     */
    char small_buf[128];
    char *buf = small_buf;
    size_t buf_size = sizeof(small_buf);
    int len;
    bool using_global_buf = false;
    bool irq_state;

    /* First try: format into stack buffer */
    va_list args_copy;
    va_copy(args_copy, args);
    len = vsnprintf(small_buf, sizeof(small_buf), fmt, args_copy);
    va_end(args_copy);

    /* 
     * If the message didn't fit (len >= size), we need the big global buffer.
     * Note: vsnprintf returns the length that WOULD have been written.
     */
    irq_state = arch_irq_save();
    
    if (len >= (int)sizeof(small_buf)) {
        lock_printk();
        using_global_buf = true;
        buf = printk_buf;
        buf_size = PRINTK_BUF_SIZE;
        
        /* Re-format into global buffer */
        len = vsnprintf(printk_buf, PRINTK_BUF_SIZE, fmt, args);
    } else {
        /* 
         * For small messages, we still need the lock to write to 
         * the ring buffer and the serial console ensuring atomicity.
         */
        lock_printk();
    }

    /* Store in log buffer */
    if (len > 0) {
        /* Cap length for safety, though vsnprintf handles it */
        if ((size_t)len > buf_size - 1) {
             len = buf_size - 1;
        }
        log_store(buf, len);
        puts_early(buf);
    }

    if (using_global_buf) {
        /* We already hold the lock */
        unlock_printk();
    } else {
        unlock_printk();
    }
    
    arch_irq_restore(irq_state);

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

noreturn void panic(const char *fmt, ...)
{
    va_list args;

    arch_irq_disable();

    /* Bypass lock if possible or just force it, but here we just print direct */
    puts_early("\n\n*** KERNEL PANIC ***\n");

    va_start(args, fmt);
    /* 
     * In panic, we don't care about the lock or the log buffer as much,
     * we just want it on screen ASAP. We reuse printk_buf unsafely 
     * because we are stopping anyway.
     */
    vsnprintf(printk_buf, PRINTK_BUF_SIZE, fmt, args);
    va_end(args);

    puts_early(printk_buf);
    puts_early("\n\n");

    /* TODO: print backtrace */

    /* Halt forever */
    while (1) {
        arch_cpu_halt();
    }
}