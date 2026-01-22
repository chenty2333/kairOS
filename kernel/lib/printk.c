/**
 * printk.c - Kernel logging implementation
 */

#include <kairos/printk.h>
#include <kairos/arch.h>
#include <stdarg.h>

/* Forward declaration */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);

/* Buffer for formatting */
#define PRINTK_BUF_SIZE 1024
static char printk_buf[PRINTK_BUF_SIZE];

/* Simple spinlock for printk (TODO: use proper spinlock) */
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

int vprintk(const char *fmt, va_list args)
{
    int ret;
    bool irq_state;

    irq_state = arch_irq_save();
    lock_printk();

    ret = vsnprintf(printk_buf, PRINTK_BUF_SIZE, fmt, args);
    puts_early(printk_buf);

    unlock_printk();
    arch_irq_restore(irq_state);

    return ret;
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

    puts_early("\n\n*** KERNEL PANIC ***\n");

    va_start(args, fmt);
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
