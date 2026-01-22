/**
 * kairos/printk.h - Kernel logging
 */

#ifndef _KAIROS_PRINTK_H
#define _KAIROS_PRINTK_H

#include <kairos/types.h>
#include <stdarg.h>

/*
 * Log Levels
 */
#define KERN_EMERG      0   /* System is unusable */
#define KERN_ALERT      1   /* Action must be taken immediately */
#define KERN_CRIT       2   /* Critical conditions */
#define KERN_ERR        3   /* Error conditions */
#define KERN_WARNING    4   /* Warning conditions */
#define KERN_NOTICE     5   /* Normal but significant */
#define KERN_INFO       6   /* Informational */
#define KERN_DEBUG      7   /* Debug messages */

#define KERN_DEFAULT    KERN_INFO

/*
 * Core print function
 */
int printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int vprintk(const char *fmt, va_list args);

/*
 * Convenience macros
 */
#define pr_emerg(fmt, ...)   printk("[EMERG] " fmt, ##__VA_ARGS__)
#define pr_alert(fmt, ...)   printk("[ALERT] " fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...)    printk("[CRIT] " fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)     printk("[ERROR] " fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)    printk("[WARN] " fmt, ##__VA_ARGS__)
#define pr_notice(fmt, ...)  printk("[NOTICE] " fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)    printk("[INFO] " fmt, ##__VA_ARGS__)

#ifdef CONFIG_DEBUG
#define pr_debug(fmt, ...)   printk("[DEBUG] %s:%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...)   do {} while (0)
#endif

/*
 * Panic - unrecoverable error
 */
noreturn void panic(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * Assertions
 */
#define BUG() do { \
    panic("BUG at %s:%d in %s()", __FILE__, __LINE__, __func__); \
} while (0)

#define BUG_ON(cond) do { \
    if (unlikely(cond)) BUG(); \
} while (0)

#define WARN_ON(cond) do { \
    if (unlikely(cond)) \
        pr_warn("WARNING at %s:%d in %s()\n", __FILE__, __LINE__, __func__); \
} while (0)

#ifdef CONFIG_DEBUG
#define ASSERT(cond) do { \
    if (unlikely(!(cond))) \
        panic("ASSERT failed: %s at %s:%d", #cond, __FILE__, __LINE__); \
} while (0)
#else
#define ASSERT(cond) do {} while (0)
#endif

#endif /* _KAIROS_PRINTK_H */
