/**
 * timer.c - RISC-V 64 Timer Implementation
 *
 * Uses the SBI timer extension for setting timer interrupts.
 * The timer runs at a fixed frequency provided by the platform.
 */

#include <kairos/types.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/config.h>

/* SBI timer extension */
#define SBI_EXT_TIME            0x54494D45  /* "TIME" */
#define SBI_TIME_SET_TIMER      0

/* Timer frequency (from QEMU virt platform) */
#define TIMER_FREQ              10000000    /* 10 MHz */

/* CSR addresses */
#define CSR_TIME                0xC01

/* Global state */
static uint64_t timer_freq = TIMER_FREQ;
static uint64_t ticks_per_interrupt;

/* Tick counter (defined in trap.c) */
extern volatile uint64_t system_ticks;

/**
 * SBI call for timer
 */
static inline void sbi_set_timer(uint64_t stime_value)
{
    register uint64_t a0 __asm__("a0") = stime_value;
    register uint64_t a6 __asm__("a6") = SBI_TIME_SET_TIMER;
    register uint64_t a7 __asm__("a7") = SBI_EXT_TIME;

    __asm__ __volatile__(
        "ecall"
        : "+r"(a0)
        : "r"(a6), "r"(a7)
        : "memory", "a1", "a2", "a3", "a4", "a5"
    );
}

/**
 * Read current time from CSR
 */
static inline uint64_t read_time(void)
{
    uint64_t time;
    __asm__ __volatile__(
        "rdtime %0"
        : "=r"(time)
    );
    return time;
}

/**
 * arch_timer_init - Initialize the timer
 * @hz: Desired interrupt frequency (e.g., 100 for 100Hz)
 */
void arch_timer_init(uint64_t hz)
{
    if (hz == 0) {
        hz = CONFIG_HZ;
    }

    ticks_per_interrupt = timer_freq / hz;

    /* Set first timer interrupt */
    uint64_t next = read_time() + ticks_per_interrupt;
    sbi_set_timer(next);

    pr_info("Timer: freq=%lu Hz, interval=%lu ticks (target %lu Hz)\n",
            (unsigned long)timer_freq, (unsigned long)ticks_per_interrupt, (unsigned long)hz);
}

/**
 * arch_timer_ticks - Get current tick count
 */
uint64_t arch_timer_ticks(void)
{
    return read_time();
}

/**
 * arch_timer_freq - Get timer frequency
 */
uint64_t arch_timer_freq(void)
{
    return timer_freq;
}

/**
 * arch_timer_ticks_to_ns - Convert ticks to nanoseconds
 */
uint64_t arch_timer_ticks_to_ns(uint64_t ticks)
{
    return (ticks * 1000000000UL) / timer_freq;
}

/**
 * arch_timer_ns_to_ticks - Convert nanoseconds to ticks
 */
uint64_t arch_timer_ns_to_ticks(uint64_t ns)
{
    return (ns * timer_freq) / 1000000000UL;
}

/**
 * arch_timer_set_next - Set next timer interrupt
 * @ticks: Ticks from now
 */
void arch_timer_set_next(uint64_t ticks)
{
    uint64_t next = read_time() + ticks;
    sbi_set_timer(next);
}

/**
 * arch_timer_ack - Acknowledge timer interrupt
 *
 * On RISC-V, this is done by setting the next timer.
 */
void arch_timer_ack(void)
{
    /* Timer is automatically cleared when we set the next one */
}

/**
 * timer_interrupt_handler - Handle timer interrupt
 *
 * Called from trap_dispatch when a timer interrupt occurs.
 */
void timer_interrupt_handler(void)
{
    system_ticks++;

    /* Set next timer interrupt */
    uint64_t next = read_time() + ticks_per_interrupt;
    sbi_set_timer(next);

    /* Print a tick message periodically (every second at 100Hz) */
    if (system_ticks % CONFIG_HZ == 0) {
        pr_debug("tick: %lu seconds\n", system_ticks / CONFIG_HZ);
    }

    /* TODO: Call scheduler for preemption in later phases */
}

/**
 * arch_timer_get_ticks - Get system tick counter
 */
uint64_t arch_timer_get_ticks(void)
{
    return system_ticks;
}
