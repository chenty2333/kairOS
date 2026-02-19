/**
 * kernel/arch/riscv64/entry.c - RISC-V 64 Architecture Entry Logic
 */

#include <asm/arch.h>
#include <boot/limine.h>
#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/sched.h>
#include <kairos/types.h>

/* SBI Extensions */
#define SBI_EXT_IPI 0x735049
#define SBI_EXT_HSM 0x48534D
#define SBI_EXT_SRST 0x53525354
#define SBI_EXT_RFENCE 0x52464E43
#define SBI_HSM_HART_START 0
#define SBI_HSM_HART_STATUS 2
#define SBI_IPI_SEND 0
#define SBI_RFENCE_REMOTE_SFENCE_VMA 0

/* Legacy SBI */
#define SBI_CONSOLE_PUTCHAR 0x01
#define SBI_CONSOLE_GETCHAR 0x02
#define SBI_SHUTDOWN 0x08

/* QEMU virt UART0 (16550 compatible) */
#define UART0_BASE 0x10000000UL
#define UART_RHR   0x00
#define UART_LSR   0x05
#define UART_LSR_DR 0x01

static inline long sbi_legacy_call(int ext, unsigned long arg0) {
    register unsigned long a0 __asm__("a0") = arg0;
    register unsigned long a7 __asm__("a7") = ext;
    __asm__ __volatile__("ecall" : "+r"(a0) : "r"(a7) : "memory");
    return a0;
}

static inline int uart_getchar_nb(void) {
    volatile uint8_t *uart = (volatile uint8_t *)UART0_BASE;
    if (uart[UART_LSR] & UART_LSR_DR)
        return (int)uart[UART_RHR];
    return -1;
}

void arch_early_putchar(char c) {
    sbi_legacy_call(SBI_CONSOLE_PUTCHAR, c);
}

int arch_early_getchar(void) {
    long ret;
    while ((ret = sbi_legacy_call(SBI_CONSOLE_GETCHAR, 0)) < 0) {
    }
    return (int)ret;
}

int arch_early_getchar_nb(void) {
    /*
     * Prefer direct UART MMIO first. Some firmware/boot flows may leave the
     * SBI console path as the only working RX backend from S-mode, so fall
     * back to SBI non-blocking getchar when MMIO reports no data.
     */
    int ch = uart_getchar_nb();
    if (ch >= 0)
        return ch;

    long ret = sbi_legacy_call(SBI_CONSOLE_GETCHAR, 0);
    if (ret >= 0)
        return (int)ret;
    return -1;
}

void arch_cpu_halt(void) {
    __asm__ __volatile__("wfi");
}

void arch_cpu_relax(void) {
    __asm__ __volatile__("" ::: "memory");
}

noreturn void arch_cpu_shutdown(void) {
    sbi_legacy_call(SBI_SHUTDOWN, 0);
    for (;;)
        arch_cpu_halt();
}

noreturn void arch_cpu_reset(void) {
    sbi_call(SBI_EXT_SRST, 0, 0, 0, 0);
    arch_cpu_shutdown();
}

void arch_irq_enable(void) {
    __asm__ __volatile__("csrsi sstatus, 0x2" ::: "memory");
}

void arch_irq_disable(void) {
    __asm__ __volatile__("csrci sstatus, 0x2" ::: "memory");
}

bool arch_irq_save(void) {
    unsigned long sstatus;
    __asm__ __volatile__("csrrc %0, sstatus, 0x2" : "=r"(sstatus)::"memory");
    return (sstatus & 0x2) != 0;
}

void arch_irq_restore(bool state) {
    if (state)
        arch_irq_enable();
}

bool arch_irq_enabled(void) {
    unsigned long sstatus;
    __asm__ __volatile__("csrr %0, sstatus" : "=r"(sstatus));
    return (sstatus & 0x2) != 0;
}

void arch_breakpoint(void) {
    __asm__ __volatile__("ebreak");
}

void arch_send_ipi(int cpu, int type) {
    struct percpu_data *data = sched_cpu_data(cpu);
    if (data)
        __sync_fetch_and_or(&data->ipi_pending_mask, (1 << type));
    const struct boot_info *bi = boot_info_get();
    uint64_t hartid = bi ? bi->cpus[cpu].hw_id : (uint64_t)cpu;
    sbi_call(SBI_EXT_IPI, SBI_IPI_SEND, 1UL << hartid, 0, 0);
}

void arch_send_ipi_all(int type) {
    unsigned long mask = 0;
    int self = arch_cpu_id();
    int count = arch_cpu_count();

    for (int i = 0; i < count; i++) {
        if (i == self) continue;
        struct percpu_data *data = sched_cpu_data(i);
        if (data) {
            __sync_fetch_and_or(&data->ipi_pending_mask, (1 << type));
            const struct boot_info *bi = boot_info_get();
            uint64_t hartid = bi ? bi->cpus[i].hw_id : (uint64_t)i;
            mask |= (1UL << hartid);
        }
    }
    
    if (mask) {
        sbi_call(SBI_EXT_IPI, SBI_IPI_SEND, mask, 0, 0);
    }
}

int arch_cpu_status(int cpu) {
    const struct boot_info *bi = boot_info_get();
    uint64_t hartid = bi ? bi->cpus[cpu].hw_id : (uint64_t)cpu;
    return (int)sbi_call(SBI_EXT_HSM, SBI_HSM_HART_STATUS, hartid, 0, 0).value;
}

void arch_mmu_flush_tlb_all(void) {
    /* Send remote SFENCE.VMA to all harts */
    sbi_call(SBI_EXT_RFENCE, SBI_RFENCE_REMOTE_SFENCE_VMA, -1UL, 0, 0);
}

void arch_cpu_init(int cpu_id) {
    __asm__ __volatile__("mv tp, %0" ::"r"(cpu_id));
}
