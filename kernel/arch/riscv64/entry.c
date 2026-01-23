/**
 * entry.c - RISC-V 64 early initialization and SBI interface
 */

#include <kairos/types.h>
#include <kairos/arch.h>

/*
 * SBI (Supervisor Binary Interface) call
 *
 * RISC-V uses ecall to request services from the firmware (OpenSBI).
 * Arguments are passed in a0-a7, return value in a0.
 */

/* Legacy SBI extensions (deprecated but widely supported) */
#define SBI_CONSOLE_PUTCHAR     0x01
#define SBI_CONSOLE_GETCHAR     0x02
#define SBI_SHUTDOWN            0x08

/* SBI extension IDs */
#define SBI_EXT_BASE            0x10
#define SBI_EXT_TIMER           0x54494D45  /* "TIME" */
#define SBI_EXT_IPI             0x735049    /* "sPI" */
#define SBI_EXT_HSM             0x48534D    /* "HSM" */
#define SBI_EXT_SRST            0x53525354  /* "SRST" */

/* HSM function IDs */
#define SBI_HSM_HART_START      0
#define SBI_HSM_HART_STOP       1
#define SBI_HSM_HART_STATUS     2

/* IPI function IDs */
#define SBI_IPI_SEND            0

struct sbi_ret {
    long error;
    long value;
};

static inline struct sbi_ret sbi_ecall(int ext, int fid,
                                        unsigned long arg0,
                                        unsigned long arg1,
                                        unsigned long arg2,
                                        unsigned long arg3,
                                        unsigned long arg4,
                                        unsigned long arg5)
{
    struct sbi_ret ret;

    register unsigned long a0 __asm__("a0") = arg0;
    register unsigned long a1 __asm__("a1") = arg1;
    register unsigned long a2 __asm__("a2") = arg2;
    register unsigned long a3 __asm__("a3") = arg3;
    register unsigned long a4 __asm__("a4") = arg4;
    register unsigned long a5 __asm__("a5") = arg5;
    register unsigned long a6 __asm__("a6") = fid;
    register unsigned long a7 __asm__("a7") = ext;

    __asm__ __volatile__(
        "ecall"
        : "+r"(a0), "+r"(a1)
        : "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)
        : "memory"
    );

    ret.error = a0;
    ret.value = a1;
    return ret;
}

/* Legacy SBI call (simpler interface for common operations) */
static inline long sbi_legacy_call(int ext, unsigned long arg0)
{
    register unsigned long a0 __asm__("a0") = arg0;
    register unsigned long a7 __asm__("a7") = ext;

    __asm__ __volatile__(
        "ecall"
        : "+r"(a0)
        : "r"(a7)
        : "memory"
    );

    return a0;
}

/*
 * Early console output using SBI
 */
void arch_early_putchar(char c)
{
    sbi_legacy_call(SBI_CONSOLE_PUTCHAR, c);
}

/*
 * Early console input (blocking)
 */
int arch_early_getchar(void)
{
    long ret;
    do {
        ret = sbi_legacy_call(SBI_CONSOLE_GETCHAR, 0);
    } while (ret < 0);
    return (int)ret;
}

/*
 * CPU control functions
 */
void arch_cpu_halt(void)
{
    __asm__ __volatile__("wfi");
}

void arch_cpu_relax(void)
{
    __asm__ __volatile__("" ::: "memory");
}

noreturn void arch_cpu_shutdown(void)
{
    sbi_legacy_call(SBI_SHUTDOWN, 0);
    while (1) {
        arch_cpu_halt();
    }
}

noreturn void arch_cpu_reset(void)
{
    /* Use SRST extension for system reset */
    sbi_ecall(SBI_EXT_SRST, 0, 0, 0, 0, 0, 0, 0);
    /* Fallback to shutdown */
    arch_cpu_shutdown();
}

/*
 * Interrupt control
 */
void arch_irq_enable(void)
{
    __asm__ __volatile__(
        "csrsi sstatus, 0x2"    /* Set SIE bit */
        ::: "memory"
    );
}

void arch_irq_disable(void)
{
    __asm__ __volatile__(
        "csrci sstatus, 0x2"    /* Clear SIE bit */
        ::: "memory"
    );
}

bool arch_irq_save(void)
{
    unsigned long sstatus;
    __asm__ __volatile__(
        "csrrc %0, sstatus, 0x2"    /* Read and clear SIE */
        : "=r"(sstatus)
        :: "memory"
    );
    return (sstatus & 0x2) != 0;
}

void arch_irq_restore(bool state)
{
    if (state) {
        arch_irq_enable();
    }
}

bool arch_irq_enabled(void)
{
    unsigned long sstatus;
    __asm__ __volatile__(
        "csrr %0, sstatus"
        : "=r"(sstatus)
    );
    return (sstatus & 0x2) != 0;
}

/*
 * CPU identification
 */
int arch_cpu_id(void)
{
    unsigned long tp;
    __asm__ __volatile__("mv %0, tp" : "=r"(tp));
    return (int)tp;
}

/*
 * Debug support
 */
void arch_breakpoint(void)
{
    __asm__ __volatile__("ebreak");
}

/*
 * SMP Support - Inter-Processor Interrupts
 */

/**
 * arch_send_ipi - Send IPI to specific CPU
 * @cpu: Target CPU ID (hart ID)
 * @type: IPI type (IPI_RESCHEDULE, IPI_CALL, IPI_STOP)
 */
void arch_send_ipi(int cpu, int type)
{
    (void)type;  /* All IPIs trigger software interrupt for now */

    /* Create hart mask with single bit set for target CPU */
    unsigned long hart_mask = 1UL << cpu;

    sbi_ecall(SBI_EXT_IPI, SBI_IPI_SEND, hart_mask, 0, 0, 0, 0, 0);
}

/**
 * arch_send_ipi_all - Send IPI to all other CPUs
 * @type: IPI type
 */
void arch_send_ipi_all(int type)
{
    (void)type;

    /* Send to all harts except self */
    unsigned long self = arch_cpu_id();
    unsigned long hart_mask = ~(1UL << self);

    sbi_ecall(SBI_EXT_IPI, SBI_IPI_SEND, hart_mask, 0, 0, 0, 0, 0);
}

/*
 * SMP Support - CPU Bring-up
 */

/* Secondary CPU entry point (defined in boot.S) */
extern void _secondary_start(void);

/* Number of online CPUs */
static int num_cpus = 1;

/**
 * arch_cpu_count - Get number of online CPUs
 */
int arch_cpu_count(void)
{
    return num_cpus;
}

/**
 * arch_start_cpu - Start a secondary CPU
 * @cpu: CPU ID (hart ID) to start
 * @start_addr: Entry point address
 * @opaque: Opaque value passed to the CPU (stored in a1)
 *
 * Returns 0 on success, negative on error.
 */
int arch_start_cpu(int cpu, unsigned long start_addr, unsigned long opaque)
{
    struct sbi_ret ret;

    ret = sbi_ecall(SBI_EXT_HSM, SBI_HSM_HART_START,
                    cpu, start_addr, opaque, 0, 0, 0);

    if (ret.error == 0) {
        num_cpus++;
        return 0;
    }

    return (int)ret.error;
}

/**
 * arch_cpu_status - Get CPU status
 * @cpu: CPU ID to query
 *
 * Returns: 0 = STARTED, 1 = STOPPED, 2 = START_PENDING, 3 = STOP_PENDING
 */
int arch_cpu_status(int cpu)
{
    struct sbi_ret ret;

    ret = sbi_ecall(SBI_EXT_HSM, SBI_HSM_HART_STATUS, cpu, 0, 0, 0, 0, 0);

    return (int)ret.value;
}

/**
 * arch_cpu_init - Initialize current CPU
 * @cpu_id: This CPU's ID
 *
 * Called early during CPU bring-up.
 */
void arch_cpu_init(int cpu_id)
{
    /* Store CPU ID in tp register for arch_cpu_id() */
    __asm__ __volatile__("mv tp, %0" :: "r"(cpu_id));
}
