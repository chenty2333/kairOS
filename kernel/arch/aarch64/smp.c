/**
 * kernel/arch/aarch64/smp.c - AArch64 SMP fallback start path
 */

#include <kairos/arch.h>
#include <kairos/boot.h>
#include <kairos/config.h>
#include <kairos/fdt.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>

#define PSCI_CPU_ON_64 0xC4000003U
#define PSCI_RET_SUCCESS 0
#define PSCI_RET_NOT_SUPPORTED (-1)
#define PSCI_RET_ALREADY_ON (-4)
#define PSCI_RET_ON_PENDING (-5)

enum psci_conduit {
    PSCI_CONDUIT_HVC = 0,
    PSCI_CONDUIT_SMC = 1,
};

struct aarch64_psci_boot_ctx {
    uint64_t reserved0;
    uint64_t cpu_id;
    uint64_t tcr_el1;
    uint64_t mair_el1;
    uint64_t ttbr0_el1;
    uint64_t ttbr1_el1;
    uint64_t sctlr_el1;
    uint64_t target_va;
};

extern void _secondary_start_psci(void);
extern void _secondary_start_psci_end(void);

static struct aarch64_psci_boot_ctx psci_ctx[CONFIG_MAX_CPUS];
volatile uint64_t aarch64_secondary_entry_stage[CONFIG_MAX_CPUS];
volatile uintptr_t aarch64_mp_info_raw_ptrs[CONFIG_MAX_CPUS];
volatile uintptr_t aarch64_mp_info_virt_ptrs[CONFIG_MAX_CPUS];
volatile uint32_t aarch64_mp_info_ptr_count;
static int psci_conduit_cached = -1;
static bool psci_trampoline_ready;
static bool psci_fallback_logged;

static size_t dcache_line_size(void) {
    uint64_t ctr = 0;
    __asm__ __volatile__("mrs %0, ctr_el0" : "=r"(ctr));
    return 4UL << ((ctr >> 16) & 0xFUL);
}

static void dcache_clean_range(const void *addr, size_t len) {
    if (!addr || len == 0)
        return;
    size_t line = dcache_line_size();
    uintptr_t start = ALIGN_DOWN((uintptr_t)addr, line);
    uintptr_t end = ALIGN_UP((uintptr_t)addr + len, line);
    for (uintptr_t p = start; p < end; p += line)
        __asm__ __volatile__("dc cvac, %0" :: "r"(p) : "memory");
    __asm__ __volatile__("dsb ish" ::: "memory");
}

static const char *psci_conduit_name(enum psci_conduit conduit) {
    return (conduit == PSCI_CONDUIT_SMC) ? "smc" : "hvc";
}

static enum psci_conduit psci_detect_conduit(const struct boot_info *bi) {
    if (psci_conduit_cached >= 0)
        return (enum psci_conduit)psci_conduit_cached;

    char method[8] = { 0 };
    if (bi && bi->dtb &&
        fdt_get_psci_method(bi->dtb, method, sizeof(method)) == 0 &&
        strcmp(method, "smc") == 0) {
        psci_conduit_cached = PSCI_CONDUIT_SMC;
    } else {
        psci_conduit_cached = PSCI_CONDUIT_HVC;
    }
    return (enum psci_conduit)psci_conduit_cached;
}

static int32_t psci_cpu_on(enum psci_conduit conduit, uint64_t target_mpidr,
                           uint64_t entry_pa, uint64_t context_id) {
    register uint64_t x0 __asm__("x0") = PSCI_CPU_ON_64;
    register uint64_t x1 __asm__("x1") = target_mpidr;
    register uint64_t x2 __asm__("x2") = entry_pa;
    register uint64_t x3 __asm__("x3") = context_id;

    if (conduit == PSCI_CONDUIT_SMC) {
        __asm__ __volatile__("smc #0"
                             : "+r"(x0)
                             : "r"(x1), "r"(x2), "r"(x3)
                             : "x4", "x5", "x6", "x7", "x8", "x9",
                               "x10", "x11", "x12", "x13", "x14",
                               "x15", "x16", "x17", "cc", "memory");
    } else {
        __asm__ __volatile__("hvc #0"
                             : "+r"(x0)
                             : "r"(x1), "r"(x2), "r"(x3)
                             : "x4", "x5", "x6", "x7", "x8", "x9",
                               "x10", "x11", "x12", "x13", "x14",
                               "x15", "x16", "x17", "cc", "memory");
    }
    return (int32_t)x0;
}

static bool psci_request_accepted(int32_t rc) {
    return (rc == PSCI_RET_SUCCESS ||
            rc == PSCI_RET_ALREADY_ON ||
            rc == PSCI_RET_ON_PENDING);
}

static int psci_prepare_trampoline(void) {
    if (psci_trampoline_ready)
        return 0;
    psci_trampoline_ready = true;
    return 0;
}

int arch_start_cpu_fallback(int cpu, unsigned long start_addr,
                            unsigned long opaque,
                            const struct boot_info *bi) {
    if (!bi || cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        return -EINVAL;

    int rc = psci_prepare_trampoline();
    if (rc < 0)
        return rc;

    uint64_t tcr = 0;
    uint64_t mair = 0;
    uint64_t ttbr1 = 0;
    uint64_t sctlr = 0;
    __asm__ __volatile__("mrs %0, tcr_el1" : "=r"(tcr));
    __asm__ __volatile__("mrs %0, mair_el1" : "=r"(mair));
    __asm__ __volatile__("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    __asm__ __volatile__("mrs %0, sctlr_el1" : "=r"(sctlr));

    psci_ctx[cpu].reserved0 = 0;
    psci_ctx[cpu].cpu_id = opaque;
    psci_ctx[cpu].tcr_el1 = tcr;
    psci_ctx[cpu].mair_el1 = mair;
    psci_ctx[cpu].ttbr0_el1 = ttbr1;
    psci_ctx[cpu].ttbr1_el1 = ttbr1;
    psci_ctx[cpu].sctlr_el1 = sctlr;
    psci_ctx[cpu].target_va = start_addr;
    dcache_clean_range(&psci_ctx[cpu], sizeof(psci_ctx[cpu]));
    dcache_clean_range((const void *)_secondary_start_psci,
                       (size_t)((uintptr_t)_secondary_start_psci_end -
                                (uintptr_t)_secondary_start_psci));
    __asm__ __volatile__("dsb ishst" ::: "memory");

    enum psci_conduit conduit = psci_detect_conduit(bi);
    paddr_t entry_pa = virt_to_phys((void *)_secondary_start_psci);
    paddr_t ctx_pa = virt_to_phys(&psci_ctx[cpu]);
    int32_t psci_rc = psci_cpu_on(conduit, bi->cpus[cpu].hw_id, entry_pa, ctx_pa);
    bool retried = false;
    if (psci_rc == PSCI_RET_NOT_SUPPORTED) {
        enum psci_conduit alt =
            (conduit == PSCI_CONDUIT_SMC) ? PSCI_CONDUIT_HVC : PSCI_CONDUIT_SMC;
        int32_t alt_rc = psci_cpu_on(alt, bi->cpus[cpu].hw_id, entry_pa, ctx_pa);
        retried = true;
        if (psci_request_accepted(alt_rc)) {
            conduit = alt;
            psci_conduit_cached = (int)alt;
        }
        psci_rc = alt_rc;
    }
    int norm_rc;
    if (psci_rc == PSCI_RET_SUCCESS || psci_rc == PSCI_RET_ON_PENDING) {
        norm_rc = 0;
    } else if (psci_rc == PSCI_RET_ALREADY_ON) {
        norm_rc = -EALREADY;
    } else {
        norm_rc = (int)psci_rc;
    }

    if (!psci_fallback_logged) {
        psci_fallback_logged = true;
        pr_info("SMP: aarch64 fallback start via PSCI (%s) entry=%p\n",
                psci_conduit_name(conduit), (void *)entry_pa);
    }
    if (retried) {
        pr_warn("SMP: PSCI CPU_ON cpu=%d retried with conduit=%s\n",
                cpu, psci_conduit_name(conduit));
    }
    pr_info("SMP: PSCI CPU_ON cpu=%d hwid=0x%llx rc=%d norm=%d\n",
            cpu, (unsigned long long)bi->cpus[cpu].hw_id, psci_rc, norm_rc);
    return norm_rc;
}

uint64_t arch_cpu_start_debug(int cpu) {
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        return 0;
    return (psci_ctx[cpu].reserved0 << 32) |
           (aarch64_secondary_entry_stage[cpu] & 0xffffffffULL);
}
