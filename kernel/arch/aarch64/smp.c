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
static int psci_conduit_cached = -1;
static bool psci_trampoline_ready;
static bool psci_fallback_logged;

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

static int psci_prepare_trampoline(void) {
    if (psci_trampoline_ready)
        return 0;

    paddr_t start = ALIGN_DOWN(virt_to_phys((void *)_secondary_start_psci),
                               CONFIG_PAGE_SIZE);
    paddr_t end = ALIGN_UP(virt_to_phys((void *)_secondary_start_psci_end),
                           CONFIG_PAGE_SIZE);
    paddr_t pgdir = arch_mmu_get_kernel_pgdir();

    for (paddr_t pa = start; pa < end; pa += CONFIG_PAGE_SIZE) {
        int rc = arch_mmu_map_merge(pgdir, (vaddr_t)pa, pa,
                                    PTE_READ | PTE_EXEC | PTE_GLOBAL);
        if (rc < 0 && rc != -EEXIST)
            return rc;
    }

    arch_mmu_flush_tlb_all();
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

    psci_ctx[cpu].cpu_id = opaque;
    psci_ctx[cpu].tcr_el1 = tcr;
    psci_ctx[cpu].mair_el1 = mair;
    psci_ctx[cpu].ttbr0_el1 = ttbr1;
    psci_ctx[cpu].ttbr1_el1 = ttbr1;
    psci_ctx[cpu].sctlr_el1 = sctlr;
    psci_ctx[cpu].target_va = start_addr;
    __asm__ __volatile__("dsb ishst" ::: "memory");

    enum psci_conduit conduit = psci_detect_conduit(bi);
    paddr_t entry_pa = virt_to_phys((void *)_secondary_start_psci);
    paddr_t ctx_pa = virt_to_phys(&psci_ctx[cpu]);
    int32_t psci_rc = psci_cpu_on(conduit, bi->cpus[cpu].hw_id, entry_pa, ctx_pa);

    if (!psci_fallback_logged) {
        psci_fallback_logged = true;
        pr_info("SMP: aarch64 fallback start via PSCI (%s) entry=%p\n",
                psci_conduit_name(conduit), (void *)entry_pa);
    }
    pr_info("SMP: PSCI CPU_ON cpu=%d hwid=%p rc=%d\n",
            cpu, (void *)bi->cpus[cpu].hw_id, psci_rc);
    return (int)psci_rc;
}
