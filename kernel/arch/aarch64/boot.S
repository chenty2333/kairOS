/**
 * kernel/arch/aarch64/boot.S - AArch64 kernel entry point (Limine)
 *
 * Handles EL2→EL1 transition, early system register init, BSS clear,
 * then jumps to limine_bootstrap.
 */

#include <kairos/config.h>

.section .text.boot
.global _start
.global _secondary_start
.global _secondary_start_psci
.global _secondary_start_psci_end
.extern aarch64_mp_info_raw_ptrs
.extern aarch64_mp_info_virt_ptrs
.extern aarch64_mp_info_ptr_count

#define PSCI_CTX_CPU_ID   8
#define PSCI_CTX_TCR      16
#define PSCI_CTX_MAIR     24
#define PSCI_CTX_TTBR0    32
#define PSCI_CTX_TTBR1    40
#define PSCI_CTX_SCTLR    48
#define PSCI_CTX_TARGET   56

/*
 * Macro: drop from EL2 to EL1 if needed.
 * Clobbers x0, x1. On return we are guaranteed EL1h.
 */
.macro DROP_TO_EL1
    mrs x0, CurrentEL
    lsr x0, x0, #2          /* EL field is bits [3:2] */
    cmp x0, #2
    b.ne 90f                /* already EL1 (or EL0/EL3) */

    /* Configure EL1 to use AArch64 */
    mrs x1, hcr_el2
    orr x1, x1, #(1 << 31) /* HCR_EL2.RW = 1 (EL1 is AArch64) */
    msr hcr_el2, x1

    /* Return to EL1h with DAIF masked */
    mov x1, #0x3c5          /* EL1h | DAIF mask */
    msr spsr_el2, x1
    adr x1, 90f
    msr elr_el2, x1
    eret
90:
.endm

/*
 * Macro: early system register setup (must run at EL1).
 * Clobbers x0.
 */
.macro INIT_SYSREGS
    /*
     * Limine enters in higher-half VA space with paging already configured.
     * Do not clear SCTLR_EL1 here, otherwise execution falls out of mapped
     * VA ranges before we can reach C entry.
     */

    /* Force EL1 to use SP_EL1 (EL1h semantics), not SP_EL0. */
    mov x0, #1
    msr spsel, x0

    /* CPACR_EL1: FPEN=0b11 — no FP/SIMD traps */
    mov x0, #(3 << 20)
    msr cpacr_el1, x0

    /* Set early VBAR_EL1 so any exception before arch_trap_init() is caught */
    adrp x0, vector_table
    add  x0, x0, :lo12:vector_table
    msr vbar_el1, x0
    isb
.endm

_start:
    DROP_TO_EL1
    INIT_SYSREGS

    ldr x0, =_boot_stack_top
    mov sp, x0

    /* Clear BSS */
    ldr x0, =_bss_start
    ldr x1, =_bss_end
1:
    cmp x0, x1
    b.hs 2f
    str xzr, [x0], #8
    b 1b
2:

    bl limine_bootstrap

3:
    wfi
    b 3b

/* Secondary CPU entry (Limine MP) */
_secondary_start:
    /* x0 = struct limine_mp_info * (Limine) or cpu_id (PSCI context) */
    mov x19, x0
    DROP_TO_EL1
    INIT_SYSREGS

    /* Small x0 values are treated as direct cpu_id context. */
    mov x1, x19
    cmp x19, #CONFIG_MAX_CPUS
    b.lo 1f
    adrp x2, aarch64_mp_info_ptr_count
    add  x2, x2, :lo12:aarch64_mp_info_ptr_count
    ldr  w3, [x2]
    mov  w4, #0
    adrp x5, aarch64_mp_info_raw_ptrs
    add  x5, x5, :lo12:aarch64_mp_info_raw_ptrs
    adrp x6, aarch64_mp_info_virt_ptrs
    add  x6, x6, :lo12:aarch64_mp_info_virt_ptrs
8:
    cmp  w4, w3
    b.hs 9f
    ldr  x7, [x5, x4, lsl #3]
    cmp  x7, x19
    b.eq 10f
    ldr  x7, [x6, x4, lsl #3]
    cmp  x7, x19
    b.eq 10f
    add  w4, w4, #1
    b    8b
10:
    uxtw x1, w4
    b    1f
9:
    ldr x1, [x19, #40] /* extra_argument in aarch64 limine_mp_info */
1:
    mov x18, x1
    cmp x1, #CONFIG_MAX_CPUS
    b.hs 5f

    ldr x2, =_percpu_stacks
    mov x3, #CONFIG_KERNEL_STACK_SIZE
    madd x2, x1, x3, x2
    add x2, x2, x3
    mov sp, x2

    /* Stage marker: AP reached virtual secondary entry. */
    adrp x9, aarch64_secondary_entry_stage
    add  x9, x9, :lo12:aarch64_secondary_entry_stage
    lsl  x10, x1, #3
    add  x9, x9, x10
    mov  x11, #1
    str  x11, [x9]

    mov x0, x1
    bl secondary_cpu_main

5:
    wfi
    b 5b

4:
    wfi
    b 4b

/*
 * Secondary CPU entry (PSCI CPU_ON)
 * x0 = physical address of struct aarch64_psci_boot_ctx.
 */
_secondary_start_psci:
    mov x20, x0
    mov x9, #1
    str x9, [x20]
    DROP_TO_EL1

    ldr x1, [x20, #PSCI_CTX_CPU_ID]
    ldr x2, [x20, #PSCI_CTX_TCR]
    ldr x3, [x20, #PSCI_CTX_MAIR]
    ldr x4, [x20, #PSCI_CTX_TTBR0]
    ldr x5, [x20, #PSCI_CTX_TTBR1]
    ldr x6, [x20, #PSCI_CTX_SCTLR]
    ldr x7, [x20, #PSCI_CTX_TARGET]
    mov x9, #2
    str x9, [x20]

    msr mair_el1, x3
    msr tcr_el1, x2
    msr ttbr0_el1, x4
    msr ttbr1_el1, x5
    isb

    mov x9, #3
    str x9, [x20]
    /* Keep AP caches off during bring-up; avoids coherency issues before EL1 init. */
    bic x6, x6, #(1 << 2)   /* SCTLR_EL1.C */
    bic x6, x6, #(1 << 12)  /* SCTLR_EL1.I */
    msr sctlr_el1, x6
    isb

    mov x0, x1
    br x7

_secondary_start_psci_end:

.section .bss
.align 16
_boot_stack:
    .space 16384
_boot_stack_top:

.align 16
.global _percpu_stacks
_percpu_stacks:
    .space CONFIG_KERNEL_STACK_SIZE * CONFIG_MAX_CPUS
