# 10 — Boot / Firmware / Trap / Syscall / Time

## Boot Sequence

All three architectures share the same path:

1. `arch/<arch>/boot.S:_start` — set up stack, zero BSS
   - riscv64 explicitly disables interrupts (csrw sie, zero); x86_64 has no explicit cli
   - aarch64 additionally handles EL2→EL1 drop and system register initialization
2. `boot/limine.c:limine_bootstrap()` — parse Limine protocol responses, populate boot_info (memory map, DTB, RSDP, framebuffer, CPU list, etc.)
   - kernel currently requests Limine protocol base revision `5` (`LIMINE_BASE_REVISION(5)`) and fails fast if unsupported
   - Limine memmap type `LIMINE_MEMMAP_RESERVED_MAPPED` is treated as `BOOT_MEM_RESERVED` (legacy `LIMINE_MEMMAP_ACPI_TABLES` remains compatibility-mapped to `BOOT_MEM_ACPI_RECLAIM` when present)
   - aarch64 fallback: when Limine MP reports only BSP, `boot_init_limine()` reads DTB `/cpus` to populate CPU topology metadata (`boot_info.cpu_count` / `cpus[].hw_id`)
   - boot path now validates and logs Limine `firmware_type`, `paging_mode`, and MP `revision/flags`; mismatch vs requested constraints triggers early panic (fail-fast)
   - Limine `date_at_boot` and `bootloader_performance` are recorded into `boot_info` when available
3. `arch_cpu_init()` — BSP CPU initialization
4. `core/main.c:kernel_main()` — main initialization sequence:
   - init_boot → init_mm → syscall_init → arch_trap_init → tick_policy_init → arch_timer_init(100) → sched_init → proc_init → futex_init → proc_idle_init → init_devices → init_net → init_fs → smp_init → init_user
5. SMP: smp_init() starts secondary CPUs one by one, each goes through `_secondary_start` → `secondary_cpu_main()` (arch_cpu_init → sched_init_cpu → sched_cpu_online → arch_trap_init → arch_timer_init(CONFIG_HZ) → proc_idle_init → enable interrupts → scheduling loop)
   - aarch64 fallback start path: if `mp_info` is missing, `arch_start_cpu()` falls back to PSCI `CPU_ON` using DTB MPIDR (`cpus[].hw_id`)
   - aarch64 PSCI fallback retries once with alternate conduit (`smc`/`hvc`) when initial `CPU_ON` returns `NOT_SUPPORTED`
   - aarch64 treats PSCI `ALREADY_ON` / `ON_PENDING` as accepted start request (normalized to success for SMP bring-up flow)
   - aarch64 keeps a low-VA identity alias for kernel image so PSCI-started AP can safely enable MMU while executing from PA
   - aarch64 Limine MP path now synchronizes AP early EL1 register context (`MAIR_EL1/TCR_EL1/TTBR0_EL1/TTBR1_EL1/SCTLR_EL1`) from BSP snapshot before entering C, preventing AP-side register drift during bring-up
   - failed AP bring-up is logged explicitly as `SMP: cpuX start failed rc=<errno>`
   - when an AP start request succeeds but CPU never reaches `secondary_cpu_main()`, kernel logs `SMP: cpuX did not reach online state` plus arch debug marker
   - SMP summary now reports discovered topology total (`SMP: online/total CPUs active`) and emits `online shortfall` when APs fail to come online

boot_info struct is defined in include/kairos/boot.h, accessed globally through boot/boot.c getters.

## Firmware

Two parsing paths, both ultimately register into the firmware descriptor table (core/dev/firmware.c):

- FDT path: init_boot() → firmware/fdt.c:fdt_parse() parses memory and reserved regions; init_devices() → fdt_scan_devices() scans device nodes → fw_register_desc() registers descriptors
- ACPI path: init_devices() → firmware/acpi.c:acpi_init() probes RSDP and marks available; on aarch64, pci_enumerate() → arch/aarch64/pci.c:arch_pci_host_init() further parses RSDP → XSDT/RSDT → MCFG to discover PCI ECAM

The firmware descriptor table is the intermediate layer for device discovery: firmware/ writes, bus/ reads and enumerates.

## Trap / Interrupt

Unified path: hardware interrupt/exception → trapasm.S saves context → arch trap.c → trap_core.c → return

Per-architecture entry:
- riscv64: stvec → trap_entry, switches to kernel stack via sscratch
  - trap_return keeps `sscratch=0` when returning to S-mode, and sets `sscratch` to kernel stack top only for U-mode return
- x86_64: IDT → isr_common (syscall goes through IDT 0x80), switches to kernel stack via TSS
- aarch64: VBAR_EL1 → vector_table, distinguishes EL0/EL1 origin

trap_core.c:trap_core_dispatch() is the architecture-independent dispatch boundary:
- Saves current trap frame to per-CPU current_tf
- Mirrors current trap frame into process-scoped `active_tf` while dispatch is in progress, so trapframe-dependent paths remain valid even if syscall paths sleep/yield and CPU-local `current_tf` changes
- Calls architecture handle_event() (dispatches to interrupt handler / exception handler / syscall)
- Delivers pending signals
- Restores per-CPU current_tf and process-scoped `active_tf`
- RISC-V page-fault diagnostics now log unresolved fault context with `pid/comm/sepc/fault-addr/access-type` before signal/panic path, and MM fault logs include the same context.

Interrupt controllers: riscv64 uses PLIC, x86_64 uses LAPIC+IOAPIC, aarch64 uses GIC.
- aarch64 GICv3 now selects Redistributor frame per CPU (`arch_cpu_id`) for local SGI/PPI enable/disable paths.

## Syscall

Path: userspace trap instruction → trapasm.S → arch trap.c identifies as syscall → syscall_dispatch()

- riscv64: ecall instruction, syscall number in a7, args a0-a5
- x86_64: int 0x80, syscall number in rax, args rdi/rsi/rdx/r10/r8/r9
- aarch64: svc #0, syscall number in x8, args x0-x5
- Linux `clone` ABI argument order differs by architecture:
  - x86_64: `(flags, newsp, ptid, ctid, tls)`
  - riscv64/aarch64: `(flags, newsp, ptid, tls, ctid)`

syscall_dispatch() (core/syscall/syscall.c):
- Checks process ABI flag
- Linux ABI: maps through linux_syscalls.def X-macro expansion to sys_*()
- Kairos ABI: direct syscall_table[] lookup
- Return value written back to trap frame return register

Syscall implementations are split by subsystem in core/syscall/sys_*.c.

## Time

Two-layer structure:

- Architecture layer: arch/<arch>/timer.c handles hardware timer configuration and interrupts
  - riscv64: SBI timer (stimecmp)
  - x86_64: LAPIC timer (PIT-calibrated, configured as periodic mode)
  - aarch64: ARM generic physical timer (CNTP, cntp_tval_el0)
  - On interrupt, calls tick_policy_on_timer_irq()

- Core layer:
  - core/time/tick.c — tick_policy_on_timer_irq() handles timer interrupts, drives scheduler time slices (sched_tick), polls console input, handles poll sleep expiry
  - core/time/time.c — system time management (wall clock, monotonic time, nanosecond-precision timer queue)
  - Linux sleep ABI compatibility:
    - `nanosleep` on `EINTR` now fills remaining time (`rem`) when provided
    - `clock_nanosleep` supports both relative sleep and `TIMER_ABSTIME` absolute deadlines
    - `clock_nanosleep` decodes `flags` using Linux ABI width (`int`/32-bit)
    - `clock_gettime`/`clock_settime`/`clock_getres`/`clock_nanosleep` decode `clockid` using Linux ABI width (`clockid_t`/32-bit int)
    - `getitimer`/`setitimer` decode `which` using Linux ABI width (`int`/32-bit)
    - `clock_nanosleep` accepts `CLOCK_BOOTTIME` and `CLOCK_TAI`; `CLOCK_TAI` absolute deadlines are converted to realtime base using the current in-kernel TAI offset
    - `CLOCK_REALTIME` is implemented as `CLOCK_MONOTONIC + realtime_offset`; `clock_settime(CLOCK_REALTIME, ...)` updates this offset while `CLOCK_MONOTONIC` remains non-settable; `clock_settime(CLOCK_TAI, ...)` updates user-adjustable TAI delta relative to the in-kernel UTC->TAI leap table baseline
    - `clock_gettime`/`clock_getres` accept Linux alias clock IDs (`*_COARSE`, `CLOCK_MONOTONIC_RAW`, `CLOCK_BOOTTIME`, `*_ALARM`, `CLOCK_TAI`) on current realtime/monotonic sources; `CLOCK_TAI` reports `CLOCK_REALTIME + (leap-table baseline + user delta)` with current default baseline +37s (post-2017), plus CPU clocks (`CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID`) from scheduler accounting
    - `clock_nanosleep(TIMER_ABSTIME)` re-checks current time by `clockid` after wakeups, so absolute `CLOCK_REALTIME` sleeps track runtime realtime adjustments
    - zero-duration sleep (`tv_sec=0,tv_nsec=0`) returns immediately instead of sleeping one tick

BSP timer frequency is hardcoded to 100Hz (arch_timer_init(100)); secondary CPUs use CONFIG_HZ. tick_policy_init() designates the timekeeper CPU.

Related references:
- references/00_REPO_MAP.md
- references/20_MEMORY.md
- references/30_PROCESS_SCHED_SYNC_IPC.md
