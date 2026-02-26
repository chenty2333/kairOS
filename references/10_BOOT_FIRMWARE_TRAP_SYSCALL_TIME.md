# 10 — Boot / Firmware / Trap / Syscall / Time

## Boot Sequence

All three architectures share the same path:

1. `arch/<arch>/boot.S:_start` — set up stack, zero BSS
   - riscv64 explicitly disables interrupts (csrw sie, zero); x86_64 has no explicit cli
   - aarch64 additionally handles EL2→EL1 drop and system register initialization
2. `boot/limine.c:limine_bootstrap()` — parse Limine protocol responses, populate boot_info (memory map, DTB, RSDP, framebuffer, CPU list, etc.)
   - kernel currently requests Limine protocol base revision `5` (`LIMINE_BASE_REVISION(5)`) and fails fast if unsupported
   - kernel records loaded base revision (`LIMINE_LOADED_BASE_REVISION`) when provided by bootloader and surfaces it in stable boot logs
   - Limine memmap type `LIMINE_MEMMAP_RESERVED_MAPPED` is treated as `BOOT_MEM_RESERVED` (legacy `LIMINE_MEMMAP_ACPI_TABLES` remains compatibility-mapped to `BOOT_MEM_ACPI_RECLAIM` when present)
   - aarch64 fallback: when Limine MP reports only BSP, `boot_init_limine()` reads DTB `/cpus` to populate CPU topology metadata (`boot_info.cpu_count` / `cpus[].hw_id`)
   - boot path now validates and logs Limine `firmware_type`, `paging_mode`, and MP `revision/flags`; mismatch vs requested constraints triggers early panic (fail-fast)
   - boot path now fail-fasts on malformed critical descriptors (missing/empty memmap, null memmap entries, memmap range overflow, missing MP CPU array/entries)
   - Limine `date_at_boot` and `bootloader_performance` are recorded into `boot_info` when available
   - Limine `executable_file` metadata (`path/string/media_type/partition_index`) is recorded into `boot_info` for boot-media diagnostics
   - Limine `smbios` and `efi_memmap` descriptors are recorded into `boot_info` when available; malformed EFI memmap descriptors (non-zero size with null memmap pointer, or zero descriptor size) trigger early panic
   - riscv64 additionally records Limine `riscv_bsp_hartid`; mismatch vs MP-reported BSP hartid triggers early panic
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
- Console UART discovery path: arch console init calls `fdt_get_stdout_uart()` to resolve UART MMIO base/IRQ from `/chosen/stdout-path` (with `/aliases` and interrupt spec parsing), falling back to arch defaults if unresolved
- FDT IRQ translation now records interrupt-controller nodes (`phandle`, `#interrupt-cells`, `interrupt-parent`) and binds the root controller phandle to the root irq_domain; device `interrupts` / `interrupts-extended` specs are mapped via parent-phandle-aware domain lookup before root fallback
- ACPI path: init_devices() → firmware/acpi.c:acpi_init() probes RSDP and marks available; on aarch64, pci_enumerate() → arch/aarch64/pci.c:arch_pci_host_init() further parses RSDP → XSDT/RSDT → MCFG to discover PCI ECAM

The firmware descriptor table is the intermediate layer for device discovery: firmware/ writes, bus/ reads and enumerates.

## Trap / Interrupt

Unified path: hardware interrupt/exception → trapasm.S saves context → arch trap.c → trap_core.c → return

Per-architecture entry:
- riscv64: stvec → trap_entry, switches to kernel stack via sscratch
  - trap_return keeps `sscratch=0` when returning to S-mode, and sets `sscratch` to kernel stack top only for U-mode return
- x86_64: IDT → isr_common (syscall goes through IDT 0x80), switches to kernel stack via TSS
  - x86_64 `#PF` first routes user-range faults through `mm_handle_fault()` (write/exec intent decoded from PF error bits) for both user and kernel origins; unresolved kernel faults then consult `search_exception_table(rip)` for uaccess fixup
  - x86_64 uaccess assembly emits `__ex_table` fixups for `copy_from_user` / `copy_to_user` / `strncpy_from_user`; fixup returns remaining bytes for copy helpers and `-EFAULT` for string copy
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
- IRQ core now uses per-IRQ descriptors (`irq_desc`) instead of a single handler slot:
  - each IRQ keeps an action list (shared IRQ capable), trigger/per-cpu flags, enable refcount, and dispatch counters
  - supports deferred/threaded handler mode via `IRQ_FLAG_DEFERRED` (hard IRQ path queues action, `irqd` kthread runs deferred handlers)
  - `arch_irq_enable_nr()` / `arch_irq_disable_nr()` now apply chip operations with refcount semantics (and per-CPU semantics for PPIs/local timer IRQs)
  - `irqchip_ops` includes `set_type(int irq, uint32_t type)` so trigger mode is configured from IRQ flags when enabling
  - `irqchip_ops` now includes `set_affinity(int irq, uint32_t cpu_mask)` and IRQ core stores per-IRQ CPU mask (default CPU0) for route programming hooks
  - IRQ action lifecycle now supports explicit unregister (`platform_irq_unregister_ex` / `platform_irq_unregister`) with safe detach from dispatch/deferred paths
  - driver-facing managed lifecycle is available via `arch_request_irq*` / `arch_free_irq*` (`platform_irq_request*` / `platform_irq_free*`): request path registers + optional auto-enable, free path unregisters + matched auto-disable by action ownership
  - IRQ free/unregister is now idempotent and reclaim-safe under concurrency (action detaches immediately, object reclaim completes once in-flight refs drain)
  - sync teardown variants are available (`arch_free_irq*_sync` / `platform_irq_free*_sync`) to wait for in-flight handler completion before returning
  - cookie-based lifecycle is available (`arch_request_irq*_cookie`, `arch_free_irq_cookie*`; platform equivalents) so drivers can release by opaque handle instead of `(irq, handler, arg)` tuple matching
  - IRQ core now includes a linear `irq_domain` layer (`hwirq -> virq` mapping); trap paths dispatch by `platform_irq_dispatch_hwirq(chip, hwirq, ...)`, while drivers keep using virq
  - `irq_domain` manager now uses dynamic domain objects (linked list + parent/child links), removing the previous fixed-slot limit
  - `irq_domain` now supports auto-allocated virq ranges (`platform_irq_domain_alloc_linear` / `IRQ_DOMAIN_AUTO_VIRQ`) for child/cascaded controllers
  - `irq_domain` mapping is no longer linear-only: mapped domains can provide custom callbacks (`platform_irq_domain_add/alloc_mapped*`) for sparse/non-linear `hwirq <-> virq` translation
  - `irq_domain` now supports firmware-node (`phandle`) bindings and mapping/dispatch (`platform_irq_domain_*_fwnode`) so cascaded controllers can resolve IRQs in per-controller namespaces
  - cascaded child domains can be chained to a parent virq via `platform_irq_domain_set_cascade(...)` (generic virq entry) or `platform_irq_domain_set_cascade_fwnode(...)`; IRQ core wires a shared parent action and tracks child-active refcount to auto-enable/disable the parent line
  - cascaded links can be explicitly detached (`platform_irq_domain_unset_cascade*`) and domains can be removed (`platform_irq_domain_remove*`) once handlers are quiesced
  - `platform_irq_domain_setup_cascade(...)` provides one-step generic child-domain bring-up (`alloc domain + chain parent irq`)
  - `platform_irq_domain_setup_cascade_fwnode(...)` provides one-step child-domain bring-up (`alloc domain + chain parent irq`) for cascaded irqchip drivers
  - mapped cascades are also supported (`platform_irq_domain_setup_cascade_mapped*`) so child controllers can combine parent chaining with custom hwirq mapping
  - FDT device scan now enumerates cascaded `interrupt-controller` nodes as platform devices (with parent IRQ resource + `platform_device_info.fwnode`), enabling firmware-described cascaded irqchip drivers to hook directly into the generic cascade core
  - root domain coverage is now board-configurable (`platform_desc.irqchip_root_irqs`) so root mappings no longer have to occupy the full global virq space
  - `arch_irq_enable_nr()` / `arch_irq_disable_nr()` / set_type / set_affinity now program irqchips with descriptor `hwirq`, not virq
  - `platform_irq_dispatch()` now gates handlers on IRQ enable refcount; disabled IRQs no longer dispatch actions
  - `IRQ_FLAG_NO_CHIP` marks software/local IRQ lines that should use refcount gating without programming irqchip enable/disable paths
  - IRQ observability now exports per-IRQ `enable/disable/dispatch` totals plus `in_flight`, `retired_pending`, and `last_cpu` alongside current enable refcount/action count via `platform_irq_format_stats()`; procfs exposes this as `/proc/interrupts`
- affinity routing details:
  - riscv64 PLIC now supports `set_affinity`: it updates per-hart enable bits for each IRQ and reroutes already-enabled IRQs
  - aarch64 GICv3 routes SPIs using CPU `hw_id` (MPIDR affinity bits) in `GICD_IROUTER`
  - x86 IOAPIC destination uses APIC IDs derived from boot CPU `hw_id`

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
  - `platform_desc.timer` (`timer_ops`) is now wired in; timer registration/dispatch resolves timer virq via `platform_timer_irq()` and timer-trap paths use `platform_timer_dispatch()`
  - timer IRQs are registered into IRQ core and dispatched through the common IRQ action path (`platform_irq_dispatch`), then timer handlers call `tick_policy_on_timer_irq()`

- Core layer:
  - core/time/tick.c — tick_policy_on_timer_irq() handles timer interrupts, drives scheduler time slices (sched_tick), keeps console poll as fallback, handles poll sleep expiry
  - Console input wakeup path is IRQ-first: `console_tty_driver_init()` calls `arch_console_input_init()`, which resolves UART config from FDT when available and registers RX IRQ handlers that trigger `console_poll_input()` immediately; `tty_receive_buf()` then wakes sleepers on `tty->read_wait`
  - core/time/time.c — system time management (wall clock, monotonic time, nanosecond-precision timer queue)
  - Linux sleep ABI compatibility:
    - `nanosleep` on `EINTR` now fills remaining time (`rem`) when provided
    - `clock_nanosleep` supports both relative sleep and `TIMER_ABSTIME` absolute deadlines
    - `clock_nanosleep` decodes `flags` using Linux ABI width (`int`/32-bit)
    - `clock_gettime`/`clock_settime`/`clock_getres`/`clock_nanosleep` decode `clockid` using Linux ABI width (`clockid_t`/32-bit int)
    - `getitimer`/`setitimer` decode `which` using Linux ABI width (`int`/32-bit)
    - `clock_nanosleep` accepts `CLOCK_BOOTTIME` and `CLOCK_TAI`; `CLOCK_TAI` absolute deadlines are converted to realtime base using the current in-kernel TAI offset
    - `CLOCK_REALTIME` is implemented as `CLOCK_MONOTONIC + realtime_offset`; `clock_settime(CLOCK_REALTIME, ...)` updates this offset while `CLOCK_MONOTONIC` remains non-settable; `clock_settime(CLOCK_TAI, ...)` updates user-adjustable TAI delta relative to the in-kernel UTC->TAI leap table baseline
    - `clock_gettime`/`clock_getres` accept Linux alias clock IDs (`*_COARSE`, `CLOCK_MONOTONIC_RAW`, `CLOCK_BOOTTIME`, `*_ALARM`, `CLOCK_TAI`) with distinct source semantics: `CLOCK_MONOTONIC_RAW` uses raw arch timer ticks, `*_COARSE` clocks return quantized values on scheduler-tick granularity, and `CLOCK_TAI` reports `CLOCK_REALTIME + (leap-table baseline + user delta)` with current default baseline +37s (post-2017); CPU clocks (`CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID`) come from scheduler accounting
    - `clock_nanosleep(TIMER_ABSTIME)` re-checks current time by `clockid` after wakeups, so absolute `CLOCK_REALTIME` sleeps track runtime realtime adjustments
    - zero-duration sleep (`tv_sec=0,tv_nsec=0`) returns immediately instead of sleeping one tick

BSP timer frequency is hardcoded to 100Hz (arch_timer_init(100)); secondary CPUs use CONFIG_HZ. `tick_policy_init()` designates the initial timekeeper CPU, and tick policy can hand over timekeeper duty when the original CPU stops receiving timer IRQs for an extended interval. Timekeeper ownership is tracked as `owner+epoch` and migrated via atomic single-winner CAS so only one CPU commits each handover; heartbeat/epoch-start markers are epoch-tagged to separate old/new owner state cleanly. Migration requires stalled-owner + lease expiry + minimum residency windows (all normalized by online CPU count against global IRQ sequence) to reduce short-term oscillation. Migration WARN logging is gated until all CPUs are online and a post-online warmup has elapsed, then rate-limited and focused on frequent repeated handovers to suppress startup noise.

Related references:
- references/00_REPO_MAP.md
- references/20_MEMORY.md
- references/30_PROCESS_SCHED_SYNC_IPC.md
