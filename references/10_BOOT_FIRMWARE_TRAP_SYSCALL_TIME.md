# 10 — Boot / Firmware / Trap / Syscall / Time

## Boot Sequence

All three architectures share the same path:

1. `arch/<arch>/boot.S:_start` — set up stack, zero BSS
   - riscv64 explicitly disables interrupts (csrw sie, zero); x86_64 has no explicit cli
   - aarch64 additionally handles EL2→EL1 drop and system register initialization
2. `boot/limine.c:limine_bootstrap()` — parse Limine protocol responses, populate boot_info (memory map, DTB, RSDP, framebuffer, CPU list, etc.)
3. `arch_cpu_init()` — BSP CPU initialization
4. `core/main.c:kernel_main()` — main initialization sequence:
   - init_boot → init_mm → syscall_init → arch_trap_init → tick_policy_init → arch_timer_init(100) → sched_init → proc_init → futex_init → proc_idle_init → init_devices → init_net → init_fs → smp_init → init_user
5. SMP: smp_init() starts secondary CPUs one by one, each goes through `_secondary_start` → `secondary_cpu_main()` (arch_cpu_init → sched_init_cpu → sched_cpu_online → arch_trap_init → arch_timer_init(CONFIG_HZ) → proc_idle_init → enable interrupts → scheduling loop)

boot_info struct is defined in include/kairos/boot.h, accessed globally through boot/boot.c getters.

## Firmware

Two parsing paths, both ultimately register into the firmware descriptor table (core/dev/firmware.c):

- FDT path: init_boot() → firmware/fdt.c:fdt_parse() parses memory and reserved regions; init_devices() → fdt_scan_devices() scans device nodes → fw_register_desc() registers descriptors
- ACPI path: init_devices() → firmware/acpi.c:acpi_init() → probes RSDP and marks available (currently does not further parse XSDT/MCFG/MADT)

The firmware descriptor table is the intermediate layer for device discovery: firmware/ writes, bus/ reads and enumerates.

## Trap / Interrupt

Unified path: hardware interrupt/exception → trapasm.S saves context → arch trap.c → trap_core.c → return

Per-architecture entry:
- riscv64: stvec → trap_entry, switches to kernel stack via sscratch
- x86_64: IDT → isr_common (syscall goes through IDT 0x80), switches to kernel stack via TSS
- aarch64: VBAR_EL1 → vector_table, distinguishes EL0/EL1 origin

trap_core.c:trap_core_dispatch() is the architecture-independent dispatch boundary:
- Saves current trap frame to per-CPU current_tf
- Calls architecture handle_event() (dispatches to interrupt handler / exception handler / syscall)
- Delivers pending signals
- Restores per-CPU current_tf

Interrupt controllers: riscv64 uses PLIC, x86_64 uses LAPIC+IOAPIC, aarch64 uses GIC.

## Syscall

Path: userspace trap instruction → trapasm.S → arch trap.c identifies as syscall → syscall_dispatch()

- riscv64: ecall instruction, syscall number in a7, args a0-a5
- x86_64: int 0x80, syscall number in rax, args rdi/rsi/rdx/r10/r8/r9
- aarch64: svc #0, syscall number in x8, args x0-x5

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

BSP timer frequency is hardcoded to 100Hz (arch_timer_init(100)); secondary CPUs use CONFIG_HZ. tick_policy_init() designates the timekeeper CPU.

Related references:
- references/00_REPO_MAP.md
- references/20_MEMORY.md
- references/30_PROCESS_SCHED_SYNC_IPC.md
