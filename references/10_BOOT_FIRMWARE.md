# 10 — Boot / Firmware

Part of the boot/trap/syscall/time subsystem. See also:
- 11_TRAP_INTERRUPT.md — Trap and interrupt dispatch
- 12_SYSCALL.md — Syscall entry and ABI dispatch
- 13_TIME.md — Timer/tick/timekeeping

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


Related references:
- references/00_REPO_MAP.md
- references/11_TRAP_INTERRUPT.md
- references/12_SYSCALL.md
- references/13_TIME.md
- references/20_MEMORY.md
- references/30_PROCESS.md
- references/31_SCHEDULER.md
- references/33_IPC.md
- references/50_DRIVERS_BUS_DISCOVERY.md
