# 11 — Trap / Interrupt

Part of the boot/trap/syscall/time subsystem. See also:
- 10_BOOT_FIRMWARE.md — Boot and firmware path
- 12_SYSCALL.md — Syscall entry path
- 13_TIME.md — Timer interrupt and timekeeping path

## Trap / Interrupt

Unified path: hardware interrupt/exception → trapasm.S saves context → arch trap.c → trap_core.c → return

Per-architecture entry:
- riscv64: stvec → trap_entry, switches to kernel stack via sscratch
  - trap_return keeps `sscratch=0` when returning to S-mode, and sets `sscratch` to kernel stack top only for U-mode return
- x86_64: IDT → isr_common (syscall goes through IDT 0x80), switches to kernel stack via TSS
  - x86_64 `#PF` first routes user-range faults through `mm_handle_fault()` (write/exec intent decoded from PF error bits) for both user and kernel origins; unresolved kernel faults then consult `search_exception_table(rip)` for uaccess fixup
  - x86_64 uaccess assembly emits `__ex_table` fixups for `copy_from_user` / `copy_to_user` / `strncpy_from_user`; fixup returns remaining bytes for copy helpers and `-EFAULT` for string copy
  - x86_64 `get_current_trapframe()` now validates that `current_tf` / process `active_tf` lies inside the current process kernel stack range before use; mismatched stale process-scoped trapframe pointers are dropped
- aarch64: VBAR_EL1 → vector_table, distinguishes EL0/EL1 origin

trap_core.c:trap_core_dispatch() is the architecture-independent dispatch boundary:
- Saves current trap frame to per-CPU current_tf
- Mirrors current trap frame into process-scoped `active_tf` while dispatch is in progress, so trapframe-dependent paths remain valid even if syscall paths sleep/yield and CPU-local `current_tf` changes
- Calls architecture handle_event() (dispatches to interrupt handler / exception handler / syscall)
- Delivers pending signals
- Restores per-CPU current_tf and process-scoped `active_tf`
- Process allocation/free paths initialize and clear `process.active_tf` to prevent stale trapframe reuse across recycled process slots
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
  - sync teardown variants are available (`arch_free_irq*_sync` / `platform_irq_free*_sync`) to wait for in-flight handler completion before returning, including actions already detached into retired lists by an earlier async free/unregister; concurrent sync waiters on the same action are coalesced safely
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
  - `arch_irq_set_type()` / `arch_irq_set_affinity()` now return `int`: invalid input is reported to callers, and when IRQ is enabled the irqchip callback error is propagated instead of being silently ignored
  - `platform_irq_dispatch()` now gates handlers on IRQ enable refcount; disabled IRQs no longer dispatch actions
  - `IRQ_FLAG_NO_CHIP` marks software/local IRQ lines that should use refcount gating without programming irqchip enable/disable paths
  - IRQ observability now exports per-IRQ `enable/disable/dispatch` totals plus `in_flight`, `retired_pending`, and `last_cpu` alongside current enable refcount/action count via `platform_irq_format_stats()`
  - `/proc/interrupts` now uses a per-CPU dispatch view (`CPU0..CPUn` columns) via `platform_irq_format_proc_interrupts()`, and still includes per-IRQ aggregate fields (dispatch total / enable-disable totals / flags / affinity / last_cpu)
- affinity routing details:
  - riscv64 PLIC now supports `set_affinity`: it updates per-hart enable bits for each IRQ and reroutes already-enabled IRQs
  - aarch64 GICv3 routes SPIs using CPU `hw_id` (MPIDR affinity bits) in `GICD_IROUTER`
  - x86 IOAPIC destination uses APIC IDs derived from boot CPU `hw_id`


Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE.md
- references/12_SYSCALL.md
- references/13_TIME.md
- references/30_PROCESS.md
- references/31_SCHEDULER.md
- references/50_DRIVERS_BUS_DISCOVERY.md
