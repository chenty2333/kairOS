# 13 — Time

Part of the boot/trap/syscall/time subsystem. See also:
- 10_BOOT_FIRMWARE.md — Boot and firmware path
- 11_TRAP_INTERRUPT.md — Trap and timer interrupt routing
- 12_SYSCALL.md — Time-related syscall entry

## Time

Two-layer structure:

- Architecture layer: arch/<arch>/timer.c handles hardware timer configuration and interrupts
  - riscv64: SBI timer (stimecmp)
  - x86_64: LAPIC timer (PIT-calibrated, configured as periodic mode)
  - aarch64: ARM generic physical timer (CNTP, cntp_tval_el0)
  - `platform_desc.timer` (`timer_ops`) is now wired in; timer registration/dispatch resolves timer virq via `platform_timer_irq()` and timer-trap paths use `platform_timer_dispatch()`
  - `platform_timer_dispatch()` now normalizes trap event tagging to `TRAP_CORE_EVENT_TIMER`, so timer handlers observe a consistent event type across architectures even when arch trap front-ends initially classify IRQs generically
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
- references/10_BOOT_FIRMWARE.md
- references/11_TRAP_INTERRUPT.md
- references/12_SYSCALL.md
- references/20_MEMORY.md
- references/31_SCHEDULER.md
- references/32_SYNC.md
- references/42_POLL_EPOLL.md
