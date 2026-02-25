# 91 — Test / CI Policy

## Testing

- `make test` — run kernel tests (default isolated mode, one run directory per invocation)
- `make test-exec-elf-smoke` — run interactive exec/ELF smoke regression (static/dynamic/PIE compile+run, PT_INTERP checks, bad-ELF rejection, fail on SIGSEGV/`no vma` markers)
- `make test-tcc-smoke` — compatibility alias of the exec/ELF smoke path
- `make test-busybox-applets-smoke` — run interactive BusyBox applet smoke regression (assert applet symlink/execution path for the enabled A-set and require `APPLET_SMOKE_OK:40`, `APPLET_BAD_COUNT:0`, `__BB_APPLET_SMOKE_DONE__`)
- `make test-errno-smoke` runs `/usr/bin/errno_smoke` inside guest; if `__ERRNO_SMOKE_DONE__` is not observed within `ERRNO_SMOKE_DONE_WAIT_SEC` (default 30s), host-side runner appends fallback structured markers (`SMOKE_FAIL:errno_smoke_done_missing` + `TEST_SUMMARY` + `TEST_RESULT_JSON`) so verdicting does not hang on timeout-only outcomes
- `make test-isolated` — isolated test alias
- `make test-driver` — driver module only
- `make test-mm` — memory module only
- `make test-sync` — sync module only
- `make test-vfork` — vfork module only
- `make test-sched` — scheduler module only
- `make test-crash` — crash module only
- `make test-syscall-trap` / `make test-syscall` — syscall/trap module only
- `make test-vfs-ipc` — vfs/tmpfs/pipe/epoll module only (includes epoll EPOLLET/EPOLLONESHOT regressions and timerfd-path monotonic clock progress check under `proc_yield`)
- `make test-socket` — socket module only (AF_UNIX stream/dgram + accept stability, AF_INET TCP/UDP time-bounded attempts)
- `make test-device-virtio` / `make test-devmodel` — device model + virtio probe-path module only
- `make test-tty` — tty stack module only (pty open/read/write/ioctl, n_tty canonical/echo/isig semantics, blocking read wakeup and EINTR paths, controlling-tty `/dev/tty` attach/detach lifecycle, pty pair EOF + reopen stability)
- `make test-soak-pr` — PR-level soak module only (default 15 min, low-rate fault injection, deterministic round-based suite scheduling, summary-based pass/fail)
- `test-soak-pr` log path is controlled by `SOAK_PR_LOG` (default isolated mode: `<TEST_BUILD_ROOT>/<arch>/test.log`; non-isolated mode: `build/<arch>/soak-pr.log`)
- `make test-soak` — long SMP stress test (timeout 600s, CONFIG_PMM_PCP_MODE=2, log: build/<arch>/soak.log)
- `make test-debug` — tests with CONFIG_DEBUG=1
- `make test-matrix` — SMP × DEBUG test matrix
- GitHub Actions `ci-quick` runs on PRs, pushes to `main`/`master`, and `quick-*` tags; it runs `riscv64` default regression gate (`make test-ci-default`), `x86_64` minimal smoke (`make test-driver`), and `aarch64` syscall/vfs-ipc/tcc gates (`make QEMU_SMP=2 test-syscall-trap` + `make QEMU_SMP=2 test-vfs-ipc` + `make QEMU_SMP=2 test-tcc-smoke`); on `riscv64`, `test-ci-default` uses `TEST_TIMEOUT=420` for quick regression and skips interactive smoke subtargets; all `aarch64` gates validate SMP stability via `scripts/impl/assert-aarch64-smp.py` (require `SMP: 2/2 CPUs active`, reject shortfall/stall diagnostics)
- GitHub Actions `soak-long` runs `riscv64` long soak-pr profile plus `x86_64` and `aarch64` bootstrap soak-pr profiles (shorter default duration and timeout for CI cost control); `aarch64` bootstrap soak runs with `QEMU_SMP=2` and applies the same SMP stability assertion (`scripts/impl/assert-aarch64-smp.py`)
- `third_party/` sources are intentionally not tracked in git; CI bootstraps required components (`lwip`, `limine`, `musl`, `busybox`, `tcc`, `doomgeneric`) via `scripts/kairos.sh deps fetch <component>` before test jobs.
- `scripts/impl/fetch-deps.sh` validates each cached dependency by sentinel files; when a directory exists but is incomplete/corrupted, it is removed and refetched instead of being blindly skipped.
- lwIP source for `deps fetch lwip` is configurable: `LWIP_GIT_URL` / `LWIP_GIT_REF` / `LWIP_GIT_COMMIT` (default URL currently `https://github.com/lwip-tcpip/lwip.git`, ref `STABLE-2_2_1_RELEASE`).
- `scripts/impl/fetch-deps.sh` defaults to preserving tracked `kernel/include/boot/limine.h`; refresh only when `FORCE_LIMINE_HEADER_FETCH=1`. Header source is configurable via `LIMINE_HEADER_REF` or `LIMINE_HEADER_URL` (default currently GitHub raw from `limine-protocol` `trunk`).
- musl source for `deps fetch musl` is configurable: `MUSL_GIT_URL` / `MUSL_GIT_REF` / `MUSL_GIT_COMMIT` (default still official musl git URL, ref `v1.2.5`).
- FatFs zip source for `deps fetch fatfs` is configurable: `FATFS_ZIP_URL` / `FATFS_ZIP_SHA256` (default still official FatFs archive URL).
- BusyBox source for `deps fetch busybox` is configurable: `BUSYBOX_GIT_URL` / `BUSYBOX_GIT_REF` / `BUSYBOX_GIT_COMMIT` (default URL currently `https://github.com/mirror/busybox.git`, ref `1_36_1`).
- TCC source for `deps fetch tcc` is configurable: `TCC_GIT_URL` / `TCC_GIT_REF` / `TCC_GIT_COMMIT` (default URL currently `https://github.com/chenty2333/tinycc.git`, ref `mob`).
- Test module selection uses `CONFIG_KERNEL_TEST_MASK` via `TEST_EXTRA_CFLAGS` (default mask `0x7FF`)
- Kernel test module bits: `0x01 driver`, `0x02 mm`, `0x04 sync`, `0x08 vfork`, `0x10 sched`, `0x20 crash`, `0x40 syscall/trap`, `0x80 vfs/ipc`, `0x100 socket`, `0x200 device/virtio`, `0x400 tty`, `0x800 soak-pr`
- `test-syscall-trap` includes a kernel-launched user-mode syscall regression (riscv64 `ecall`, x86_64 `int 0x80`, aarch64 `svc #0`) covering bad user pointer (`-EFAULT`) and positive syscall path; it also covers `uaccess` cross-page/large-range copy behavior plus `strncpy_from_user` semantics (returned length excludes terminating `NUL`; unmapped tail without `NUL` returns `-EFAULT`; if `NUL` appears before the unmapped page, copy succeeds even when `count` spans that page), and trapframe fallback semantics (`current_tf` + process `active_tf`) for trap/syscall paths that can schedule
- Example (only syscall/trap): `make ARCH=riscv64 test TEST_EXTRA_CFLAGS='-DCONFIG_KERNEL_TESTS=1 -DCONFIG_KERNEL_TEST_MASK=0x40'`
- `test-soak-pr` tunables (via `SOAK_PR_EXTRA_CFLAGS`): `CONFIG_KERNEL_FAULT_INJECT`, `CONFIG_KERNEL_SOAK_PR_DURATION_SEC`, `CONFIG_KERNEL_SOAK_PR_FAULT_PERMILLE`, `CONFIG_KERNEL_SOAK_PR_SUITE_MASK`, `CONFIG_KERNEL_SOAK_PR_MAX_ITERS`, `CONFIG_KERNEL_SOAK_PR_SCHED_EVERY`, `CONFIG_KERNEL_SOAK_PR_FAULT_EVERY`, `CONFIG_KERNEL_SOAK_PR_MIN_RUNS_PER_SUITE`, `CONFIG_KERNEL_SOAK_PR_SUITE_TIMEOUT_SEC`
- Fault injection probe points in PR soak: `kmalloc`, `copy_from_user`, `copy_to_user`; each probe logs hit/failure counters.

## Session Artifacts

Run/test sessions are executed via `scripts/run-qemu-session.sh` and `scripts/run-qemu-test.sh`, orchestrated by Make + `scripts/kairos.sh`.
For isolated sessions, outputs are under `build/runs/.../<run_id>/` and include:
- Default `<run_id>` format is short-readable `YYMMDD-HHMM-xxxx` (example: `250222-2315-7f3a`)
- `manifest.json` (command, arch, build root, git sha, timestamps)
- `result.json` (status/reason/verdict source + structured block + summary block + marker flags + log path)
- `qemu.pid` is owned by `run-qemu-session.sh`; `run-qemu-test.sh` uses `test-runner.pid` to avoid pid-file collisions
- Default isolated test logs live under the run directory (including `test-soak-pr`); explicit `TEST_LOG` / `SOAK_PR_LOG` / `TCC_SMOKE_LOG` / `EXEC_ELF_SMOKE_LOG` overrides keep caller-provided paths

## Locking and Concurrency

- Global locks live at `build/.locks/global-<name>.lock` (current shared resource: `global-deps-fetch.lock`).
- Local locks live at `<BUILD_ROOT>/<arch>/.locks/<name>.lock` (current: `image.lock`, `qemu.lock`, `test.lock`).
- `scripts/run-qemu-session.sh` uses `qemu.lock`; `scripts/run-qemu-test.sh` (via `scripts/kairos.sh run test*`) uses `test.lock` to avoid nested `qemu.lock` self-contention.
- `scripts/kairos.sh run test*` forces non-interactive QEMU stdin (`QEMU_STDIN=`); interactive stdin remains for explicit run/interactive flows.
- Lock metadata is written to `<lock>.meta` (`pid/start_utc/start_epoch/cwd/cmd`) for observability.
- On lock contention, stale metadata (dead pid) is reclaimed automatically and lock acquisition is retried once.
- Different `BUILD_ROOT` runs are parallel-safe; same `BUILD_ROOT` conflicting actions are blocked and return `lock_busy`.
- Lock wait is configurable: `LOCK_WAIT` (shared default), with per-flow overrides `RUN_LOCK_WAIT` and `TEST_LOCK_WAIT` (default `0` seconds).
- `make lock-status` lists lock files and metadata pid liveness (`alive`/`dead`).
- `make lock-clean-stale` removes dead `.lock.meta` and legacy `qemu-run.lock*`.

Concurrency troubleshooting:
- If you see `lock_busy`, run `make lock-status` first.
- On `lock_busy`, run/test output still prints `manifest.json` and `result.json` paths for the failed attempt.
- If metadata pid is `dead`, rerun the same command once; stale lock is reclaimed on the next lock attempt.
- If metadata pid is `alive`, another run/test is still active for the same build directory; wait or switch to a different `BUILD_ROOT`.
- Quick wait tuning examples: `make LOCK_WAIT=5 test-mm` (default); advanced override: `make RUN_LOCK_WAIT=10 run`.

Run retention:
- `make gc-runs` keeps latest `RUNS_KEEP` runs (default `20`)
- `make test` auto-triggers `gc-runs` when `GC_RUNS_AUTO=1` (default)
- `make run` auto-triggers `gc-runs` for `RUN_RUNS_ROOT` when `RUN_GC_AUTO=1` (default keep `5` via `RUNS_KEEP_RUN`)

## Result Verdict Policy

- `scripts/run-qemu-test.sh` writes `manifest.json` at start and `result.json` at end.
- Structured mode is default for kernel test/smoke paths (`TEST_REQUIRE_STRUCTURED=auto`, resolved to `1` when `TEST_REQUIRE_MARKERS=1`).
- Structured verdict requires both `TEST_RESULT_JSON` and `TEST_SUMMARY` and checks `failed` consistency.
- When structured result is complete and passed, `qemu_rc=0/124/2` are accepted (`2` covers firmware-reset style exits seen on some runs).
- If structured output is missing/invalid/inconsistent, verdict is non-pass (`infra_fail`).
- In structured mode, pre-QEMU/structured integrity checks run before optional required-marker assertions; this keeps build failures classified as `build_fail_*` instead of `required_markers_missing`.
- Required-marker assertions are enforced on the structured-pass path; when structured `failed > 0`, smoke failure reasons (`SMOKE_FAIL:*`) are preserved as primary verdict reasons.
- `run-qemu-session.sh` / `run-qemu-test.sh` emit signal telemetry in `result.json` under `signals`:
  `qemu_exit_signal`, `qemu_term_signal`, `qemu_term_sender_pid` (nullable when unavailable)
- When no kernel failure markers are present and the runner exits by signal (`qemu_rc` in 128+N, non-timeout),
  verdict is treated as infrastructure interruption (`external_sigterm` / `external_sigkill` / `external_signal`).
- `run-qemu-test.sh` also supports optional log assertions (diagnostic/extra constraints, not primary verdict source in structured mode):
  - `TEST_REQUIRED_MARKER_REGEX`: at least one required regex
  - `TEST_REQUIRED_MARKERS_ALL`: newline-delimited required regex list (all must match)
  - `TEST_FORBIDDEN_MARKER_REGEX`: forbidden regex (any match fails)
  - `TEST_OPTIONAL_MARKERS_IF_PRESENT`: newline-delimited `<present_regex><TAB><required_regex>` pairs; when `present_regex` appears in log, `required_regex` must also match, otherwise verdict fails as `optional_markers_invalid`
- CI gate steps validate `result.json` with `scripts/impl/assert-result-pass.py` (`--require-structured`).

## Verification Baseline

Primary verification architecture is `ARCH=riscv64` (run, test, test-soak, uefi).

Related references:
- references/00_REPO_MAP.md
- references/90_BUILD_TEST_DEBUG.md
