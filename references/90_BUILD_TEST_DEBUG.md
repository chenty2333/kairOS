# 90 — Build / Test / Debug

## Build System

Top-level Makefile, make-based, auto-detects parallelism (nproc).

Architecture selection:
- `make` or `make ARCH=riscv64` — default RISC-V 64
- `make ARCH=x86_64`
- `make ARCH=aarch64`

Toolchain:
- Default uses clang cross-compilation (CC=clang, LD=ld.lld, OBJCOPY=llvm-objcopy)
- `USE_GCC=1` switches kernel compilation to GCC (requires corresponding cross-compile prefix)
- `TOOLCHAIN_MODE=auto|clang|gcc` controls toolchain policy for scripts/kairos.sh flows (compiler-rt, musl, busybox, tcc); does not directly select the kernel compiler

Compiler flags:
- `-ffreestanding -fno-common -nostdlib -fno-stack-protector -O2 -g`
- `-Wall -Wextra -Werror=implicit-function-declaration`
- riscv64: `-march=rv64gc -mabi=lp64d -mcmodel=medany`
- x86_64: `-m64 -mno-red-zone -mno-sse -mno-sse2 -mcmodel=kernel`
- aarch64: `-mgeneral-regs-only -fno-omit-frame-pointer`

Artifacts:
- `<BUILD_ROOT>/<arch>/kairos.elf` — kernel ELF
- `<BUILD_ROOT>/<arch>/kairos.bin` — kernel binary
- `<BUILD_ROOT>/<arch>/kairos.iso` — ISO image (x86_64 only)

## Build Targets

Core:
- `make` — build kernel
- `make clean` — remove current `<BUILD_ROOT>/<arch>`
- `make clean-all` — remove entire `build/`
- `make distclean` — `clean-all` + third_party/musl and third_party/busybox build artifacts

Userspace and rootfs:
- `make user` — build userspace init (depends on musl)
- `make initramfs` — build initramfs image
- `make busybox` — build busybox
- `make tcc` — build TCC (Tiny C Compiler)
- `make compiler-rt` — build clang compiler-rt builtins
- `make rootfs` — full rootfs (base + busybox + init; includes tcc when WITH_TCC=1, which is the default)
- `make disk` — create ext2 disk image
- Image allocation prefers `truncate` and falls back to `dd if=/dev/zero`, improving compatibility in restricted containers

Boot image:
- `make uefi` — prepare UEFI firmware + Limine boot image

Variables:
- `V=1` — verbose output
- `BUILD_ROOT=...` — override build root (default `build`)
- Top-level userspace sub-make passes absolute `BUILD_ROOT` to avoid relative-path drift under `make -C user`
- `EMBEDDED_INIT=1` — embedded init (riscv64 only)
- `WITH_TCC=0` — exclude tcc from rootfs
- `CONFIG_DRM_LITE=0` — disable drm_lite
- `EXTRA_CFLAGS=...` — additional compiler flags

## Running

- `make run` — run in QEMU (default isolated mode, one run directory per invocation)
- `make run-e1000` — run in QEMU with e1000 NIC (default isolated mode)
- `make debug` — QEMU + GDB server (port 1234)
- `make run-iso` — boot from ISO (x86_64 only; not a primary verification path for other architectures)

QEMU configuration:
- 256MB RAM, SMP default 4 cores (aarch64 defaults to 1 core, SMP path still unstable)
- Network: virtio-net + user mode; `HOSTFWD_PORT=8080` forwards host port to guest :80
- Graphics: `QEMU_GUI=1` enables GTK display
- Disk: virtio-blk; riscv64 uses virtio-mmio, x86_64/aarch64 use virtio-pci
- All architectures boot via UEFI + Limine

## Testing

- `make test` — run kernel tests (default isolated mode, one run directory per invocation)
- `make test-tcc-smoke` — run interactive `tcc` smoke regression (send `tcc` command in guest shell, assert usage + prompt round-trip, and fail on SIGSEGV/`no vma` markers)
- `make test-isolated` — isolated test alias
- `make test-driver` — driver module only
- `make test-mm` — memory module only
- `make test-sync` — sync module only
- `make test-vfork` — vfork module only
- `make test-sched` — scheduler module only
- `make test-crash` — crash module only
- `make test-syscall-trap` / `make test-syscall` — syscall/trap module only
- `make test-vfs-ipc` — vfs/tmpfs/pipe/epoll module only (includes epoll EPOLLET/EPOLLONESHOT regressions)
- `make test-socket` — socket module only (AF_UNIX stream/dgram + accept stability, AF_INET TCP/UDP time-bounded attempts)
- `make test-device-virtio` / `make test-devmodel` — device model + virtio probe-path module only
- `make test-tty` — tty stack module only (pty open/read/write/ioctl, n_tty canonical/echo/isig semantics, blocking read wakeup and EINTR paths, controlling-tty `/dev/tty` attach/detach lifecycle, pty pair EOF + reopen stability)
- `make test-soak-pr` — PR-level soak module only (default 15 min, low-rate fault injection, deterministic round-based suite scheduling, summary-based pass/fail)
- `test-soak-pr` log path is controlled by `SOAK_PR_LOG` (default `build/<arch>/soak-pr.log`, even when tests run in isolated mode)
- `make test-soak` — long SMP stress test (timeout 600s, CONFIG_PMM_PCP_MODE=2, log: build/<arch>/soak.log)
- `make test-debug` — tests with CONFIG_DEBUG=1
- `make test-matrix` — SMP × DEBUG test matrix
- Test module selection uses `CONFIG_KERNEL_TEST_MASK` via `TEST_EXTRA_CFLAGS` (default mask `0x7FF`)
- Kernel test module bits: `0x01 driver`, `0x02 mm`, `0x04 sync`, `0x08 vfork`, `0x10 sched`, `0x20 crash`, `0x40 syscall/trap`, `0x80 vfs/ipc`, `0x100 socket`, `0x200 device/virtio`, `0x400 tty`, `0x800 soak-pr`
- `test-syscall-trap` includes a kernel-launched user-mode ecall regression covering bad user pointer (`-EFAULT`) and positive syscall path
- Example (only syscall/trap): `make ARCH=riscv64 test TEST_EXTRA_CFLAGS='-DCONFIG_KERNEL_TESTS=1 -DCONFIG_KERNEL_TEST_MASK=0x40'`
- `test-soak-pr` tunables (via `SOAK_PR_EXTRA_CFLAGS`): `CONFIG_KERNEL_FAULT_INJECT`, `CONFIG_KERNEL_SOAK_PR_DURATION_SEC`, `CONFIG_KERNEL_SOAK_PR_FAULT_PERMILLE`, `CONFIG_KERNEL_SOAK_PR_SUITE_MASK`, `CONFIG_KERNEL_SOAK_PR_MAX_ITERS`, `CONFIG_KERNEL_SOAK_PR_SCHED_EVERY`, `CONFIG_KERNEL_SOAK_PR_FAULT_EVERY`, `CONFIG_KERNEL_SOAK_PR_MIN_RUNS_PER_SUITE`, `CONFIG_KERNEL_SOAK_PR_SUITE_TIMEOUT_SEC`
- Fault injection probe points in PR soak: `kmalloc`, `copy_from_user`, `copy_to_user`; each probe logs hit/failure counters.

Run/test sessions are executed via `scripts/run-qemu-session.sh` and `scripts/run-qemu-test.sh`, orchestrated by Make + `scripts/kairos.sh`.
For isolated sessions, outputs are under `build/runs/.../<run_id>/` and include:
- Default `<run_id>` format is short-readable `YYMMDD-HHMM-xxxx` (example: `250222-2315-7f3a`)
- `manifest.json` (command, arch, build root, git sha, timestamps)
- `result.json` (status/reason/verdict source + structured test summary + marker flags + log path)
- `qemu.pid` is owned by `run-qemu-session.sh`; `run-qemu-test.sh` uses `test-runner.pid` to avoid pid-file collisions
- Default isolated test logs live under the run directory; explicit `TEST_LOG` / `SOAK_PR_LOG` / `TCC_SMOKE_LOG` overrides keep caller-provided paths

Concurrency and locking:
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
- Quick wait tuning examples: `make LOCK_WAIT=5 test-mm`, `make RUN_LOCK_WAIT=10 run`.

Run retention:
- `make gc-runs` keeps latest `RUNS_KEEP` runs (default `20`)
- `make test` auto-triggers `gc-runs` when `GC_RUNS_AUTO=1` (default)
- `make run` auto-triggers `gc-runs` for `RUN_RUNS_ROOT` when `RUN_GC_AUTO=1` (default keep `5` via `RUNS_KEEP_RUN`)

Result decision policy:
- `scripts/run-qemu-test.sh` writes `manifest.json` at start and `result.json` at end.
- `TEST_RESULT_JSON` (kernel-emitted single-line JSON) is the primary verdict source for marker-required test runs.
- When structured result is complete and passed, `qemu_rc=0/124/2` are accepted (`2` covers firmware-reset style exits seen on some runs).
- If structured output is missing/invalid, the runner uses timeout/failure markers as guarded fallback and reports non-pass status.
- `run-qemu-test.sh` also supports optional log assertions:
  - `TEST_REQUIRED_MARKER_REGEX`: at least one required regex
  - `TEST_REQUIRED_MARKERS_ALL`: newline-delimited required regex list (all must match)
  - `TEST_FORBIDDEN_MARKER_REGEX`: forbidden regex (any match fails)
- `result.json` is the primary machine-readable test outcome consumed by automation.

Primary verification architecture is ARCH=riscv64 (run, test, test-soak, uefi).

## Debugging

- `make debug` starts QEMU paused, waiting for GDB connection
- Connect: `gdb <BUILD_ROOT>/<arch>/kairos.elf -ex 'target remote localhost:1234'`
- `make disasm` — generate disassembly (`<BUILD_ROOT>/<arch>/kairos.asm`)
- `make symbols` — generate symbol table (`<BUILD_ROOT>/<arch>/kairos.sym`)

## Toolchain Check

- `make check-tools` or `make doctor` — verify host toolchain and UEFI firmware are ready

Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE_TRAP_SYSCALL_TIME.md
