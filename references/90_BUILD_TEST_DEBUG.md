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

Boot image:
- `make uefi` — prepare UEFI firmware + Limine boot image

Variables:
- `V=1` — verbose output
- `BUILD_ROOT=...` — override build root (default `build`)
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
- `make test-isolated` — isolated test alias
- `make test-driver` — driver module only
- `make test-mm` — memory module only
- `make test-sync` — sync module only
- `make test-vfork` — vfork module only
- `make test-sched` — scheduler module only
- `make test-crash` — crash module only
- `make test-syscall-trap` / `make test-syscall` — syscall/trap module only
- `make test-vfs-ipc` — vfs/tmpfs/pipe/epoll module only
- `make test-soak` — long SMP stress test (timeout 600s, CONFIG_PMM_PCP_MODE=2, log: build/<arch>/soak.log)
- `make test-debug` — tests with CONFIG_DEBUG=1
- `make test-matrix` — SMP × DEBUG test matrix
- Test module selection uses `CONFIG_KERNEL_TEST_MASK` via `TEST_EXTRA_CFLAGS` (default mask `0xFF`)
- Kernel test module bits: `0x01 driver`, `0x02 mm`, `0x04 sync`, `0x08 vfork`, `0x10 sched`, `0x20 crash`, `0x40 syscall/trap`, `0x80 vfs/ipc`
- Example (only syscall/trap): `make ARCH=riscv64 test TEST_EXTRA_CFLAGS='-DCONFIG_KERNEL_TESTS=1 -DCONFIG_KERNEL_TEST_MASK=0x40'`

Run/test sessions are executed via `scripts/run-qemu-session.sh` and `scripts/run-qemu-test.sh`, orchestrated by Make + `scripts/kairos.sh`.
For isolated sessions, outputs are under `build/runs/.../<run_id>/` and include:
- `manifest.json` (command, arch, build root, git sha, timestamps)
- `result.json` (pass/fail/timeout/error + reason + marker summary + log path)

Concurrency and locking:
- Shared-resource operations use a global lock.
- `image` and `run/test` use per-`BUILD_ROOT` locks.
- Different `BUILD_ROOT` runs are parallel-safe; same `BUILD_ROOT` conflicting actions are blocked.

Run retention:
- `make gc-runs` keeps latest `RUNS_KEEP` runs (default `20`)
- `make test` auto-triggers `gc-runs` when `GC_RUNS_AUTO=1` (default)
- `make run` auto-triggers `gc-runs` for `RUN_RUNS_ROOT` when `RUN_GC_AUTO=1` (default keep `5` via `RUNS_KEEP_RUN`)

Result decision policy:
- `scripts/run-qemu-test.sh` writes `manifest.json` at start and `result.json` at end.
- `TEST_SUMMARY` is preferred when present; log markers remain fallback compatibility checks.
- `result.json` is the primary machine-readable test outcome.

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
