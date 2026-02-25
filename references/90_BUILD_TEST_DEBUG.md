# 90 — Build / Run / Debug

## Scope

- This document covers build/run/debug workflows.
- Detailed testing, CI gates, lock/session behavior, and verdict policy are moved to `references/91_TEST_CI_POLICY.md`.

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
- `make help` — show common targets/variables (minimal daily surface)
- `make HELP_ADVANCED=1 help` — show advanced targets/variables
- `make print-config` — print effective build/run/test configuration (paths, timeouts, locks, retention)
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
- BusyBox applet link staging is driven by `scripts/busybox-applets.txt`; both `rootfs-busybox` and `initramfs` now depend on this file to avoid stale applet-link images

Boot image:
- `make uefi` — prepare UEFI firmware + Limine boot image

Variables:
- `V=1` — verbose output
- `BUILD_ROOT=...` — override build root (default `build`)
- Recommended day-to-day knobs: `ARCH`, `TEST_TIMEOUT`, `LOCK_WAIT`, `RUN_ID`
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
- 384MB RAM, SMP default 4 cores (`aarch64` run/debug default is `QEMU_SMP=4`; CI keeps explicit `QEMU_SMP=2` stability gates plus `SMP=4` blocking gates across syscall/vfs-ipc/driver/socket/tcc paths)
- Default accelerator is `QEMU_ACCEL=tcg,thread=multi`; for deterministic boot-hart ordering in specific `riscv64` scenarios, override with `QEMU_ACCEL=tcg,thread=single`
- Network: virtio-net + user mode; `HOSTFWD_PORT=8080` forwards host port to guest :80
- Graphics: `QEMU_GUI=1` enables GTK display
- Disk: virtio-blk; riscv64 uses virtio-mmio, x86_64/aarch64 use virtio-pci
- All architectures boot via UEFI + Limine
- Boot media contract: `UEFI_BOOT_MODE=dir|img|both` controls generated boot artifacts, `QEMU_UEFI_BOOT_MODE=dir|img` controls run-time media selection
- Default is directory boot (`bootfs`); when `UEFI_BOOT_MODE=both`, run-time default remains `dir`
- For non-`both` builds, mode mismatch is rejected early (`UEFI_BOOT_MODE` must equal `QEMU_UEFI_BOOT_MODE`)
- `scripts/run-qemu-session.sh` preflights boot media strictly and fails fast on missing expected artifact (no automatic `boot.img`/`bootfs` fallback)
- Under `UEFI_BOOT_MODE=both`, selecting `QEMU_UEFI_BOOT_MODE=img` requires `mkfs.fat + mtools`; missing host tools now fail image preparation early
- `make uefi` now propagates image-preparation failure to caller (no silent success on missing boot image prerequisites)
- aarch64 UEFI image prep now auto-generates `qemu-virt-aarch64.dtb` (via QEMU `dumpdtb`) and embeds it as a Limine module; `make uefi` passes current `QEMU_SMP` into image prep so generated DTB CPU topology matches the requested SMP count

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
- references/91_TEST_CI_POLICY.md
