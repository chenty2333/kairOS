# Kairos Kernel

Kairos is a multi-architecture hobby kernel focused on practical build/run/test workflows and subsystem iteration.

## Current Status

- Primary verification architecture: `riscv64`
- Supported build targets: `riscv64`, `x86_64`, `aarch64`
- Boot flow: UEFI + Limine

## Quick Start

```bash
# 1) Check host dependencies
make check-tools

# 2) Build kernel (default ARCH=riscv64)
make

# 3) Run in QEMU (isolated run directory by default)
make run

# 4) Run kernel tests (isolated test directory by default)
make test
```

## Common Build/Run Targets

```bash
make ARCH=riscv64
make ARCH=x86_64
make ARCH=aarch64

make run
make run-e1000
make debug

make uefi
make disk
make rootfs
```

## Test Targets

```bash
make test
make test-mm
make test-sched
make test-vfs-ipc
make test-device-virtio
make test-tty
make test-soak
make test-matrix
```

## Isolated Runs and Structured Results

`make run` / `make test` use isolated run directories by default.

- Test runs root: `build/runs/<run_id>/...`
- Run runs root: `build/runs/run/<run_id>/...`
- Each run writes:
  - `manifest.json`
  - `result.json`

`result.json` is the machine-readable outcome for automation.

## Locking, Concurrency, and Cleanup

- Local lock scope: `<BUILD_ROOT>/<arch>/.locks/`
- Shared lock scope: `build/.locks/`
- Useful commands:

```bash
make lock-status
make lock-clean-stale
```

Lock wait controls:

```bash
make LOCK_WAIT=5 test-mm
make RUN_LOCK_WAIT=10 run
make TEST_LOCK_WAIT=10 test-vfs-ipc
```

## Retention and GC

By default, old isolated runs are auto-pruned before new runs/tests.

- Test runs kept: `RUNS_KEEP` (default `20`)
- Run sessions kept: `RUNS_KEEP_RUN` (default `5`)

Manual GC:

```bash
make gc-runs
```

## Useful Variables

- `ARCH`: `riscv64|x86_64|aarch64`
- `BUILD_ROOT`: build root (default `build`)
- `RUN_ID`: explicit isolated run ID
- `LOCK_WAIT`: shared lock wait default
- `RUN_LOCK_WAIT`: run lock wait override
- `TEST_LOCK_WAIT`: test lock wait override
- `TEST_TIMEOUT`: test timeout seconds
- `V=1`: verbose build output

See full target/variable list:

```bash
make help
```

## Repository Layout

```text
kernel/       # kernel sources (arch/core/drivers/fs/net/...)
user/         # userland init + libc/shell
scripts/      # orchestration scripts (build/run/test/deps/image)
third_party/  # external dependencies
tools/        # helper tools
build/        # generated artifacts
references/   # subsystem references
```

## License

MIT (see `LICENSE`).
