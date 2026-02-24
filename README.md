# Kairos Kernel

Kairos is a multi-architecture hobby kernel with a build/run/test flow optimized for iteration.

- Primary verification architecture: `riscv64`
- Supported build targets: `riscv64`, `x86_64`, `aarch64`
- Boot flow: UEFI + Limine

## 5-Minute Start

```bash
# 1) Verify host tools
make check-tools

# 2) Boot once (default ARCH=riscv64)
make run

# 3) Run core tests
make test
```

If you only run one module test first, use:

```bash
make test-vfs-ipc
```

Common module-focused test targets:
- `make test-mm`
- `make test-sched`
- `make test-vfs-ipc`
- `make test-device-virtio`

## The 4 Knobs You Usually Need

- `ARCH` - `riscv64|x86_64|aarch64`
- `TEST_TIMEOUT` - test timeout seconds (default `180`)
- `LOCK_WAIT` - wait seconds for run/test lock acquisition (default `0`)
- `V=1` - verbose output

Examples:

```bash
make ARCH=x86_64
make TEST_TIMEOUT=300 test-sched
make LOCK_WAIT=5 test-mm
make V=1 run
```

## Where Results Go

Run/test are isolated by default.

- Test runs: `build/runs/<run_id>/...`
- Run sessions: `build/runs/run/<run_id>/...`
- Each run writes:
  - `manifest.json`
  - `result.json`

Automation should consume `result.json`.

## If You Hit Concurrency Issues

```bash
make lock-status
make lock-clean-stale
```

If you see `lock_busy`, either wait for active runs to finish or retry with a small wait window:

```bash
make LOCK_WAIT=5 test-vfs-ipc
```

## Retention

Old isolated runs are auto-pruned before `run`/`test`.

- Test runs kept: `RUNS_KEEP` (default `20`)
- Run sessions kept: `RUNS_KEEP_RUN` (default `5`)

Manual cleanup:

```bash
make gc-runs
```

## Advanced Usage

Default help is intentionally minimal:

```bash
make help
```

Full target/parameter surface:

```bash
make HELP_ADVANCED=1 help
```

For detailed build/test/debug behavior, see `references/90_BUILD_TEST_DEBUG.md`.

## Repository Layout

```text
kernel/       # kernel sources (arch/core/drivers/fs/net/...)
user/         # userland init + libc/shell
scripts/      # build/run/test orchestration
third_party/  # external dependencies
tools/        # helper tools
build/        # generated artifacts
references/   # subsystem references
```

## License

MIT (see `LICENSE`).
