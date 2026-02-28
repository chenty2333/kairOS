# 92B — CI Workflows and Dependency Bootstrap

Part of Test/CI policy. See also:
- 92_TESTING_COMMANDS.md — Testing/CI index
- 92_TESTING_COMMANDS__A_TARGETS_AND_PROFILES.md — Test targets and profiles
- 92_TESTING_COMMANDS__C_MASKS_AND_TUNABLES.md — Test masks and soak tunables

## CI Workflows and Dependency/Bootstrap Model

- GitHub Actions `ci-quick` is triggered by `quick-*` tags (plus manual `workflow_dispatch`) and has lane split: default/core lane runs `riscv64-test` (`syscall-trap`, `vfs/ipc`, `driver`, `socket`, `tcc-smoke`, `abi-smoke`), full lane (tag contains `-full-` or manual `lane=full`) additionally runs `x86_64-gates` (same + `test-x86-boot-smp`) and `aarch64-smoke` (`smp2` full quick set + `smp4` `syscall-trap`/`vfs-ipc`), irq lane (tag contains `-irq-` or manual `lane=irq`) runs `x86_64-irq-soak` (`test-irq-soak`); `riscv64` boot diagnostics artifacts (`qemu-version`, firmware hash, `qemu-virt-ci.dtb`, repro `boot.img` bundle) are disabled by default and only emitted when the tag name includes `-bootdiag-` (or manual dispatch sets `enable_bootdiag=true`).
- GitHub Actions `ci-nightly-matrix` runs on a daily schedule and manual dispatch, and executes the expanded cross-arch matrix (`boot`, `ipc-cap`, `syscall-trap`, `sched`, `vfs/ipc`, `socket`, `driver`, `device-virtio`, and non-riscv64 `tcc-smoke`; plus aarch64 SMP=4 syscall/vfs-ipc checks).
- GitHub Actions `soak-long` runs `riscv64` long soak-pr profile plus `x86_64` and `aarch64` bootstrap soak-pr profiles (shorter default duration and timeout for CI cost control); before `aarch64` soak-pr mixed-suite runs, it executes directed loop profiles for `test-driver` on `QEMU_SMP=2` (`AARCH64_DRIVER_SMP2_LOOP_ROUNDS`, default 12) and `QEMU_SMP=4` (`AARCH64_DRIVER_LOOP_ROUNDS`, default 4) with `QEMU_IOMMU=virtio`, plus `QEMU_SMP=4` loops for `test-vfs-ipc` (`AARCH64_VFS_IPC_LOOP_ROUNDS`, default 6) and `test-socket` (`AARCH64_SOCKET_LOOP_ROUNDS`, default 4); all loops share `scripts/impl/run-directed-loop.sh` and enforce structured pass + `scripts/impl/assert-aarch64-smp.py` CPU-online checks
- `ci-quick` and `soak-long` now each include a final inline `flake-report` job (`if: always()`), so rolling flake conclusions are visible in the same run page as the gate execution and are uploaded as artifacts (`ci-flake-report.json` / `ci-flake-report.md`).
- GitHub Actions `ci-flake-report` is retained as periodic/on-demand reporting workflow (daily schedule + manual dispatch); it computes rolling failure-rate stats for key gates in `ci-quick`/`soak-long` over the latest N completed runs per workflow (default `20`) and publishes both step summary + artifacts (`ci-flake-report.json` / `ci-flake-report.md`); enforcement is layered into `kernel_fail_rate` and `infra_fail_rate` thresholds (defaults: kernel `10%`, infra `20%`, `min_evaluated=10`), with optional legacy fallback `--max-fail-rate-percent` (applies to both when specific caps are unset).
- `scripts/impl/classify-run-failures.py` is used in CI `if: always()` tails to classify failed runs from `result.json + log` into signature buckets (for example `page_fault`, `interactive_hang_timeout`, `boot_timeout`, `build_failure`, `infra_signal`) and publish JSON/Markdown summaries.
- CI workflow bootstrap steps are centralized through local action `./.github/actions/prepare-kairos-ci` (cache restore + `scripts/impl/ci-bootstrap.sh` subcommands `install-host-deps`, `fetch-required-third-party`, `locate-uefi`) to keep host package/dependency/firmware detection logic consistent across jobs/workflows.
- Common gate execution (`make` + latest isolated run structured assert + optional aarch64 SMP-online assert) is centralized through local action `./.github/actions/run-gate-assert`.
- Rolling flake report generation (threshold args + summary publish) is centralized through local action `./.github/actions/run-flake-report`.
- `third_party/` sources are intentionally not tracked in git; CI bootstraps required components (`lwip`, `limine`, `musl`, `busybox`, `tcc`, `doomgeneric`) via `scripts/kairos.sh deps fetch <component>` before test jobs.
- `scripts/impl/fetch-deps.sh` validates each cached dependency by sentinel files; when a directory exists but is incomplete/corrupted, it is removed and refetched instead of being blindly skipped.
- QEMU IOMMU mode is controlled by `QEMU_IOMMU` (`auto|off|virtio`): `auto` enables `virtio-iommu-pci` on `x86_64`/`aarch64` only when host QEMU advertises the device, otherwise falls back to `off`.
- lwIP source for `deps fetch lwip` is configurable: `LWIP_GIT_URL` / `LWIP_GIT_REF` / `LWIP_GIT_COMMIT` (default URL currently `https://github.com/lwip-tcpip/lwip.git`, ref `STABLE-2_2_1_RELEASE`).
- `scripts/impl/fetch-deps.sh` defaults to preserving tracked `kernel/include/boot/limine.h`; refresh only when `FORCE_LIMINE_HEADER_FETCH=1`. Header source is configurable via `LIMINE_HEADER_REF` or `LIMINE_HEADER_URL` (default currently GitHub raw from `limine-protocol` `trunk`).
- musl source for `deps fetch musl` is configurable: `MUSL_GIT_URL` / `MUSL_GIT_REF` / `MUSL_GIT_COMMIT` (default still official musl git URL, ref `v1.2.5`).
- FatFs zip source for `deps fetch fatfs` is configurable: `FATFS_ZIP_URL` / `FATFS_ZIP_SHA256` (default still official FatFs archive URL).
- BusyBox source for `deps fetch busybox` is configurable: `BUSYBOX_GIT_URL` / `BUSYBOX_GIT_REF` / `BUSYBOX_GIT_COMMIT` (default URL currently `https://github.com/mirror/busybox.git`, ref `1_36_1`).
- TCC source for `deps fetch tcc` is configurable: `TCC_GIT_URL` / `TCC_GIT_REF` / `TCC_GIT_COMMIT` (default URL currently `https://github.com/chenty2333/tinycc.git`, ref `mob`).

Related references:
- references/00_REPO_MAP.md
- references/90_BUILD_TEST_DEBUG.md
- references/92_TESTING_COMMANDS.md
- references/92_TESTING_COMMANDS__A_TARGETS_AND_PROFILES.md
- references/92_TESTING_COMMANDS__C_MASKS_AND_TUNABLES.md
- references/93_TEST_SESSION_LOCKING.md
- references/94_TEST_VERDICT_POLICY.md
