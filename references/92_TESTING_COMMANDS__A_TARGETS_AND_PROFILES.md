# 92A — Test Targets and Profiles

Part of Test/CI policy. See also:
- 92_TESTING_COMMANDS.md — Testing/CI index
- 92_TESTING_COMMANDS__B_CI_WORKFLOWS_AND_DEPS.md — CI workflows and dependency/bootstrap model
- 92_TESTING_COMMANDS__C_MASKS_AND_TUNABLES.md — Test masks and soak tunables

## Test Targets and Profiles

- `make test` — run kernel tests (default isolated mode, one run directory per invocation)
- `make test-exec-elf-smoke` — run interactive exec/ELF smoke regression (static/dynamic/PIE compile+run, PT_INTERP checks, bad-ELF rejection, fail on SIGSEGV/`no vma` markers)
- `make test-tcc-smoke` — compatibility alias of the exec/ELF smoke path
- `make test-busybox-applets-smoke` — run interactive BusyBox applet smoke regression (assert applet symlink/execution path for the enabled A-set and require `APPLET_SMOKE_OK:40`, `APPLET_BAD_COUNT:0`, `__BB_APPLET_SMOKE_DONE__`)
- `make test-errno-smoke` runs `/usr/bin/errno_smoke` inside guest; if `__ERRNO_SMOKE_DONE__` is not observed within `ERRNO_SMOKE_DONE_WAIT_SEC` (default 30s), host-side runner appends fallback structured markers (`SMOKE_FAIL:errno_smoke_done_missing` + `TEST_SUMMARY` + `TEST_RESULT_JSON`) so verdicting does not hang on timeout-only outcomes
- `make test-isolated` — isolated test alias
- `make test-driver` — driver module only
- `test-driver` includes `virtio_iommu_health` checks; strict backend-required mode is controlled by `VIRTIO_IOMMU_HEALTH_REQUIRED` (default auto-derived from `QEMU_IOMMU_EFFECTIVE`, so PCI arches running with `virtio-iommu-pci` fail instead of skipping when backend is unavailable)
- In `ci-quick`, `x86_64` and `aarch64` driver gates pin `QEMU_IOMMU=virtio` to avoid host-dependent `auto -> off` fallback and keep `virtio_iommu_health` gate deterministic.
- `make test-mm` — memory module only
- `make test-sync` — sync module only
- `make test-vfork` — vfork module only
- `make test-sched` — scheduler module only (includes `poll_wait_head` single-waiter fastpath regression)
- `make test-crash` — crash module only
- `make test-syscall-trap` / `make test-syscall` — syscall/trap module only
- `make test-ipc-cap` — focused syscall-trap IPC/Capability subset (`cap_rights_fd`, `channel_port`, `channel_port_stress_mpmc`, `file_handle_bridge`, `kobj_refcount_history`, `channel_inline_queue_zero_heap`, `send_transfer_rollback_kmalloc_fault`, `reserved_transfer_timeout_sweep`, `kcap_revoke_transfer_matrix_first_batch`, `kcap_revoke_transfer_matrix_second_batch`, `transfer_reserve_transaction`) with `QEMU_IOMMU=off` to avoid unrelated backend noise
- `make test-ipc-cap-matrix` — run `test-ipc-cap` across `aarch64`, `x86_64`, `riscv64`
- `make test-boot-smoke` — cross-arch boot-chain smoke (`KERNEL_TESTS=0`) with shell markers (`SMP`, `/init`, BusyBox) and forbidden fault/kill/fork-fail markers
- `make test-x86-boot-smp` — x86_64 boot-chain smoke on `QEMU_SMP=1` and `QEMU_SMP=4` with `KERNEL_TESTS=0`; requires shell boot markers (`SMP`, `/init`, BusyBox) and rejects fault/kill/fork-fail markers
- `make test-vfs-ipc` — vfs/tmpfs/pipe/epoll module only (includes epoll EPOLLET/EPOLLONESHOT regressions and timerfd-path monotonic clock progress check under `proc_yield`)
- `make test-socket` — socket module only (AF_UNIX stream/dgram + accept stability, AF_INET TCP/UDP time-bounded attempts)
- `make test-device-virtio` / `make test-devmodel` — device model + virtio probe-path module coverage. On `aarch64`, this target runs a 4-case IRQ-route matrix with explicit log assertions (`MSI-X(2)`, `MSI-X(1)`, `MSI-attempt fallback`, `INTx`) via `VIRTIO_IRQ_MODE:<mode>:<vectors>` + `VIRTIO_IRQ_MSI_STATE:<state>` markers and validates MSI-X affinity programming via `VIRTIO_IRQ_AFFINITY:ok:<vec>:<mask>`. On `riscv64`, it runs an 8-case AIA on/off matrix (`MSI-X(2)`, `MSI-X(1)`, `MSI-attempt`, `INTx`) using unstructured marker assertions over `run-direct`; when `RISCV_IRQ_BACKEND:imsic` is present, MSI-X route/affinity markers are required; when `RISCV_IRQ_BACKEND:none` is present, INTx + fallback markers are required.
- `make test-tty` — tty stack module only (pty open/read/write/ioctl, n_tty canonical/echo/isig semantics, blocking read wakeup and EINTR paths, controlling-tty `/dev/tty` attach/detach lifecycle, pty pair EOF + reopen stability)
- `make test-soak-pr` — PR-level soak module only (default 15 min, low-rate fault injection, deterministic round-based suite scheduling, summary-based pass/fail)
- `make test-soak-ipc-cap-deep` — deep IPC/CAP soak profile (default 30 min) with dedicated deep suite mask, random scheduler jitter and multi-thread noise workers
- `test-soak-pr` log path is controlled by `SOAK_PR_LOG` (default isolated mode: `<TEST_BUILD_ROOT>/<arch>/test.log`; non-isolated mode: `build/<arch>/soak-pr.log`)
- `make test-soak` — long SMP stress test (timeout 600s, CONFIG_PMM_PCP_MODE=2, log: build/<arch>/soak.log)
- `make test-debug` — tests with CONFIG_DEBUG=1
- `make test-matrix` — SMP × DEBUG test matrix

Related references:
- references/00_REPO_MAP.md
- references/90_BUILD_TEST_DEBUG.md
- references/92_TESTING_COMMANDS.md
- references/92_TESTING_COMMANDS__B_CI_WORKFLOWS_AND_DEPS.md
- references/92_TESTING_COMMANDS__C_MASKS_AND_TUNABLES.md
- references/93_TEST_SESSION_LOCKING.md
- references/94_TEST_VERDICT_POLICY.md
