# 92C — Test Masks and Soak Tunables

Part of Test/CI policy. See also:
- 92_TESTING_COMMANDS.md — Testing/CI index
- 92_TESTING_COMMANDS__A_TARGETS_AND_PROFILES.md — Test targets and profiles
- 92_TESTING_COMMANDS__B_CI_WORKFLOWS_AND_DEPS.md — CI workflows and dependency/bootstrap model

## Test Masks and Soak Tunables

- Test module selection uses `CONFIG_KERNEL_TEST_MASK` via `TEST_EXTRA_CFLAGS` (default mask `0x7FF`)
- Kernel test module bits: `0x01 driver`, `0x02 mm`, `0x04 sync`, `0x08 vfork`, `0x10 sched`, `0x20 crash`, `0x40 syscall/trap`, `0x80 vfs/ipc`, `0x100 socket`, `0x200 device/virtio`, `0x400 tty`, `0x800 soak-pr`
- `test-syscall-trap` includes a kernel-launched user-mode syscall regression (riscv64 `ecall`, x86_64 `int 0x80`, aarch64 `svc #0`) covering bad user pointer (`-EFAULT`) and positive syscall path; it also covers `uaccess` cross-page/large-range copy behavior plus `strncpy_from_user` semantics (returned length excludes terminating `NUL`; unmapped tail without `NUL` returns `-EFAULT`; if `NUL` appears before the unmapped page, copy succeeds even when `count` spans that page), and trapframe fallback semantics (`current_tf` + process `active_tf`) for trap/syscall paths that can schedule
- `test-ipc-cap` is enabled by compile-time selector `CONFIG_SYSCALL_TRAP_IPC_CAP_ONLY=1` on top of `CONFIG_KERNEL_TEST_MASK=0x40`; default `test-syscall-trap` behavior is unchanged when the selector is not set
- Example (only syscall/trap): `make ARCH=riscv64 test TEST_EXTRA_CFLAGS='-DCONFIG_KERNEL_TESTS=1 -DCONFIG_KERNEL_TEST_MASK=0x40'`
- `test-soak-pr` tunables (via `SOAK_PR_EXTRA_CFLAGS`): `CONFIG_KERNEL_FAULT_INJECT`, `CONFIG_KERNEL_SOAK_PR_DURATION_SEC`, `CONFIG_KERNEL_SOAK_PR_FAULT_PERMILLE`, `CONFIG_KERNEL_SOAK_PR_SUITE_MASK`, `CONFIG_KERNEL_SOAK_PR_MAX_ITERS`, `CONFIG_KERNEL_SOAK_PR_SCHED_EVERY`, `CONFIG_KERNEL_SOAK_PR_FAULT_EVERY`, `CONFIG_KERNEL_SOAK_PR_MIN_RUNS_PER_SUITE`, `CONFIG_KERNEL_SOAK_PR_SUITE_TIMEOUT_SEC`
- `test-soak-pr` optional suite bit adds IPC/CAP focused longrun set: `CONFIG_KERNEL_SOAK_PR_SUITE_MASK` includes `0x100` (`syscall_trap_ipc_cap`, covering close-vs-blocking races, fd-only keepalive longrun, channelfd `epoll(EPOLLET)` stress and IPC fault-inject coverage); default suite mask remains unchanged unless explicitly overridden
- `test-soak-pr` optional deep suite bit `0x200` (`syscall_trap_ipc_cap_deep`) runs repeated IPC/CAP rounds with randomized `proc_yield()` jitter and concurrent noise workers; knobs: `CONFIG_KERNEL_SOAK_PR_IPC_CAP_DEEP_ROUNDS`, `CONFIG_KERNEL_SOAK_PR_IPC_CAP_NOISE_THREADS`, `CONFIG_KERNEL_SOAK_PR_IPC_CAP_NOISE_YIELD_MAX`, `CONFIG_KERNEL_SOAK_PR_IPC_CAP_NOISE_STOP_TIMEOUT_SEC`
- `test-soak-ipc-cap-deep` defaults: `CONFIG_KERNEL_SOAK_PR_SUITE_MASK=0x200`, `CONFIG_KERNEL_SOAK_PR_SCHED_EVERY=1`, `CONFIG_KERNEL_SOAK_PR_IPC_CAP_DEEP_ROUNDS=3`, `CONFIG_KERNEL_SOAK_PR_IPC_CAP_NOISE_THREADS=4`
- Fault injection probe points in PR soak: `kmalloc`, `copy_from_user`, `copy_to_user`; each probe logs hit/failure counters.

Related references:
- references/00_REPO_MAP.md
- references/90_BUILD_TEST_DEBUG.md
- references/92_TESTING_COMMANDS.md
- references/92_TESTING_COMMANDS__A_TARGETS_AND_PROFILES.md
- references/92_TESTING_COMMANDS__B_CI_WORKFLOWS_AND_DEPS.md
- references/94_TEST_VERDICT_POLICY.md
