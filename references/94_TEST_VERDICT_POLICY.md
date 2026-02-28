# 94 — Test Result Verdict Policy

Part of Test/CI policy. See also:
- 90_BUILD_TEST_DEBUG.md — Build/run/debug parent entry
- 92_TESTING_COMMANDS.md — Test command and gate surface
- 93_TEST_SESSION_LOCKING.md — Session artifacts and lock model

## Result Verdict Policy

- `scripts/run-qemu-test.sh` writes `manifest.json` at start and `result.json` at end.
- Structured mode is default for kernel test/smoke paths (`TEST_REQUIRE_STRUCTURED=auto`, resolved to `1` when `TEST_REQUIRE_MARKERS=1`).
- Structured verdict requires both `TEST_RESULT_JSON` and `TEST_SUMMARY` and checks `failed` consistency.
- Kernel test runs also emit a post-suite `/sys/ipc/hash_stats` snapshot bracketed by `kernel tests: /sys/ipc/hash_stats begin|end`, so load-factor/collision trends can be compared across suites without interactive shell access.
- When structured result is complete and passed, `qemu_rc=0/124/2` are accepted (`2` covers firmware-reset style exits seen on some runs).
- If structured output is missing/invalid/inconsistent, verdict is non-pass (`infra_fail`).
- In structured mode, pre-QEMU/structured integrity checks run before optional required-marker assertions; this keeps build failures classified as `build_fail_*` instead of `required_markers_missing`.
- Required-marker assertions are enforced on the structured-pass path; when structured `failed > 0`, smoke failure reasons (`SMOKE_FAIL:*`) are preserved as primary verdict reasons.
- `run-qemu-session.sh` / `run-qemu-test.sh` emit signal telemetry in `result.json` under `signals`:
  `qemu_exit_signal`, `qemu_term_signal`, `qemu_term_sender_pid` (nullable when unavailable)
- Signal-based infra classification uses either runner exit signal (`qemu_rc` in 128+N) or parsed QEMU log termination signal (`terminating on signal N`) when non-timeout.
- When no kernel failure markers are present and the runner exits by signal (effective signal, non-timeout),
  verdict is treated as infrastructure interruption (`external_sigterm` / `external_sigkill` / `external_signal`).
- `run-qemu-test.sh` supports `TEST_INFRA_SIGNAL_RETRIES` (default `1`) to auto-retry transient `external_sigterm` / `external_sigkill` / `external_signal` infra failures.
- `run-qemu-test.sh` also supports optional log assertions (diagnostic/extra constraints, not primary verdict source in structured mode):
  - `TEST_REQUIRED_MARKER_REGEX`: at least one required regex
  - `TEST_REQUIRED_MARKERS_ALL`: newline-delimited required regex list (all must match)
  - `TEST_FORBIDDEN_MARKER_REGEX`: forbidden regex (any match fails)
  - `TEST_OPTIONAL_MARKERS_IF_PRESENT`: newline-delimited `<present_regex><TAB><required_regex>` pairs; when `present_regex` appears in log, `required_regex` must also match, otherwise verdict fails as `optional_markers_invalid`
- `scripts/kairos.sh run test` accepts pass-through overrides that map to the above assertion knobs:
  - `KAIROS_RUN_TEST_REQUIRED_MARKER_REGEX`
  - `KAIROS_RUN_TEST_REQUIRED_MARKERS_ALL`
  - `KAIROS_RUN_TEST_FORBIDDEN_MARKER_REGEX`
- CI gate steps validate `result.json` with `scripts/impl/assert-result-pass.py` (`--require-structured`).

## Verification Baseline

Primary verification architecture is `ARCH=riscv64` (run, test, test-soak, uefi).


Related references:
- references/00_REPO_MAP.md
- references/90_BUILD_TEST_DEBUG.md
- references/92_TESTING_COMMANDS.md
- references/93_TEST_SESSION_LOCKING.md
