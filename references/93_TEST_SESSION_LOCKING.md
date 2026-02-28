# 93 — Test Session Artifacts and Locking

Part of Test/CI policy. See also:
- 90_BUILD_TEST_DEBUG.md — Build/run/debug parent entry
- 92_TESTING_COMMANDS.md — Test command surface
- 94_TEST_VERDICT_POLICY.md — Verdict and structured result policy

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


Related references:
- references/00_REPO_MAP.md
- references/90_BUILD_TEST_DEBUG.md
- references/92_TESTING_COMMANDS.md
- references/94_TEST_VERDICT_POLICY.md
