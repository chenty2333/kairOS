#!/usr/bin/env python3

import argparse
import re
import sys
from pathlib import Path


FORBIDDEN_PATTERNS = [
    r"SMP:\s*startup wait stalled",
    r"SMP:\s*cpu[0-9]+\s+did not reach online state",
    r"SMP:\s*[0-9]+\s+CPU start requests failed",
    r"SMP:\s*online shortfall expected=",
    r"SMP:\s*cpu[0-9]+\s+start failed rc=",
]


def fail(msg: str) -> int:
    print(f"assert-aarch64-smp: {msg}", file=sys.stderr)
    return 2


def collect_candidates(run_dir: Path, workspace: Path, arch: str) -> list[Path]:
    candidates = [
        run_dir / arch / "test.log",
        run_dir / arch / "run.log",
        run_dir / arch / "tcc-smoke.log",
        workspace / "build" / arch / "test.log",
        workspace / "build" / arch / "run.log",
        workspace / "build" / arch / "tcc-smoke.log",
    ]
    return [p for p in candidates if p.is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Assert AArch64 SMP stability markers in Kairos run logs"
    )
    parser.add_argument("--run-dir", required=True, help="Isolated run directory")
    parser.add_argument("--arch", default="aarch64", help="Architecture directory name")
    parser.add_argument(
        "--expected-online",
        type=int,
        default=2,
        help="Expected online CPU count for SMP marker (default: 2)",
    )
    parser.add_argument(
        "--workspace",
        default=".",
        help="Repository root for fallback build logs (default: .)",
    )
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    workspace = Path(args.workspace)
    if not run_dir.is_dir():
        return fail(f"run dir not found: {run_dir}")

    logs = collect_candidates(run_dir, workspace, args.arch)
    if not logs:
        return fail(
            "no candidate logs found under run/build paths "
            f"(run_dir={run_dir}, arch={args.arch})"
        )

    required_re = re.compile(
        rf"SMP:\s*{args.expected_online}/{args.expected_online}\s+CPUs active"
    )
    forbidden_res = [re.compile(p) for p in FORBIDDEN_PATTERNS]

    required_hit = None
    forbidden_hits: list[str] = []

    for path in logs:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return fail(f"failed to read {path}: {exc}")
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            if required_hit is None and required_re.search(line):
                required_hit = f"{path}:{idx}:{line.strip()}"
            for fre in forbidden_res:
                if fre.search(line):
                    forbidden_hits.append(f"{path}:{idx}:{line.strip()}")

    if required_hit is None:
        listed = ", ".join(str(p) for p in logs)
        return fail(
            f"missing required marker 'SMP: {args.expected_online}/{args.expected_online} CPUs active' "
            f"(scanned: {listed})"
        )

    if forbidden_hits:
        preview = "\n".join(forbidden_hits[:10])
        return fail(f"forbidden SMP diagnostics detected:\n{preview}")

    print(f"assert-aarch64-smp: PASS ({required_hit})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
