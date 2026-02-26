#!/usr/bin/env python3

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple

CASE_RE = re.compile(
    r"ABI_CASE:([A-Za-z0-9_.-]+):errno=(-?[0-9]+):name=([A-Z0-9_]+)"
)
ARCH_RE = re.compile(r"/(riscv64|x86_64|aarch64)/")


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def resolve_paths(args: argparse.Namespace) -> Tuple[Path, Path, str, str]:
    run_dir = Path(args.run_dir).resolve()
    result_path = Path(args.result_json).resolve() if args.result_json else run_dir / "result.json"
    if not result_path.exists():
        raise SystemExit(f"result.json not found: {result_path}")

    result = load_json(result_path)
    log_path_raw = args.log_path or result.get("log_path")
    if not log_path_raw:
        raise SystemExit("log_path missing (pass --log-path or ensure result.json has log_path)")
    log_path = Path(log_path_raw)
    if not log_path.is_absolute():
        log_path = Path.cwd() / log_path
    log_path = log_path.resolve()
    if not log_path.exists():
        raise SystemExit(f"log file not found: {log_path}")

    arch = args.arch
    if not arch:
        match = ARCH_RE.search(str(log_path))
        arch = match.group(1) if match else "unknown"

    run_id = result.get("run_id", run_dir.name)
    return result_path, log_path, arch, run_id


def parse_log(log_path: Path) -> Tuple[Dict[str, dict], int, bool]:
    cases: Dict[str, dict] = {}
    case_lines = 0
    saw_done = False
    with log_path.open("r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            line = line.rstrip("\r\n")
            m = CASE_RE.search(line)
            if m:
                case_id = m.group(1)
                errno_value = int(m.group(2))
                errno_name = m.group(3)
                cases[case_id] = {"errno": errno_value, "errno_name": errno_name}
                case_lines += 1
            elif "__ABI_SMOKE_DONE__" in line:
                saw_done = True
    return cases, case_lines, saw_done


def render_markdown(snapshot: dict) -> str:
    lines = []
    lines.append(f"### ABI Snapshot ({snapshot['arch']})")
    lines.append("")
    lines.append(f"- run_id: `{snapshot['run_id']}`")
    lines.append(f"- cases: `{len(snapshot['cases'])}`")
    lines.append("")
    lines.append("| case | errno | name |")
    lines.append("| --- | ---: | --- |")
    for case_id in sorted(snapshot["cases"]):
        info = snapshot["cases"][case_id]
        lines.append(f"| `{case_id}` | `{info['errno']}` | `{info['errno_name']}` |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture ABI snapshot from abi_smoke run log."
    )
    parser.add_argument("--run-dir", required=True, help="isolated run directory")
    parser.add_argument("--result-json", help="path to result.json (default: <run-dir>/result.json)")
    parser.add_argument("--log-path", help="path to run log (default: from result.json)")
    parser.add_argument("--arch", help="override architecture name")
    parser.add_argument("--json-out", help="write snapshot JSON to this path")
    parser.add_argument("--markdown-out", help="write markdown summary to this path")
    args = parser.parse_args()

    result_path, log_path, arch, run_id = resolve_paths(args)
    cases, case_lines, saw_done = parse_log(log_path)
    if not cases:
        raise SystemExit(f"no ABI_CASE lines found in {log_path}")
    if not saw_done:
        raise SystemExit(f"missing __ABI_SMOKE_DONE__ marker in {log_path}")

    snapshot = {
        "schema_version": 1,
        "suite": "abi-smoke-v1",
        "arch": arch,
        "run_id": run_id,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "result_json": str(result_path),
        "log_path": str(log_path),
        "case_lines": case_lines,
        "cases": {k: cases[k] for k in sorted(cases)},
    }

    markdown = render_markdown(snapshot)
    print(markdown)

    if args.json_out:
        json_path = Path(args.json_out)
        json_path.write_text(json.dumps(snapshot, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    if args.markdown_out:
        Path(args.markdown_out).write_text(markdown + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
