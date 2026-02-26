#!/usr/bin/env python3

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

PAGE_FAULT_PATTERNS = (
    r"\bfault pid=",
    r"\bInst page fault\b",
    r"\bLoad page fault\b",
    r"\bStore/AMO page fault\b",
    r"\bno vma\b",
    r"\bsepc=0x",
)
PAGE_FAULT_RE = re.compile("|".join(PAGE_FAULT_PATTERNS))
SHELL_READY_RE = re.compile(r"init: starting shell|BusyBox v|\[[^\]]*\]\s*#")
BOOT_MARKER_RE = re.compile(r"SMP: .*CPU active|init: started /init|BusyBox v")


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def find_runs(root: Path, latest_only: bool, max_runs: int) -> list[Path]:
    if not root.is_dir():
        return []
    runs = [p for p in root.iterdir() if p.is_dir()]
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    if latest_only:
        return runs[:1]
    return runs[: max(1, max_runs)]


def detect_arch(run_dir: Path, result_obj: dict[str, Any]) -> str:
    manifest = run_dir / "manifest.json"
    manifest_obj = read_json(manifest) if manifest.is_file() else None
    if isinstance(manifest_obj, dict):
        arch = manifest_obj.get("arch")
        if isinstance(arch, str) and arch:
            return arch

    log_path = result_obj.get("log_path")
    if isinstance(log_path, str):
        for arch in ("aarch64", "x86_64", "riscv64"):
            if f"/{arch}/" in log_path or log_path.endswith(f"/{arch}/test.log"):
                return arch
    return "unknown"


def resolve_log_path(run_dir: Path, result_obj: dict[str, Any]) -> Path | None:
    log_path = result_obj.get("log_path")
    if not isinstance(log_path, str) or not log_path:
        return None

    p = Path(log_path)
    if p.is_absolute() and p.is_file():
        return p

    cwd_path = Path.cwd() / p
    if cwd_path.is_file():
        return cwd_path

    local_path = run_dir / p.name
    if local_path.is_file():
        return local_path
    return None


def scan_log(log_path: Path | None, max_evidence: int) -> dict[str, Any]:
    info: dict[str, Any] = {
        "has_page_fault": False,
        "has_shell_ready": False,
        "has_boot_marker": False,
        "evidence": [],
    }
    if log_path is None or not log_path.is_file():
        return info

    evidence: list[str] = []
    with log_path.open("r", encoding="utf-8", errors="ignore") as fp:
        for raw in fp:
            line = raw.rstrip("\n")
            if not info["has_page_fault"] and PAGE_FAULT_RE.search(line):
                info["has_page_fault"] = True
                if len(evidence) < max_evidence:
                    evidence.append(line)
            if not info["has_shell_ready"] and SHELL_READY_RE.search(line):
                info["has_shell_ready"] = True
                if len(evidence) < max_evidence:
                    evidence.append(line)
            if not info["has_boot_marker"] and BOOT_MARKER_RE.search(line):
                info["has_boot_marker"] = True
            if len(evidence) >= max_evidence and info["has_page_fault"] and info["has_shell_ready"]:
                break

    info["evidence"] = evidence
    return info


def classify(result_obj: dict[str, Any], log_info: dict[str, Any]) -> str:
    status = str(result_obj.get("status", ""))
    reason = str(result_obj.get("reason", ""))
    markers = result_obj.get("markers")
    has_boot_marker = False
    if isinstance(markers, dict):
        has_boot_marker = bool(markers.get("has_boot_marker", False))
    if not has_boot_marker:
        has_boot_marker = bool(log_info.get("has_boot_marker", False))

    has_page_fault = bool(log_info.get("has_page_fault", False))
    has_shell_ready = bool(log_info.get("has_shell_ready", False))

    if reason.startswith("build_fail_"):
        return "build_failure"
    if reason in {"external_sigterm", "external_sigkill", "external_signal"}:
        return "infra_signal"
    if reason in {
        "pre_qemu_failure_no_log",
        "pre_qemu_failure",
        "missing_structured_result",
        "invalid_structured_result",
        "structured_done_false",
        "missing_test_summary",
        "invalid_test_summary",
        "summary_result_mismatch",
    }:
        return "infra_result_integrity"
    if has_page_fault:
        return "page_fault"
    if reason in {"forbidden_markers_detected", "fatal_markers_detected"}:
        return "fatal_marker_detected"
    if reason in {"timeout", "timeout_without_structured"}:
        if has_shell_ready:
            return "interactive_hang_timeout"
        if not has_boot_marker:
            return "boot_timeout"
        return "runtime_timeout"
    if reason == "required_markers_missing":
        if not has_boot_marker:
            return "boot_marker_missing"
        return "required_marker_missing"
    if reason.startswith("smoke_") or reason == "structured_failed":
        return "kernel_test_failure"
    if status == "infra_fail":
        return "infra_failure"
    if status in {"fail", "error", "timeout"}:
        return "runtime_failure"
    return "unclassified"


def render_markdown(records: list[dict[str, Any]], scanned: int) -> str:
    lines: list[str] = []
    lines.append("## Failure Classification")
    lines.append("")
    lines.append(f"- scanned runs: `{scanned}`")
    lines.append(f"- failed runs: `{len(records)}`")
    lines.append("")

    if not records:
        lines.append("No failed runs found in scanned range.")
        return "\n".join(lines) + "\n"

    by_cat = Counter(r["category"] for r in records)
    lines.append("### Category Counts")
    lines.append("")
    for cat, count in sorted(by_cat.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"- `{cat}`: {count}")
    lines.append("")
    lines.append("### Failed Runs")
    lines.append("")
    lines.append("| run_id | arch | status | reason | category | qemu_rc |")
    lines.append("|---|---|---|---|---|---|")
    for r in records:
        lines.append(
            f"| `{r['run_id']}` | `{r['arch']}` | `{r['status']}` | `{r['reason']}` | `{r['category']}` | `{r['qemu_exit_code']}` |"
        )

    lines.append("")
    lines.append("### Evidence")
    lines.append("")
    for r in records:
        lines.append(f"- `{r['run_id']}` (`{r['category']}`)")
        if r["log_path"]:
            lines.append(f"  - log: `{r['log_path']}`")
        if r["evidence"]:
            for e in r["evidence"]:
                lines.append(f"  - {e}")
        else:
            lines.append("  - (no signature lines captured)")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classify Kairos isolated run failures by result reason + log signatures"
    )
    parser.add_argument("--runs-root", default="build/runs", help="Isolated runs root")
    parser.add_argument("--latest-only", action="store_true", help="Only scan latest run directory")
    parser.add_argument("--max-runs", type=int, default=20, help="Scan at most N runs")
    parser.add_argument("--max-evidence-lines", type=int, default=4, help="Evidence lines per run")
    parser.add_argument("--json-out", default="", help="Optional JSON output path")
    parser.add_argument("--markdown-out", default="", help="Optional Markdown output path")
    args = parser.parse_args()

    runs_root = Path(args.runs_root)
    run_dirs = find_runs(runs_root, args.latest_only, args.max_runs)
    scanned = len(run_dirs)

    failures: list[dict[str, Any]] = []
    for run_dir in run_dirs:
        result_path = run_dir / "result.json"
        result_obj = read_json(result_path)
        if not isinstance(result_obj, dict):
            continue
        status = str(result_obj.get("status", ""))
        if status == "pass":
            continue

        arch = detect_arch(run_dir, result_obj)
        log_path = resolve_log_path(run_dir, result_obj)
        log_info = scan_log(log_path, max(1, args.max_evidence_lines))
        failures.append(
            {
                "run_id": str(result_obj.get("run_id", run_dir.name)),
                "arch": arch,
                "status": status,
                "reason": str(result_obj.get("reason", "")),
                "qemu_exit_code": result_obj.get("qemu_exit_code"),
                "verdict_source": str(result_obj.get("verdict_source", "")),
                "category": classify(result_obj, log_info),
                "log_path": str(log_path) if log_path else "",
                "evidence": log_info.get("evidence", []),
            }
        )

    payload = {
        "schema_version": 1,
        "runs_root": str(runs_root),
        "scanned_runs": scanned,
        "failed_runs": len(failures),
        "category_counts": dict(Counter(r["category"] for r in failures)),
        "failures": failures,
    }

    markdown = render_markdown(failures, scanned)
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.markdown_out:
        out = Path(args.markdown_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")

    print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
