#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple


def load_snapshot(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)
    if "cases" not in data or not isinstance(data["cases"], dict):
        raise SystemExit(f"invalid snapshot: missing cases map ({path})")
    return data


def diff_cases(base: Dict[str, dict], cur: Dict[str, dict]) -> Tuple[List[str], List[str], List[Tuple[str, int, int, str, str]]]:
    base_keys = set(base)
    cur_keys = set(cur)
    missing = sorted(base_keys - cur_keys)
    extra = sorted(cur_keys - base_keys)
    mismatched: List[Tuple[str, int, int, str, str]] = []
    for key in sorted(base_keys & cur_keys):
        base_errno = int(base[key].get("errno", 0))
        cur_errno = int(cur[key].get("errno", 0))
        if base_errno != cur_errno:
            mismatched.append(
                (
                    key,
                    base_errno,
                    cur_errno,
                    str(base[key].get("errno_name", "OTHER")),
                    str(cur[key].get("errno_name", "OTHER")),
                )
            )
    return missing, extra, mismatched


def render_markdown(
    baseline_label: str,
    current_label: str,
    baseline: dict,
    current: dict,
    missing: List[str],
    extra: List[str],
    mismatched: List[Tuple[str, int, int, str, str]],
) -> str:
    lines: List[str] = []
    lines.append(f"### ABI Compare ({current_label} vs {baseline_label})")
    lines.append("")
    lines.append(f"- baseline: `{baseline_label}` ({len(baseline['cases'])} cases)")
    lines.append(f"- current: `{current_label}` ({len(current['cases'])} cases)")
    lines.append(f"- missing cases: `{len(missing)}`")
    lines.append(f"- extra cases: `{len(extra)}`")
    lines.append(f"- errno mismatches: `{len(mismatched)}`")
    lines.append("")

    if missing:
        lines.append("Missing cases:")
        for case_id in missing:
            lines.append(f"- `{case_id}`")
        lines.append("")
    if extra:
        lines.append("Extra cases:")
        for case_id in extra:
            lines.append(f"- `{case_id}`")
        lines.append("")
    if mismatched:
        lines.append("| case | baseline errno | current errno |")
        lines.append("| --- | ---: | ---: |")
        for case_id, base_errno, cur_errno, _base_name, _cur_name in mismatched:
            lines.append(f"| `{case_id}` | `{base_errno}` | `{cur_errno}` |")
        lines.append("")
    if not missing and not extra and not mismatched:
        lines.append("ABI snapshot comparison passed.")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare two ABI snapshot JSON files.")
    parser.add_argument("--baseline", required=True, help="baseline snapshot JSON path")
    parser.add_argument("--current", required=True, help="current snapshot JSON path")
    parser.add_argument("--label-baseline", default="baseline")
    parser.add_argument("--label-current", default="current")
    parser.add_argument("--json-out", help="write diff JSON to this path")
    parser.add_argument("--markdown-out", help="write markdown summary to this path")
    args = parser.parse_args()

    baseline_path = Path(args.baseline).resolve()
    current_path = Path(args.current).resolve()
    baseline = load_snapshot(baseline_path)
    current = load_snapshot(current_path)

    missing, extra, mismatched = diff_cases(baseline["cases"], current["cases"])
    status = "pass" if not missing and not extra and not mismatched else "fail"
    diff = {
        "schema_version": 1,
        "status": status,
        "baseline": str(baseline_path),
        "current": str(current_path),
        "missing_cases": missing,
        "extra_cases": extra,
        "errno_mismatches": [
            {
                "case": case_id,
                "baseline_errno": base_errno,
                "current_errno": cur_errno,
                "baseline_errno_name": base_name,
                "current_errno_name": cur_name,
            }
            for case_id, base_errno, cur_errno, base_name, cur_name in mismatched
        ],
    }

    markdown = render_markdown(
        args.label_baseline,
        args.label_current,
        baseline,
        current,
        missing,
        extra,
        mismatched,
    )
    print(markdown)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(diff, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    if args.markdown_out:
        Path(args.markdown_out).write_text(markdown + "\n", encoding="utf-8")

    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
