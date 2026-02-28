#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TargetRule:
    target: str
    patterns: tuple[re.Pattern[str], ...]


RULES: tuple[TargetRule, ...] = (
    TargetRule(
        target="test-ipc-cap",
        patterns=(
            re.compile(r"^kernel/core/ipc/"),
            re.compile(r"^kernel/core/syscall/sys_handle\.c$"),
            re.compile(r"^kernel/core/tests/syscall_trap_tests\.c$"),
            re.compile(r"^kernel/include/kairos/handle\.h$"),
            re.compile(r"^kernel/include/kairos/kobj\.h$"),
            re.compile(r"^kernel/fs/sysfs/ipc_objects\.c$"),
            re.compile(r"^kernel/fs/sysfs/sysfs\.c$"),
        ),
    ),
    TargetRule(
        target="test-socket",
        patterns=(
            re.compile(r"^kernel/net/"),
            re.compile(r"^kernel/core/syscall/sys_socket\.c$"),
            re.compile(r"^kernel/core/tests/socket_tests\.c$"),
            re.compile(r"^kernel/include/kairos/socket\.h$"),
        ),
    ),
    TargetRule(
        target="test-vfs-ipc",
        patterns=(
            re.compile(r"^kernel/fs/"),
            re.compile(r"^kernel/core/syscall/sys_fs_.*\.c$"),
            re.compile(r"^kernel/core/tests/vfs_ipc_tests\.c$"),
            re.compile(r"^kernel/include/kairos/vfs\.h$"),
            re.compile(r"^kernel/include/kairos/mount\.h$"),
        ),
    ),
    TargetRule(
        target="test-sched",
        patterns=(
            re.compile(r"^kernel/core/sched/"),
            re.compile(r"^kernel/core/syscall/sys_proc\.c$"),
            re.compile(r"^kernel/core/sync/pollwait\.c$"),
            re.compile(r"^kernel/core/sync/futex\.c$"),
            re.compile(r"^kernel/core/tests/sched_tests\.c$"),
            re.compile(r"^kernel/include/kairos/sched\.h$"),
            re.compile(r"^kernel/include/kairos/pollwait\.h$"),
            re.compile(r"^kernel/include/kairos/wait\.h$"),
        ),
    ),
)


def git_diff_files(base: str, head: str) -> list[str]:
    rev = f"{base}...{head}"
    cmd = ["git", "diff", "--name-only", "--diff-filter=ACMR", rev]
    proc = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git diff failed for {rev}")
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def read_changed_files(args: argparse.Namespace) -> list[str]:
    files: list[str] = []
    if args.changed_file:
        files.extend(args.changed_file)
    if args.changed_file_list:
        p = Path(args.changed_file_list)
        if not p.is_file():
            raise RuntimeError(f"missing changed-file-list: {p}")
        files.extend([line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()])
    if files:
        dedup: OrderedDict[str, None] = OrderedDict()
        for f in files:
            dedup[f] = None
        return list(dedup.keys())
    return git_diff_files(args.base, args.head)


def select_targets(files: list[str], all_if_empty: bool) -> tuple[list[str], dict[str, list[str]]]:
    matched_by_target: dict[str, list[str]] = OrderedDict((rule.target, []) for rule in RULES)
    for path in files:
        for rule in RULES:
            if any(pat.search(path) for pat in rule.patterns):
                matched_by_target[rule.target].append(path)
    selected = [target for target, paths in matched_by_target.items() if paths]
    if not selected and all_if_empty:
        selected = [rule.target for rule in RULES]
    return selected, matched_by_target


def format_output(targets: list[str], fmt: str) -> str:
    if fmt == "make":
        return " ".join(targets)
    if fmt == "json":
        return json.dumps(targets)
    return "\n".join(targets)


def markdown_report(
    base: str,
    head: str,
    files: list[str],
    selected: list[str],
    matched_by_target: dict[str, list[str]],
) -> str:
    lines: list[str] = []
    lines.append("## Focused Targets")
    lines.append("")
    lines.append(f"- diff: `{base}...{head}`")
    lines.append(f"- changed files: `{len(files)}`")
    lines.append(f"- selected targets: `{len(selected)}`")
    lines.append("")
    if selected:
        for target in selected:
            lines.append(f"- `{target}`")
    else:
        lines.append("- (none)")
    lines.append("")
    lines.append("### Target Evidence")
    lines.append("")
    for target, matched in matched_by_target.items():
        lines.append(f"- `{target}`: {len(matched)} file(s)")
        for path in matched[:8]:
            lines.append(f"  - `{path}`")
        if len(matched) > 8:
            lines.append(f"  - ... +{len(matched) - 8} more")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Select focused test targets for high-conflict subsystems from changed files"
    )
    parser.add_argument("--base", default="origin/main", help="Diff base ref (default: origin/main)")
    parser.add_argument("--head", default="HEAD", help="Diff head ref (default: HEAD)")
    parser.add_argument(
        "--changed-file",
        action="append",
        default=[],
        help="Changed file path (repeatable); skips git diff when provided",
    )
    parser.add_argument(
        "--changed-file-list",
        default="",
        help="Path to newline-separated changed files; skips git diff when provided",
    )
    parser.add_argument(
        "--all-if-empty",
        action="store_true",
        help="Select all focused targets when no file matches",
    )
    parser.add_argument(
        "--format",
        choices=("lines", "make", "json"),
        default="lines",
        help="Output format (default: lines)",
    )
    parser.add_argument("--json-out", default="", help="Optional JSON report output path")
    parser.add_argument("--markdown-out", default="", help="Optional markdown report output path")
    args = parser.parse_args()

    try:
        files = read_changed_files(args)
    except RuntimeError as exc:
        print(f"select-focused-targets: {exc}", file=sys.stderr)
        return 2

    selected, matched_by_target = select_targets(files, args.all_if_empty)
    payload = {
        "schema_version": 1,
        "base": args.base,
        "head": args.head,
        "changed_files": files,
        "selected_targets": selected,
        "matched_by_target": matched_by_target,
    }

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.markdown_out:
        out = Path(args.markdown_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            markdown_report(args.base, args.head, files, selected, matched_by_target),
            encoding="utf-8",
        )

    print(format_output(selected, args.format))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
