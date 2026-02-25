#!/usr/bin/env python3
"""
Compute rolling CI gate failure-rate statistics from GitHub Actions history.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"

FAIL_CONCLUSIONS = {
    "failure",
    "timed_out",
    "startup_failure",
    "action_required",
}

PASS_CONCLUSIONS = {"success"}

@dataclass(frozen=True)
class GateSpec:
    gate: str
    job: str
    step: Optional[str] = None


WORKFLOW_GATES = {
    "ci-quick.yml": [
        GateSpec(gate="riscv64-test", job="riscv64-test"),
        GateSpec(gate="x86_64-gates", job="x86_64-gates"),
        GateSpec(
            gate="x86_64-syscall-trap",
            job="x86_64-gates",
            step="Run x86_64 syscall/trap gate",
        ),
        GateSpec(
            gate="x86_64-vfs-ipc",
            job="x86_64-gates",
            step="Run x86_64 vfs/ipc gate",
        ),
        GateSpec(gate="x86_64-driver", job="x86_64-gates", step="Run x86_64 driver gate"),
        GateSpec(gate="x86_64-socket", job="x86_64-gates", step="Run x86_64 socket gate"),
        GateSpec(
            gate="x86_64-tcc-smoke",
            job="x86_64-gates",
            step="Run x86_64 tcc smoke gate",
        ),
        GateSpec(gate="aarch64-smoke", job="aarch64-smoke"),
        GateSpec(gate="aarch64-smp4-gate", job="aarch64-smp4-gate"),
    ],
    "soak-long.yml": [
        GateSpec(gate="riscv64-soak-pr", job="riscv64-soak-pr"),
        GateSpec(gate="x86_64-soak-pr", job="x86_64-soak-pr"),
        GateSpec(gate="aarch64-soak-pr", job="aarch64-soak-pr"),
        GateSpec(
            gate="aarch64-vfs-ipc-loop",
            job="aarch64-soak-pr",
            step="Run aarch64 directed vfs/ipc loop profile",
        ),
        GateSpec(
            gate="aarch64-socket-loop",
            job="aarch64-soak-pr",
            step="Run aarch64 directed socket loop profile",
        ),
        GateSpec(
            gate="aarch64-driver-loop",
            job="aarch64-soak-pr",
            step="Run aarch64 directed driver loop profile",
        ),
        GateSpec(
            gate="aarch64-soak-pr-step",
            job="aarch64-soak-pr",
            step="Run aarch64 soak-pr profile",
        ),
    ],
}


@dataclass
class GateStats:
    workflow: str
    gate: str
    source_job: str
    source_step: Optional[str]
    window_runs: int
    evaluated: int
    pass_count: int
    fail_count: int
    missing_count: int
    ignored_count: int
    ignored_by_conclusion: Dict[str, int]

    @property
    def fail_rate_percent(self) -> float:
        if self.evaluated == 0:
            return 0.0
        return (self.fail_count * 100.0) / self.evaluated


class GitHubClient:
    def __init__(self, repo: str, token: str):
        self.repo = repo
        self.token = token

    def _get_json(self, path: str) -> dict:
        url = f"{API_BASE}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def list_completed_runs(self, workflow_file: str, limit: int) -> List[dict]:
        encoded = urllib.parse.quote(workflow_file, safe="")
        runs: List[dict] = []
        page = 1
        while len(runs) < limit:
            path = (
                f"/repos/{self.repo}/actions/workflows/{encoded}/runs"
                f"?status=completed&per_page=100&page={page}"
            )
            payload = self._get_json(path)
            items = payload.get("workflow_runs", [])
            if not items:
                break
            runs.extend(items)
            if len(items) < 100:
                break
            page += 1
        return runs[:limit]

    def list_jobs_for_run(self, run_id: int) -> List[dict]:
        jobs: List[dict] = []
        page = 1
        while True:
            path = (
                f"/repos/{self.repo}/actions/runs/{run_id}/jobs"
                f"?per_page=100&page={page}"
            )
            payload = self._get_json(path)
            items = payload.get("jobs", [])
            if not items:
                break
            jobs.extend(items)
            if len(items) < 100:
                break
            page += 1
        return jobs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate rolling CI gate flake/failure statistics."
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="GitHub repository in owner/name format (default: GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=20,
        help="Number of latest completed runs per workflow to inspect",
    )
    parser.add_argument(
        "--json-out",
        default="ci-flake-report.json",
        help="Path to write JSON report",
    )
    parser.add_argument(
        "--markdown-out",
        default="ci-flake-report.md",
        help="Path to write Markdown report",
    )
    return parser.parse_args()


def pick_job_by_name(jobs: List[dict], name: str) -> Optional[dict]:
    matches = [job for job in jobs if job.get("name") == name]
    if not matches:
        return None

    def key(job: dict) -> Tuple[str, int]:
        completed_at = job.get("completed_at") or ""
        job_id = int(job.get("id") or 0)
        return (completed_at, job_id)

    return sorted(matches, key=key)[-1]


def pick_step_by_name(job: dict, name: str) -> Optional[dict]:
    steps = job.get("steps") or []
    matches = [step for step in steps if step.get("name") == name]
    if not matches:
        return None

    def key(step: dict) -> Tuple[int, str]:
        number = int(step.get("number") or 0)
        completed_at = step.get("completed_at") or ""
        return (number, completed_at)

    return sorted(matches, key=key)[-1]


def compute_gate_stats(client: GitHubClient, sample_size: int) -> List[GateStats]:
    out: List[GateStats] = []
    for workflow_file, gate_specs in WORKFLOW_GATES.items():
        runs = client.list_completed_runs(workflow_file, sample_size)
        window_runs = len(runs)
        run_jobs: Dict[int, List[dict]] = {}
        for run in runs:
            run_id = int(run["id"])
            run_jobs[run_id] = client.list_jobs_for_run(run_id)

        for gate_spec in gate_specs:
            pass_count = 0
            fail_count = 0
            missing_count = 0
            ignored_count = 0
            ignored_by_conclusion: Dict[str, int] = {}
            for run in runs:
                run_id = int(run["id"])
                job = pick_job_by_name(run_jobs.get(run_id, []), gate_spec.job)
                if job is None:
                    missing_count += 1
                    continue

                if gate_spec.step is None:
                    conclusion = (job.get("conclusion") or "unknown").lower()
                else:
                    step = pick_step_by_name(job, gate_spec.step)
                    if step is None:
                        missing_count += 1
                        continue
                    conclusion = (step.get("conclusion") or "unknown").lower()

                if conclusion in PASS_CONCLUSIONS:
                    pass_count += 1
                elif conclusion in FAIL_CONCLUSIONS:
                    fail_count += 1
                else:
                    ignored_count += 1
                    ignored_by_conclusion[conclusion] = (
                        ignored_by_conclusion.get(conclusion, 0) + 1
                    )

            evaluated = pass_count + fail_count
            out.append(
                GateStats(
                    workflow=workflow_file,
                    gate=gate_spec.gate,
                    source_job=gate_spec.job,
                    source_step=gate_spec.step,
                    window_runs=window_runs,
                    evaluated=evaluated,
                    pass_count=pass_count,
                    fail_count=fail_count,
                    missing_count=missing_count,
                    ignored_count=ignored_count,
                    ignored_by_conclusion=ignored_by_conclusion,
                )
            )
    return out


def render_markdown(
    repo: str,
    sample_size: int,
    generated_at: str,
    rows: List[GateStats],
) -> str:
    lines: List[str] = []
    lines.append("# CI Flake Report")
    lines.append("")
    lines.append(f"- Repo: `{repo}`")
    lines.append(f"- Window: latest `{sample_size}` completed runs per workflow")
    lines.append(f"- Generated at: `{generated_at}`")
    lines.append("")
    lines.append(
        "| Workflow | Gate | Source | Evaluated | Pass | Fail | Fail Rate | Missing | Ignored |"
    )
    lines.append("|---|---|---|---:|---:|---:|---:|---:|---:|")
    for row in rows:
        source = row.source_job
        if row.source_step:
            source = f"{row.source_job} / {row.source_step}"
        lines.append(
            "| {workflow} | {gate} | {source} | {evaluated} | {pass_count} | {fail_count} | "
            "{rate:.2f}% | {missing_count} | {ignored_count} |".format(
                workflow=row.workflow,
                gate=row.gate,
                source=source,
                evaluated=row.evaluated,
                pass_count=row.pass_count,
                fail_count=row.fail_count,
                rate=row.fail_rate_percent,
                missing_count=row.missing_count,
                ignored_count=row.ignored_count,
            )
        )

    lines.append("")
    lines.append("Ignored conclusion breakdown:")
    for row in rows:
        if not row.ignored_by_conclusion:
            continue
        parts = [f"{k}={v}" for k, v in sorted(row.ignored_by_conclusion.items())]
        lines.append(f"- `{row.workflow}` / `{row.gate}`: {', '.join(parts)}")

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    if not args.repo:
        print("ci-flake-report: --repo or GITHUB_REPOSITORY is required", file=sys.stderr)
        return 2
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("ci-flake-report: GITHUB_TOKEN is required", file=sys.stderr)
        return 2
    if args.sample_size < 1:
        print("ci-flake-report: --sample-size must be >= 1", file=sys.stderr)
        return 2

    client = GitHubClient(repo=args.repo, token=token)
    rows = compute_gate_stats(client, args.sample_size)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    json_doc = {
        "schema_version": 1,
        "repo": args.repo,
        "sample_size": args.sample_size,
        "generated_at_utc": now,
        "gates": [
            {
                "workflow": row.workflow,
                "gate": row.gate,
                "source_job": row.source_job,
                "source_step": row.source_step,
                "window_runs": row.window_runs,
                "evaluated": row.evaluated,
                "pass_count": row.pass_count,
                "fail_count": row.fail_count,
                "fail_rate_percent": round(row.fail_rate_percent, 4),
                "missing_count": row.missing_count,
                "ignored_count": row.ignored_count,
                "ignored_by_conclusion": row.ignored_by_conclusion,
            }
            for row in rows
        ],
    }

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(json_doc, f, indent=2, sort_keys=True)
        f.write("\n")

    markdown = render_markdown(args.repo, args.sample_size, now, rows)
    with open(args.markdown_out, "w", encoding="utf-8") as f:
        f.write(markdown)

    print(f"ci-flake-report: wrote {args.json_out}")
    print(f"ci-flake-report: wrote {args.markdown_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
