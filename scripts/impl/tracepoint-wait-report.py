#!/usr/bin/env python3
"""
Summarize Kairos wait tracepoint export from /sys/kernel/tracepoint/wait_events.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from typing import Iterable


@dataclass
class Event:
    ticks: int
    cpu: int
    seq: int
    pid: int
    event: str
    flags: int
    arg0: int
    arg1: int


def parse_events(lines: Iterable[str]) -> list[Event]:
    events: list[Event] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 8:
            continue
        try:
            events.append(
                Event(
                    ticks=int(parts[0], 0),
                    cpu=int(parts[1], 0),
                    seq=int(parts[2], 0),
                    pid=int(parts[3], 0),
                    event=parts[4],
                    flags=int(parts[5], 0),
                    arg0=int(parts[6], 0),
                    arg1=int(parts[7], 0),
                )
            )
        except ValueError:
            continue
    return events


def build_summary(events: list[Event]) -> dict:
    by_event = Counter(e.event for e in events)
    by_cpu = Counter(e.cpu for e in events)
    by_pid = Counter(e.pid for e in events)

    wait_blocks = [e for e in events if e.event == "wait_block"]
    wait_wakes = [e for e in events if e.event == "wait_wake"]
    wake_one = sum(1 for e in wait_wakes if (e.flags & 0x80000000) != 0)
    wake_all = len(wait_wakes) - wake_one
    block_with_deadline = sum(1 for e in wait_blocks if (e.flags & 0x1) != 0)

    return {
        "total": len(events),
        "by_event": dict(by_event),
        "by_cpu": dict(by_cpu),
        "by_pid_top10": dict(by_pid.most_common(10)),
        "wait_block": {
            "count": len(wait_blocks),
            "with_deadline": block_with_deadline,
            "without_deadline": len(wait_blocks) - block_with_deadline,
        },
        "wait_wake": {
            "count": len(wait_wakes),
            "wake_one": wake_one,
            "wake_all": wake_all,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input",
        nargs="?",
        default="/sys/kernel/tracepoint/wait_events",
        help="Path to tracepoint wait_events export (default: %(default)s)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON summary",
    )
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        events = parse_events(f)

    summary = build_summary(events)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print(f"total events: {summary['total']}")
    print(f"events by type: {summary['by_event']}")
    print(f"events by cpu:  {summary['by_cpu']}")
    print(f"top pids:       {summary['by_pid_top10']}")
    wb = summary["wait_block"]
    ww = summary["wait_wake"]
    print(
        "wait_block: "
        f"count={wb['count']} with_deadline={wb['with_deadline']} "
        f"without_deadline={wb['without_deadline']}"
    )
    print(
        "wait_wake:  "
        f"count={ww['count']} wake_one={ww['wake_one']} wake_all={ww['wake_all']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

