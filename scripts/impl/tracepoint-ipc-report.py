#!/usr/bin/env python3
"""
Summarize Kairos IPC tracepoint export from /sys/kernel/tracepoint/ipc_events.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from typing import Iterable


TRACE_IPC_FLAG_VERSION_SHIFT = 28
TRACE_IPC_FLAG_VERSION_MASK = 0xF
TRACE_IPC_FLAG_OP_SHIFT = 0
TRACE_IPC_FLAG_OP_MASK = 0xFF
TRACE_IPC_FLAG_WAKE_SHIFT = 8
TRACE_IPC_FLAG_WAKE_MASK = 0xF
TRACE_IPC_FLAG_SELF_STATE_SHIFT = 12
TRACE_IPC_FLAG_SELF_STATE_MASK = 0xF
TRACE_IPC_FLAG_PEER_STATE_SHIFT = 16
TRACE_IPC_FLAG_PEER_STATE_MASK = 0xF


def op_name(op: int) -> str:
    return {
        1: "send_epipe",
        2: "recv_eof",
        3: "close_local",
        4: "close_peer",
    }.get(op, "unknown")


def wake_name(wake: int) -> str:
    return {
        0: "none",
        1: "data",
        2: "hup",
        3: "close",
        4: "signal",
        5: "timeout",
    }.get(wake, "unknown")


def state_name(state: int) -> str:
    return {
        0: "unknown",
        1: "open",
        2: "closing",
        3: "closed",
    }.get(state, "unknown")


@dataclass
class Event:
    ticks: int
    cpu: int
    seq: int
    pid: int
    event: str
    flags: int
    version: int
    op: int
    wake: int
    self_state: int
    peer_state: int
    self_id: int
    peer_id: int
    arg1: int


def decode_from_flags(flags: int) -> tuple[int, int, int, int, int]:
    version = (flags >> TRACE_IPC_FLAG_VERSION_SHIFT) & TRACE_IPC_FLAG_VERSION_MASK
    op = (flags >> TRACE_IPC_FLAG_OP_SHIFT) & TRACE_IPC_FLAG_OP_MASK
    wake = 0
    self_state = 0
    peer_state = 0
    if version == 1:
        wake = (flags >> TRACE_IPC_FLAG_WAKE_SHIFT) & TRACE_IPC_FLAG_WAKE_MASK
        self_state = (
            (flags >> TRACE_IPC_FLAG_SELF_STATE_SHIFT) & TRACE_IPC_FLAG_SELF_STATE_MASK
        )
        peer_state = (
            (flags >> TRACE_IPC_FLAG_PEER_STATE_SHIFT) & TRACE_IPC_FLAG_PEER_STATE_MASK
        )
    return version, op, wake, self_state, peer_state


def parse_events(lines: Iterable[str]) -> list[Event]:
    events: list[Event] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        try:
            if len(parts) >= 14:
                ticks = int(parts[0], 0)
                cpu = int(parts[1], 0)
                seq = int(parts[2], 0)
                pid = int(parts[3], 0)
                event = parts[4]
                flags = int(parts[5], 0)
                self_id = int(parts[11], 0)
                peer_id = int(parts[12], 0)
                arg1 = int(parts[13], 0)
                version, op, wake, self_state, peer_state = decode_from_flags(flags)
            elif len(parts) == 8:
                ticks = int(parts[0], 0)
                cpu = int(parts[1], 0)
                seq = int(parts[2], 0)
                pid = int(parts[3], 0)
                event = parts[4]
                flags = int(parts[5], 0)
                arg0 = int(parts[6], 0)
                arg1 = int(parts[7], 0)
                self_id = (arg0 >> 32) & 0xFFFFFFFF
                peer_id = arg0 & 0xFFFFFFFF
                version, op, wake, self_state, peer_state = decode_from_flags(flags)
            else:
                continue
        except ValueError:
            continue
        events.append(
            Event(
                ticks=ticks,
                cpu=cpu,
                seq=seq,
                pid=pid,
                event=event,
                flags=flags,
                version=version,
                op=op,
                wake=wake,
                self_state=self_state,
                peer_state=peer_state,
                self_id=self_id,
                peer_id=peer_id,
                arg1=arg1,
            )
        )
    return events


def build_summary(events: list[Event]) -> dict:
    by_event = Counter(e.event for e in events)
    by_cpu = Counter(e.cpu for e in events)
    by_pid = Counter(e.pid for e in events)
    by_version = Counter(e.version for e in events)
    by_op = Counter(op_name(e.op) for e in events)
    by_wake = Counter(wake_name(e.wake) for e in events)
    by_self_state = Counter(state_name(e.self_state) for e in events)
    by_peer_state = Counter(state_name(e.peer_state) for e in events)
    by_self_id = Counter(e.self_id for e in events if e.self_id != 0)
    by_pair = Counter(
        f"{e.self_id}->{e.peer_id}" for e in events if e.self_id != 0 or e.peer_id != 0
    )

    return {
        "total": len(events),
        "by_event": dict(by_event),
        "by_cpu": dict(by_cpu),
        "by_pid_top10": dict(by_pid.most_common(10)),
        "by_version": dict(by_version),
        "by_op": dict(by_op),
        "by_wake": dict(by_wake),
        "by_self_state": dict(by_self_state),
        "by_peer_state": dict(by_peer_state),
        "channel_top10": dict(by_self_id.most_common(10)),
        "pair_top10": dict(by_pair.most_common(10)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input",
        nargs="?",
        default="/sys/kernel/tracepoint/ipc_events",
        help="Path to tracepoint ipc_events export (default: %(default)s)",
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
    print(f"schema version: {summary['by_version']}")
    print(f"by op:          {summary['by_op']}")
    print(f"by wake:        {summary['by_wake']}")
    print(f"self state:     {summary['by_self_state']}")
    print(f"peer state:     {summary['by_peer_state']}")
    print(f"top channels:   {summary['channel_top10']}")
    print(f"top pairs:      {summary['pair_top10']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
