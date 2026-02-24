#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path


def fail(msg: str) -> int:
    print(f"assert-result-pass: {msg}", file=sys.stderr)
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Assert Kairos result.json indicates pass")
    parser.add_argument("result_path", help="Path to result.json")
    parser.add_argument(
        "--require-structured",
        action="store_true",
        help="Require structured verdict and summary consistency checks",
    )
    args = parser.parse_args()

    path = Path(args.result_path)
    if not path.is_file():
        return fail(f"missing result file: {path}")

    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return fail(f"invalid JSON in {path}: {exc}")

    status = str(obj.get("status", ""))
    reason = str(obj.get("reason", ""))
    if status != "pass":
        return fail(f"status is not pass (status={status!r}, reason={reason!r}, file={path})")

    if not args.require_structured:
        print(f"assert-result-pass: PASS ({path})")
        return 0

    verdict_source = str(obj.get("verdict_source", ""))
    if verdict_source != "structured":
        return fail(
            f"verdict_source is not structured (verdict_source={verdict_source!r}, file={path})"
        )

    structured = obj.get("structured")
    if not isinstance(structured, dict):
        return fail(f"structured block missing in {path}")

    summary = obj.get("summary")
    if not isinstance(summary, dict):
        return fail(f"summary block missing in {path}")

    structured_status = str(structured.get("status", ""))
    structured_done = structured.get("done")
    structured_failed = structured.get("failed")
    summary_status = str(summary.get("status", ""))
    summary_failed = summary.get("failed")

    if structured_status != "ok":
        return fail(f"structured.status is not ok (got {structured_status!r}, file={path})")
    if structured_done is not True:
        return fail(f"structured.done is not true (got {structured_done!r}, file={path})")
    if not isinstance(structured_failed, int):
        return fail(f"structured.failed is not int (got {structured_failed!r}, file={path})")
    if summary_status != "ok":
        return fail(f"summary.status is not ok (got {summary_status!r}, file={path})")
    if not isinstance(summary_failed, int):
        return fail(f"summary.failed is not int (got {summary_failed!r}, file={path})")
    if summary_failed != structured_failed:
        return fail(
            "summary/structured failed mismatch "
            f"(summary_failed={summary_failed}, structured_failed={structured_failed}, file={path})"
        )
    if structured_failed != 0:
        return fail(f"structured.failed is not 0 (got {structured_failed}, file={path})")

    print(f"assert-result-pass: PASS (structured, {path})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
