"""Diff the records of the runner parity harness (rust/PLAN.md 7.4).

Usage::

    python rust/parity/runner/compare.py RECORDS_DIR [RECORDS_DIR ...] [--require-rust]

Every record (written by ``pytest rust/parity/runner --records DIR``) names its
scenario and its stack (API: ``fake``, ``python`` or ``rust``; the runner
implementations in start order). For each scenario the all-Python stack is
the baseline (every all-Python record of a scenario must have passed and agree
with the first); every other stack that ran must have passed and must have
observed exactly the same normalised values. Skipped stacks are counted, not
compared. Exit status 1 on any difference, a failed stack, a scenario without
a passing baseline, or (with ``--require-rust``) when no Rust stack ran.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

MAX_DIFFS_PER_STACK = 20


def is_python_only(stack: dict[str, Any]) -> bool:
    return stack.get("api") in {"fake", "python"} and all(r == "python" for r in stack.get("runners", []))


def stack_label(stack: dict[str, Any]) -> str:
    return f"api={stack.get('api')} runners={'>'.join(stack.get('runners', []))}"


def diff(a: Any, b: Any, path: str = "") -> Iterator[tuple[str, Any, Any]]:
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            sub = f"{path}/{key}"
            if key not in a:
                yield sub, "<missing>", b[key]
            elif key not in b:
                yield sub, a[key], "<missing>"
            else:
                yield from diff(a[key], b[key], sub)
    elif isinstance(a, list) and isinstance(b, list):
        for index in range(max(len(a), len(b))):
            sub = f"{path}[{index}]"
            if index >= len(a):
                yield sub, "<missing>", b[index]
            elif index >= len(b):
                yield sub, a[index], "<missing>"
            else:
                yield from diff(a[index], b[index], sub)
    elif a != b or type(a) is not type(b):
        yield path or "/", a, b


def load(dirs: list[Path]) -> dict[str, list[dict[str, Any]]]:
    scenarios: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for directory in dirs:
        for path in sorted(directory.glob("*.json")):
            record = json.loads(path.read_text(encoding="utf-8"))
            record["_file"] = str(path)
            scenarios[str(record["scenario"])].append(record)
    return scenarios


def compare(scenarios: dict[str, list[dict[str, Any]]], *, require_rust: bool = False) -> tuple[list[str], int]:
    """Return (problems, number of compared non-baseline stacks)."""
    problems: list[str] = []
    compared = 0
    for name in sorted(scenarios):
        records = scenarios[name]
        ran = [r for r in records if r["outcome"] != "skipped"]
        baselines = [r for r in ran if is_python_only(r["stack"])]
        others = [r for r in ran if not is_python_only(r["stack"])]
        if not baselines:
            if others:
                problems.append(f"{name}: no all-Python baseline record")
            continue
        failed = [b for b in baselines if b["outcome"] != "passed"]
        for record in failed:
            problems.append(f"{name}: baseline {stack_label(record['stack'])} {record['outcome']} ({record['_file']})")
        if failed:
            continue
        baseline = baselines[0]
        # Further all-Python records (several record directories, cross stacks) must agree with the first.
        checks = [(record, True) for record in baselines[1:]] + [(record, False) for record in others]
        for record, is_baseline in checks:
            label = stack_label(record["stack"])
            if is_baseline:
                label = f"{label} (second baseline {record['_file']})"
            else:
                compared += 1
            if record["outcome"] != "passed":
                problems.append(f"{name}: {label} {record['outcome']}")
            differences = list(diff(baseline["observed"], record["observed"]))
            for path, left, right in differences[:MAX_DIFFS_PER_STACK]:
                left_text, right_text = json.dumps(left)[:300], json.dumps(right)[:300]
                problems.append(f"{name}: {label} differs at {path}: python={left_text} other={right_text}")
            if len(differences) > MAX_DIFFS_PER_STACK:
                problems.append(f"{name}: {label}: {len(differences) - MAX_DIFFS_PER_STACK} more differences")
    if require_rust and compared == 0:
        problems.append("no Rust stack ran (all skipped or missing)")
    return problems, compared


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("dirs", nargs="+", type=Path)
    parser.add_argument("--require-rust", action="store_true", help="fail when no Rust stack ran")
    args = parser.parse_args(argv)
    scenarios = load(args.dirs)
    problems, compared = compare(scenarios, require_rust=args.require_rust)
    skipped = sum(1 for records in scenarios.values() for r in records if r["outcome"] == "skipped")
    print(f"{len(scenarios)} scenarios, {compared} non-baseline stacks compared, {skipped} skipped")
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
