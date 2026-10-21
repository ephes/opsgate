"""Diff the scenario records of two parity runs (rust/PLAN.md 7.3).

Usage::

    python rust/parity/api/compare.py RECORDS_A RECORDS_B [--report FILE]

Each directory holds the records ``pytest rust/parity/api --records DIR``
wrote for one implementation. A scenario recorded by both runs must have
equal records, unless the scenario names a P3 divergence (PLAN.md section 5;
``Recorder.divergence``): then the difference is reported as explained. A
scenario recorded by only one run (the other skipped it, e.g. because the
Rust slice has not landed) is listed, not failed. A scenario that did not
pass in a run fails the comparison. Exit status: 0 when no unexplained
difference was found, 1 otherwise. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load(directory: Path) -> dict[str, dict[str, Any]]:
    return {path.name: json.loads(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.json"))}


def short(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)[:200]


def differences(left: Any, right: Any, path: str = "") -> list[str]:
    if type(left) is not type(right):
        return [f"{path or '/'}: {short(left)} != {short(right)}"]
    if isinstance(left, dict):
        out: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                out.append(f"{path}/{key}: only in {'second' if key not in left else 'first'}")
            else:
                out.extend(differences(left[key], right[key], f"{path}/{key}"))
        return out
    if isinstance(left, list):
        out = [] if len(left) == len(right) else [f"{path}: {len(left)} items != {len(right)} items"]
        for index, (a, b) in enumerate(zip(left, right, strict=False)):
            out.extend(differences(a, b, f"{path}[{index}]"))
        return out
    if left != right:
        return [f"{path or '/'}: {short(left)} != {short(right)}"]
    return []


def compare(first: Path, second: Path) -> dict[str, Any]:
    a, b = load(first), load(second)
    report: dict[str, Any] = {
        "first": str(first),
        "second": str(second),
        "compared": 0,
        "equal": 0,
        "explained": {},
        "different": {},
        "not_passed": {},
        "only_first": sorted(set(a) - set(b)),
        "only_second": sorted(set(b) - set(a)),
    }
    for name in sorted(set(a) & set(b)):
        left, right = a[name], b[name]
        report["compared"] += 1
        outcomes = (left.get("outcome"), right.get("outcome"))
        if outcomes != ("passed", "passed"):
            report["not_passed"][name] = outcomes
            continue
        found = differences(
            {key: left.get(key) for key in ("steps", "db")}, {key: right.get(key) for key in ("steps", "db")}
        )
        divergences = sorted(set(left.get("divergences", [])) | set(right.get("divergences", [])))
        if not found:
            report["equal"] += 1
        elif divergences:
            report["explained"][name] = {"divergences": divergences, "differences": found[:20]}
        else:
            report["different"][name] = found[:50]
    report["ok"] = not report["different"] and not report["not_passed"]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("--report", type=Path, help="write the full report as JSON")
    args = parser.parse_args(argv)
    for directory in (args.first, args.second):
        if not directory.is_dir():
            parser.error(f"{directory} is not a directory")
    report = compare(args.first, args.second)
    if args.report:
        args.report.write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"compared {report['compared']} scenarios: {report['equal']} equal, "
        f"{len(report['explained'])} explained by P3 divergences, {len(report['different'])} different, "
        f"{len(report['not_passed'])} not passed; only in {args.first.name}: {len(report['only_first'])}, "
        f"only in {args.second.name}: {len(report['only_second'])}"
    )
    for name, found in report["different"].items():
        print(f"DIFFERENT {name}")
        for line in found:
            print(f"    {line}")
    for name, outcomes in report["not_passed"].items():
        print(f"NOT PASSED {name}: {outcomes}")
    for name, item in report["explained"].items():
        print(f"explained {name} ({', '.join(item['divergences'])})")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
