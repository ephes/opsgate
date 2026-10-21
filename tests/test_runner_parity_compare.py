"""The record comparison of the runner parity harness (rust/parity/runner/compare.py, rust/PLAN.md 7.4)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

COMPARE = Path(__file__).resolve().parents[1] / "rust" / "parity" / "runner" / "compare.py"


def load_compare() -> ModuleType:
    spec = importlib.util.spec_from_file_location("runner_parity_compare", COMPARE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


compare = load_compare()


def record(scenario: str, api: str, runners: list[str], observed: Any, outcome: str = "passed") -> dict[str, Any]:
    return {"scenario": scenario, "stack": {"api": api, "runners": runners}, "outcome": outcome, "observed": observed}


def write(directory: Path, *records: dict[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for number, item in enumerate(records):
        (directory / f"{number}.json").write_text(json.dumps(item), encoding="utf-8")
    return directory


def test_equal_records_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    python = write(tmp_path / "py", record("s", "fake", ["python"], {"a": [1, {"b": "x"}]}))
    rust = write(tmp_path / "rs", record("s", "fake", ["rust"], {"a": [1, {"b": "x"}]}))
    assert compare.main([str(python), str(rust), "--require-rust"]) == 0
    assert "1 non-baseline stacks compared" in capsys.readouterr().out


def test_differences_fail_with_their_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    python = write(tmp_path / "py", record("s", "fake", ["python", "python"], {"a": [1, {"b": "x"}], "c": 1}))
    rust = write(tmp_path / "rs", record("s", "fake", ["python", "rust"], {"a": [1, {"b": "y"}, 2]}))
    assert compare.main([str(python), str(rust)]) == 1
    out = capsys.readouterr().out
    assert '/a[1]/b: python="x" other="y"' in out
    assert '/a[2]: python="<missing>" other=2' in out
    assert '/c: python=1 other="<missing>"' in out


def test_types_are_compared(tmp_path: Path) -> None:
    python = write(tmp_path / "py", record("s", "fake", ["python"], {"a": 1}))
    rust = write(tmp_path / "rs", record("s", "fake", ["rust"], {"a": 1.0}))
    assert compare.main([str(python), str(rust)]) == 1


def test_failed_stack_and_missing_baseline_fail(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    records = write(
        tmp_path / "r",
        record("s", "python", ["python"], {}),
        record("s", "rust", ["python"], {}, outcome="failed"),
        record("t", "rust", ["rust"], {}),
    )
    assert compare.main([str(records)]) == 1
    out = capsys.readouterr().out
    assert "s: api=rust runners=python failed" in out
    assert "t: no all-Python baseline record" in out


def test_require_rust_fails_without_rust_records(tmp_path: Path) -> None:
    python = write(
        tmp_path / "py",
        record("s", "fake", ["python"], {}),
        record("u", "fake", ["rust"], {}, outcome="skipped"),
    )
    assert compare.main([str(python)]) == 0
    assert compare.main([str(python), "--require-rust"]) == 1


def test_every_baseline_is_checked(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    first = write(tmp_path / "a", record("s", "fake", ["python"], {"a": 1}), record("t", "fake", ["python"], {}))
    second = write(
        tmp_path / "b",
        record("s", "fake", ["python"], {"a": 2}),
        record("t", "fake", ["python"], {}, outcome="failed"),
    )
    assert compare.main([str(first), str(second)]) == 1
    out = capsys.readouterr().out
    assert "s: api=fake runners=python (second baseline" in out and "differs at /a" in out
    assert "t: baseline api=fake runners=python failed" in out


def test_complete_fails_on_a_skipped_stack(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    python = write(tmp_path / "py", record("s", "fake", ["python"], {"a": 1}))
    rust = write(
        tmp_path / "rs",
        record("s", "fake", ["rust"], {"a": 1}),
        record("s", "rust", ["rust"], {}, outcome="skipped"),
    )
    assert compare.main([str(python), str(rust), "--require-rust"]) == 0
    assert compare.main([str(python), str(rust), "--require-rust", "--complete"]) == 1
    assert "s: api=rust runners=rust skipped" in capsys.readouterr().out
