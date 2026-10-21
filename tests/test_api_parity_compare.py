"""The record comparison of the API parity harness (rust/parity/api/compare.py, rust/PLAN.md 7.3)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

COMPARE = Path(__file__).resolve().parents[1] / "rust" / "parity" / "api" / "compare.py"


def load_compare() -> ModuleType:
    spec = importlib.util.spec_from_file_location("api_parity_compare", COMPARE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


compare = load_compare()


def record(steps: Any, outcome: str = "passed", divergences: list[str] | None = None) -> dict[str, Any]:
    return {"outcome": outcome, "steps": steps, "db": {}, "divergences": divergences or []}


def write(directory: Path, **records: dict[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, item in records.items():
        (directory / f"{name}.json").write_text(json.dumps(item), encoding="utf-8")
    return directory


def test_equal_records_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    python = write(tmp_path / "python", a=record([{"status": 200}]))
    rust = write(tmp_path / "rust", a=record([{"status": 200}]))
    assert compare.main([str(python), str(rust), "--complete"]) == 0
    assert "1 equal" in capsys.readouterr().out


def test_differences_fail_unless_explained(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    python = write(tmp_path / "python", a=record([{"status": 200}]), b=record([1], divergences=["D-2"]))
    rust = write(tmp_path / "rust", a=record([{"status": 201}]), b=record([2], divergences=["D-2"]))
    assert compare.main([str(python), str(rust)]) == 1
    out = capsys.readouterr().out
    assert "DIFFERENT a.json" in out and "/steps[0]/status: 200 != 201" in out
    assert "explained b.json (D-2)" in out


def test_failed_scenario_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    python = write(tmp_path / "python", a=record([]))
    rust = write(tmp_path / "rust", a=record([], outcome="failed"))
    assert compare.main([str(python), str(rust)]) == 1
    assert "NOT PASSED a.json" in capsys.readouterr().out


def test_complete_fails_on_one_sided_scenarios(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    python = write(tmp_path / "python", a=record([]), b=record([]))
    rust = write(tmp_path / "rust", a=record([]))
    assert compare.main([str(python), str(rust)]) == 0
    assert compare.main([str(python), str(rust), "--complete"]) == 1
    assert "ONLY IN python b.json" in capsys.readouterr().out
