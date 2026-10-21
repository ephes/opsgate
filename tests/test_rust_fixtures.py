"""Drift guard for the Rust port's shared fixtures (rust/PLAN.md 7.2).

The fixtures in ``rust/fixtures`` are generated from this Python package and
pin the behaviour the Rust port must reproduce. A Python change that alters
any of them must regenerate the files (``just rs-fixtures``), which then
shows the Rust side what to change.
"""

from __future__ import annotations

import importlib.util
import shutil
import sqlite3
import sys
from pathlib import Path
from types import ModuleType

import pytest

GENERATOR_PATH = Path(__file__).resolve().parents[1] / "rust" / "fixtures" / "generate.py"


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rust_fixture_generator", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_committed_fixtures_match_the_python_implementation(generator: ModuleType) -> None:
    stale = generator.check_fixtures()
    assert not stale, f"stale Rust fixtures {stale}: run `just rs-fixtures` and update the Rust side to match"


def test_every_committed_fixture_has_a_generator(generator: ModuleType) -> None:
    committed = {
        path.name for path in generator.FIXTURES_DIR.iterdir() if path.is_file() and path.suffix in {".json", ".sql"}
    }
    assert committed == set(generator.GENERATORS)


def test_drift_check_detects_a_hand_edited_or_missing_fixture(generator: ModuleType, tmp_path: Path) -> None:
    assert generator.write_fixtures(tmp_path) == [tmp_path / name for name in sorted(generator.GENERATORS)]
    assert generator.check_fixtures(tmp_path) == []

    edited = tmp_path / "schema.sql"
    text = edited.read_text(encoding="utf-8")
    assert "max_duration_seconds INTEGER NOT NULL" in text
    edited.write_text(text.replace("max_duration_seconds INTEGER NOT NULL", "max_duration_seconds INTEGER", 1))
    assert generator.check_fixtures(tmp_path) == ["schema.sql"]

    # Whitespace and line endings count: the files are compared as bytes.
    edited.write_bytes(text.encode("utf-8").replace(b"\n", b"\r\n"))
    assert generator.check_fixtures(tmp_path) == ["schema.sql"]

    edited.unlink()
    assert generator.check_fixtures(tmp_path) == ["schema.sql"]


def test_check_option_exits_1_on_drift(
    generator: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in generator.GENERATORS:
        shutil.copy(generator.FIXTURES_DIR / name, tmp_path / name)
    monkeypatch.setattr(generator, "FIXTURES_DIR", tmp_path)
    assert generator.main(["--check"]) == 0

    (tmp_path / "schema.sql").write_text("-- edited\n", encoding="utf-8")
    assert generator.main(["--check"]) == 1
    assert "stale fixture: schema.sql" in capsys.readouterr().err


def test_schema_fixture_is_the_python_schema(generator: ModuleType, tmp_path: Path) -> None:
    """``schema.sql`` runs as one script and yields the objects of a
    Python-initialised database (PLAN.md 4.10)."""
    from opsgate.service import OpsGateService

    python_db = tmp_path / "python.sqlite3"
    OpsGateService(generator._settings(python_db)).init_db()
    fixture_db = tmp_path / "fixture.sqlite3"
    with sqlite3.connect(fixture_db) as connection:
        connection.executescript((generator.FIXTURES_DIR / "schema.sql").read_text(encoding="utf-8"))

    def objects(path: Path) -> list[tuple[str, str, str]]:
        connection = sqlite3.connect(path)
        try:
            return connection.execute(
                "SELECT type, name, tbl_name FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name"
            ).fetchall()
        finally:
            connection.close()

    assert objects(fixture_db) == objects(python_db)
    assert {name for kind, name, _ in objects(python_db) if kind == "table"} == {
        "audit_events",
        "runner_heartbeats",
        "sqlite_sequence",
        "tickets",
        "ui_session_state",
    }
