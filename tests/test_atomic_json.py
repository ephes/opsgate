from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from opsgate.runner import _atomic_write_json


@pytest.mark.parametrize("failure", ["serialize", "write", "replace"])
def test_failed_publication_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    destination = tmp_path / "state.json"
    destination.write_bytes(b"previous state")
    error = OSError("injected failure")
    invoked = False

    def fail(*args: Any, **kwargs: Any) -> None:
        nonlocal invoked
        invoked = True
        if failure == "write":
            args[1].write("partial JSON")
        raise error

    payload: dict[str, Any] = {"state": "running"}
    if failure == "serialize":
        payload["invalid"] = object()
    elif failure == "write":
        monkeypatch.setattr("opsgate.runner.json.dump", fail)
    else:
        monkeypatch.setattr(Path, "replace", fail)

    with pytest.raises(TypeError if failure == "serialize" else OSError) as caught:
        _atomic_write_json(destination, payload)
    if failure != "serialize":
        assert invoked
        assert caught.value is error
    assert destination.read_bytes() == b"previous state"
    assert list(tmp_path.iterdir()) == [destination]


def test_successful_publication_is_private(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "state.json"
    _atomic_write_json(destination, {"state": "running"})
    assert json.loads(destination.read_text()) == {"state": "running"}
    assert destination.read_bytes().endswith(b"\n")
    assert destination.stat().st_mode & 0o777 == 0o600
    assert list(destination.parent.iterdir()) == [destination]


def test_cleanup_refusal_preserves_publication_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    destination = tmp_path / "state.json"
    destination.write_bytes(b"previous state")
    publication_error = OSError("replace failed")
    cleanup_error = OSError("unlink failed")
    cleanup_attempted = False

    def fail_replace(*args: Any, **kwargs: Any) -> None:
        raise publication_error

    def fail_unlink(*args: Any, **kwargs: Any) -> None:
        nonlocal cleanup_attempted
        cleanup_attempted = True
        raise cleanup_error

    monkeypatch.setattr(Path, "replace", fail_replace)
    monkeypatch.setattr(Path, "unlink", fail_unlink)
    with pytest.raises(OSError) as caught:
        _atomic_write_json(destination, {"state": "running"})
    assert cleanup_attempted
    assert caught.value is publication_error
    assert destination.read_bytes() == b"previous state"


def test_success_does_not_unlink_released_temp_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse_unlink(*args: Any, **kwargs: Any) -> None:
        pytest.fail("successful publication must not unlink the released temp name")

    monkeypatch.setattr(Path, "unlink", refuse_unlink)
    destination = tmp_path / "state.json"
    _atomic_write_json(destination, {"state": "running"})
    assert json.loads(destination.read_text()) == {"state": "running"}
