from __future__ import annotations

import os
from pathlib import Path

import pytest

from opsgate.config import SettingsError, load_env_file, load_settings


def test_load_env_file_strips_wrapping_quotes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "opsgate.env"
    env_file.write_text(
        "\n".join(
            (
                'OPSGATE_UI_USERNAME="opsgate-admin"',
                "OPSGATE_UI_PASSWORD_BCRYPT='bcrypt-hash'",
                "OPSGATE_BIND_HOST=127.0.0.1",
            )
        ),
        encoding="utf-8",
    )

    monkeypatch.delenv("OPSGATE_UI_USERNAME", raising=False)
    monkeypatch.delenv("OPSGATE_UI_PASSWORD_BCRYPT", raising=False)
    monkeypatch.delenv("OPSGATE_BIND_HOST", raising=False)

    load_env_file(str(env_file))

    assert Path(env_file).exists()
    assert os.environ["OPSGATE_UI_USERNAME"] == "opsgate-admin"
    assert os.environ["OPSGATE_UI_PASSWORD_BCRYPT"] == "bcrypt-hash"
    assert os.environ["OPSGATE_BIND_HOST"] == "127.0.0.1"


def test_load_settings_requires_explicit_session_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / "opsgate.env"
    env_file.write_text(
        "\n".join(
            (
                "OPSGATE_UI_USERNAME=opsgate-admin",
                "OPSGATE_UI_PASSWORD_BCRYPT=$2b$12$C6UzMDM.H6dfI/f/IKcEe.7Pj9N6byN1Nsx3Rp3XIanFkFJxux1fW",
                "OPSGATE_SUBMIT_TOKEN_OPENCLAW=openclaw-token-0000000000",
                "OPSGATE_SUBMIT_TOKEN_NYXMON=nyxmon-token-000000000000",
                "OPSGATE_SUBMIT_TOKEN_OPERATOR=operator-token-00000000000",
                "OPSGATE_RUNNER_TOKEN=runner-token-000000000000",
                "OPSGATE_DB_PATH=/tmp/opsgate-test.sqlite3",
            )
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))
    monkeypatch.delenv("OPSGATE_SESSION_SECRET", raising=False)

    with pytest.raises(SettingsError, match="OPSGATE_SESSION_SECRET"):
        load_settings()
