from __future__ import annotations

import os
from pathlib import Path

import pytest

from opsgate.config import SettingsError, load_env_file, load_runner_settings, load_settings


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


def test_load_runner_settings_accepts_runner_only_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / "opsgate-runner.env"
    env_file.write_text(
        "\n".join(
            (
                "OPSGATE_RUNNER_TOKEN=runner-token-000000000000",
                "OPSGATE_RUNNER_API_BASE_URL=http://127.0.0.1:8711",
                "OPSGATE_RUNNER_HOST=macstudio",
                "OPSGATE_MAX_PARALLEL_JOBS=4",
                "OPSGATE_RUNNER_POLL_INTERVAL_SECONDS=3",
                "OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS=15",
                "OPSGATE_EXECUTION_DATA_DIR=/tmp/opsgate-remediation",
                "OPSGATE_TICKETS_DIR=/tmp/opsgate-remediation/jobs",
                "OPSGATE_SESSION_ARTIFACTS_DIR=/tmp/opsgate-remediation/sessions",
                "OPSGATE_TMUX_SOCKET_LABEL=remediation",
            )
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))
    settings = load_runner_settings()

    assert settings.runner_host == "macstudio"
    assert settings.runner_api_base_url == "http://127.0.0.1:8711"
    assert settings.max_parallel_jobs == 4
    assert settings.runner_poll_interval_seconds == 3
    assert settings.runner_heartbeat_interval_seconds == 15


def test_load_runner_settings_requires_runner_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / "opsgate-runner.env"
    env_file.write_text("OPSGATE_RUNNER_TOKEN=short\n", encoding="utf-8")
    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))

    with pytest.raises(SettingsError, match="OPSGATE_RUNNER_TOKEN"):
        load_runner_settings()


def test_load_settings_allows_missing_openclaw_submit_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / "opsgate.env"
    env_file.write_text(
        "\n".join(
            (
                "OPSGATE_UI_USERNAME=opsgate-admin",
                "OPSGATE_UI_PASSWORD_BCRYPT=$2b$12$C6UzMDM.H6dfI/f/IKcEe.7Pj9N6byN1Nsx3Rp3XIanFkFJxux1fW",
                "OPSGATE_SESSION_SECRET=session-secret-0123456789",
                "OPSGATE_SUBMIT_TOKEN_NYXMON=nyxmon-token-000000000000",
                "OPSGATE_SUBMIT_TOKEN_OPERATOR=operator-token-00000000000",
                "OPSGATE_RUNNER_TOKEN=runner-token-000000000000",
                "OPSGATE_DB_PATH=/tmp/opsgate-test.sqlite3",
            )
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))
    monkeypatch.delenv("OPSGATE_SUBMIT_TOKEN_OPENCLAW", raising=False)

    settings = load_settings()
    submit_sources = {policy.source for policy in settings.submitter_policies}
    assert submit_sources == {"nyxmon", "operator"}


def test_load_runner_settings_reports_invalid_integer_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / "opsgate-runner.env"
    env_file.write_text(
        "\n".join(
            (
                "OPSGATE_RUNNER_TOKEN=runner-token-000000000000",
                "OPSGATE_MAX_PARALLEL_JOBS=not-a-number",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))

    with pytest.raises(SettingsError, match="OPSGATE_MAX_PARALLEL_JOBS must be an integer"):
        load_runner_settings()
